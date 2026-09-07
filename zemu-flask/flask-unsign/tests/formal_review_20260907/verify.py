"""SMT verification of manually translated obligations, NOT whole-C++ verification.

No candidate examples are sampled. Each UNSAT query negates a universally
intended property over symbolic states. Source correspondence and the listed
environment assumptions remain outside the solver's proof.
"""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE / '_deps'))
import z3 as z
z.set_param(proof=True)
OUT = HERE / 'obligations'
OUT.mkdir(exist_ok=True)
results = []

def check(name, assumptions, property_, expected='unsat', witness=()):
    solver = z.Solver()
    solver.set(timeout=30000)
    solver.add(*assumptions)
    feasible = solver.check()
    assert feasible == z.sat, (name, 'vacuous or unknown precondition', feasible)
    solver.add(z.Not(property_))
    (OUT / (name + '.smt2')).write_text(solver.to_smt2(), encoding='utf-8')
    answer = solver.check()
    row = dict(name=name, preconditions=str(feasible), result=str(answer), expected=expected)
    if answer == z.sat:
        model = solver.model()
        row['counterexample'] = {str(v): str(model.eval(v, model_completion=True)) for v in witness}
    elif answer == z.unsat:
        # Z3's proof object is retained; it has not been independently checked.
        (OUT / (name + '.proof.txt')).write_text(solver.proof().sexpr(), encoding='utf-8')
    else:
        row['reason'] = solver.reason_unknown()
    results.append(row)
    print(name, answer, row.get('counterexample', ''), flush=True)
    assert str(answer) == expected, row

# One arbitrary candidate x suffices to state pointwise coverage of all [0,N).
# cs: 0 unclaimed by CPU, 1 CPU obligation pending, 2 verified, 3 discarded.
# R is a ghost prefix completed by GPU; H is its committed raw prefix.
# R advances only under the assumption that the backend completed every eligible
# candidate in that prefix. No driver liveness or SHA/HMAC correctness is proved.
N, x, H, T, R, cs = z.Ints('N x H T R cs')
base_domain = [N > 0, N <= 2**32-1, x >= 0, x < N]
def invariant(h, t, r, c):
    return z.And(0 <= r, r <= h, h <= N, 0 <= t, t <= N,
                 c >= 0, c <= 3, (c == 0) == (x < t),
                 z.Implies(c == 3, x < h))
inv = invariant(H, T, R, cs)
check('01_initial_invariant', base_domain, invariant(0, N, 0, 0))

# A successful tail CAS is its linearization point. Failed/spurious CAS attempts
# change no shared state, and are abstracted to stuttering transitions.
newT = z.If(T > 65536, T-65536, 0)
newCs = z.If(z.And(newT <= x, x < T), 1, cs)
check('02_cpu_claim_preserves_invariant', base_domain+[inv, T > 0],
      invariant(H, newT, R, newCs))

# Relaxed head reads may be stale. For this abstraction they may return ANY
# 0 <= seenH <= H, a superset of the monotonically published past values.
seenH = z.Int('seenH')
readH = [seenH >= 0, seenH <= H]
check('03_cpu_discard_preserves_invariant', base_domain+[inv, cs == 1, x < seenH]+readH,
      invariant(H, T, R, 3))
check('04_cpu_verify_preserves_invariant', base_domain+[inv, cs == 1, x >= seenH]+readH,
      invariant(H, T, R, 2))

# The only GPU producer reads its own head. Tail may have fallen further since
# the observed value. Publishing the clamped boundary remains monotone.
seenT = z.Int('seenT')
hi0 = z.If(H+2**24 < N, H+2**24, N)
newH = z.If(hi0 > seenT, seenT, hi0)
readT = [T <= seenT, seenT <= N]
check('05_gpu_claim_preserves_invariant', base_domain+[inv, H < N, H < seenT]+readT,
      invariant(newH, T, R, cs))
newR = z.Int('newR')
check('06_gpu_completion_preserves_invariant', base_domain+[inv, R <= newR, newR <= H],
      invariant(H, T, newR, cs))

check('07_gpu_exhaustion_closes_gap', base_domain+[inv, H >= seenT]+readT, H >= T)
check('08_gpu_total_exhaustion_closes_gap', base_domain+[inv, H >= N], H >= T)

# CPU loop break after acquiring [start,end): current global T may be below
# that worker's start because other workers can claim intervening suffix chunks.
start, end = z.Ints('start end')
check('09_cpu_head_break_closes_gap', base_domain+[inv, T <= start, start < end,
      end <= seenH]+readH, H >= T)
check('10_cpu_zero_tail_closes_gap', base_domain+[inv, T == 0], H >= T)

eligible, supplemented = z.Bools('eligible supplemented')
normal_exit = base_domain+[inv, H >= T, R == H, cs != 1,
                          z.Implies(z.Not(eligible), supplemented)]
verified = z.Or(cs == 2, z.And(eligible, x < R),
                z.And(z.Not(eligible), supplemented))
check('11_normal_exit_has_no_omitted_candidate', normal_exit, verified)

# Mutation sensitivity: publish fetch_add(CHUNK)'s full boundary while promising
# only up to the observed CPU tail, the old overclaim pattern.
tailAfterCpu = N-65536
oldPublished = z.IntVal(2**24)
oldGpuCovered = x < tailAfterCpu
oldCpuVerified = z.And(tailAfterCpu <= x, x < N, x >= oldPublished)
check('12_old_overclaim_counterexample', base_domain+[N > 65536, N < 2**24,
      tailAfterCpu <= x], z.Or(oldGpuCovered, oldCpuVerified), expected='sat',
      witness=(N, x, tailAfterCpu, oldPublished))

# Arithmetic correspondence: unlike Int, these are the actual unsigned 64-bit
# addition/comparison semantics. Domain bound follows the current WordSet loader.
bH, bN, bT = z.BitVecs('bH bN bT', 64)
bSum = bH+z.BitVecVal(2**24, 64)
bHi0 = z.If(z.ULT(bSum, bN), bSum, bN)
bHi = z.If(z.UGT(bHi0, bT), bT, bHi0)
check('13_gpu_u64_arithmetic_dictionary_domain', [z.UGT(bN, 0), z.ULE(bN, 2**32-1),
      z.ULT(bH, bN), z.ULT(bH, bT), z.ULE(bT, bN)],
      z.And(z.UGT(bHi, bH), z.ULE(bHi, bN), z.ULE(bHi, bT)))
u = z.BitVec('u', 64)
lo = z.If(z.UGT(u, 65536), u-65536, z.BitVecVal(0, 64))
check('14_cpu_u64_tail_no_underflow', [z.UGT(u, 0)], z.ULT(lo, u))

# WordSet compaction: trim can only decrease line length. memmove supports
# overlap; writes end no later than this line's delimiter, before the unread
# suffix. This is an arithmetic safety lemma, not a proof of memchr/ifstream.
n, i, eol, length, w = z.Ints('n i eol length w')
line_domain = [0 <= w, w <= i, i <= eol, eol <= n, n <= 2**32-1,
               length >= 0, length <= eol-i]
check('15_wordset_no_overwrite_of_unread_suffix', line_domain,
      z.And(w+length <= eol, w+length <= n))
check('16_wordset_u32_offset_remains_representable', line_domain,
      z.And(0 <= w+length, w+length <= 2**32-1))
check('17_wordset_next_iteration_preserves_write_bound', line_domain+[eol < n],
      z.And(w+length <= eol+1, eol+1 <= n))

# The skipped-word fallback is logically necessary, not merely a test fixture.
check('18_without_supplement_counterexample', base_domain+[inv, H >= T,
      R == H, cs != 1, z.Not(eligible), z.Not(supplemented),
      # Reachable trace: CPU claims [1,65537), GPU claims [0,1).
      # Candidate 0 is skipped; at least one of the other words is packable.
      # This avoids the all-skipped dictionary's separate full-CPU fallback.
      N == 65537, x == 0, H == 1, T == 1, R == 1, cs == 0], verified,
      expected='sat', witness=(N, x, H, T, R, cs, eligible, supplemented))

files=['src/crack_cpu.cpp','src/crack_cpu.h','src/gpu/ocl.cpp','src/flask.cpp']
summary=dict(solver=z.get_version_string(), method='manual abstraction + SMT inductive obligations',
             source_hashes={f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files},
             results=results)
(HERE/'results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print('Completed:',len(results),'obligations;',sum(r['result']=='unsat' for r in results),
      'UNSAT,',sum(r['result']=='sat' for r in results),'expected SAT counterexamples')
