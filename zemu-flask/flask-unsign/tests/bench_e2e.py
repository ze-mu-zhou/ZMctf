"""Wall-clock benchmark, including process startup and dictionary loading.
Requires tests/wl-bench16.txt from bench.py. Warm file/kernel caches; no hits.
Usage: python tests/bench_e2e.py --output results.json --repeats 3
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import time
from itsdangerous import URLSafeTimedSerializer

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True)
parser.add_argument('--repeats', type=int, default=3)
args = parser.parse_args()
if args.repeats < 1:
    parser.error("--repeats must be positive")
root = Path(__file__).resolve().parents[1]
exe = str(root / 'bin/zemu-flask.exe')
wordlist = root / 'tests/wl-bench16.txt'
if not wordlist.is_file():
    parser.error('Generate tests/wl-bench16.txt using bench.py first')
# Contains symbols absent from the lowercase/digit benchmark dictionaries/masks.
cookie = URLSafeTimedSerializer('BENCH-NEVER-MATCH!', salt='cookie-session',
    signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1}).dumps({'flag': 'x'})
env = dict(os.environ, ZK_NOPROG='1', ZK_PROF='1')
for key in ('ZK_GPUTHRESH', 'ZK_LWS', 'ZK_NOTUNE'):
    env.pop(key, None)
cases = {}
for work, workload in [('mask100M', ['--mask', '?d' * 8]),
                       ('dict16M', ['--wordlist', str(wordlist)])]:
    for engine, threads in [('cpu', 8), ('cpu', 16), ('cpu', 32),
                            ('gpu', 16), ('auto', 16), ('auto', 32)]:
        name = f'{work}-{engine}-{threads}'
        cases[name] = ['flask', 'crack', '--cookie', cookie, *workload,
                       '--engine', engine, '--threads', str(threads)]
results = {name: [] for name in cases}
def run(name):
    start = time.perf_counter()
    r = subprocess.run([exe, *cases[name]], capture_output=True,
                       text=True, encoding='utf-8', env=env, timeout=120)
    elapsed = time.perf_counter() - start
    if r.returncode != 1 or '跑完未命中' not in r.stderr:
        raise RuntimeError((name, r.returncode, r.stdout, r.stderr))
    return {'seconds': elapsed, 'stderr': r.stderr}
# Warm caches separately; interleave trials to reduce ordering/thermal bias.
for name in cases:
    run(name)
rng = random.Random(42)
for repeat in range(args.repeats):
    order = list(cases)
    rng.shuffle(order)
    for name in order:
        result = run(name)
        results[name].append(result)
        print(repeat + 1, name, round(result['seconds'], 4), flush=True)
summary = {name: {'median_s': statistics.median(r['seconds'] for r in rows),
                  'min_s': min(r['seconds'] for r in rows),
                  'max_s': max(r['seconds'] for r in rows)} for name, rows in results.items()}
Path(args.output).write_text(json.dumps({'cache': 'warm file/kernel caches, fresh CLI processes',
    'dictionary_bytes': wordlist.stat().st_size, 'summary': summary, 'runs': results},
    ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(summary, indent=2))
