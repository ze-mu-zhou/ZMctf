"""Extract the unchanged production result-read branch for a CBMC obligation.

The containing lambda-heavy function is not accepted by CBMC 6.11's C++ parser.
The exact branch below is retained, with a one-chunk continuation returning 1.
The full-function/program correspondence is exercised by native_replay.cpp;
that replay is a concrete refutation witness, not a universal proof.
"""
from pathlib import Path
import hashlib, json
HERE=Path(__file__).resolve().parent
src=HERE/'snapshot/src/gpu/ocl.cpp'
s=src.read_text(encoding='utf-8')
start=s.index('    if (ranKernel) {\n      int64_t found = -1;',s.index('static int runChunks'))
end=s.index('    if (nextCopyRc != CL_SUCCESS)',start)
body=s[start:end]
line=s[:start].count('\n')+1
prefix=r'''
typedef unsigned long long uint64_t;
typedef signed long long int64_t;
typedef unsigned long long size_t;
typedef int cl_int;
typedef void* cl_mem;
#define CL_TRUE 1
namespace std { enum memory_order { memory_order_relaxed }; }
struct Stop {
  bool value;
  void store(bool v, std::memory_order) { value=v; }
};
struct HybridCtl { Stop stop; };
struct RawMap {
  size_t word[1];
  size_t operator[](size_t i) const { return word[i]; }
};
struct OclCtx { void* q; };
bool readFails;
bool readCalled;
int finish(int rc) { return rc; } // pipe == nullptr: exact finish return effect
cl_int p_clEnqueueReadBuffer(void*,cl_mem,int,size_t,size_t,void* dst,
                            unsigned,const void*,void*) {
  readCalled=true;
  if (readFails) return -5; // CL_OUT_OF_RESOURCES: no successful transfer
  *(int64_t*)dst=0;        // the only candidate actually matched on device
  return 0;
}
int readProductionResult(OclCtx& c, cl_mem foundBuf, bool ranKernel,
      uint64_t& foundIdx, const RawMap* rawMap, HybridCtl* hyb,
      uint64_t* attemptsOut, uint64_t attempted) {
'''
suffix=r'''
  // The actual runChunks continuation returns finish(1) once the only chunk
  // is consumed: nextCopyRc==CL_SUCCESS, pipe==nullptr, claim(next)==false.
  return finish(1);
}
int main() {
  OclCtx c; c.q=0;
  uint64_t foundIdx=99;
  readCalled=false;
  bool nondet_failure;
  readFails=nondet_failure;
#ifdef ASSUME_READ_SUCCESS
  __CPROVER_assume(!readFails);
#endif
  int rc=readProductionResult(c,0,true,foundIdx,0,0,0,1);
  __CPROVER_assert(readCalled,"production result-read branch reached");
  __CPROVER_assert(rc!=1,"known matching candidate must not become EXHAUSTED");
}
'''
generated=prefix+'\n#line '+str(line)+' "snapshot/src/gpu/ocl.cpp"\n'+body+'\n#line 1 "harness-continuation"\n'+suffix
(HERE/'read_obligation.cpp').write_text(generated,encoding='utf-8')
(HERE/'source_mapping.json').write_text(json.dumps(dict(source=str(src.relative_to(HERE)),
   source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),begin_line=line,
   exact_branch_sha256=hashlib.sha256(body.encode()).hexdigest(),
   correspondence='verbatim production branch; modeled API/types; one-chunk continuation'),indent=2),encoding='utf-8')
print('Extracted production branch at line',line)
