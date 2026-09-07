
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

#line 617 "snapshot/src/gpu/ocl.cpp"
    if (ranKernel) {
      int64_t found = -1;
      p_clEnqueueReadBuffer(c.q, foundBuf, CL_TRUE, 0, sizeof found, &found, 0, nullptr, nullptr);
      if (found >= 0) {
        foundIdx = rawMap ? (uint64_t)(*rawMap)[(size_t)found] : (uint64_t)found;
        if (hyb) hyb->stop.store(true, std::memory_order_relaxed);
        if (attemptsOut) *attemptsOut = attempted;
        return finish(0);
      }
    }

#line 1 "harness-continuation"

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
