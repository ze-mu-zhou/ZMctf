// Compile the real OpenCL implementation in this translation unit so its
// dynamically resolved API boundary can be replaced for a failure replay.
#include "snapshot/src/gpu/ocl.cpp"
#include "snapshot/src/flask.h"
#include <iostream>

static PFN_clEnqueueReadBuffer realRead;
static bool injectReadFailure = false;
static unsigned failedReads = 0;
static cl_int readWithFailure(cl_command_queue q, cl_mem buffer, cl_uint blocking,
    size_t offset, size_t size, void* dst, cl_uint count,
    const cl_event* wait, cl_event* event) {
  if (injectReadFailure && size == sizeof(int64_t)) {
    ++failedReads;
    // OpenCL permits CL_OUT_OF_RESOURCES on an otherwise valid read request.
    // Reject it before enqueuing a transfer: host memory remains unchanged.
    return -5;
  }
  return realRead(q, buffer, blocking, offset, size, dst, count, wait, event);
}

int main(int argc, char** argv) {
  if (argc != 3) return 2;
  auto probe = gpuProbe();
  realRead = p_clEnqueueReadBuffer;
  if (!realRead) { std::cerr << "OpenCL unavailable\n"; return 3; }
  p_clEnqueueReadBuffer = readWithFailure;
  for (int mode = 0; mode < 2; ++mode) {
    injectReadFailure = mode != 0;
    std::cout << "REPLAY mode=" << mode << std::endl;
    int rc = flaskCrack(argv[1], argv[2], "", "cookie-session", 1, "gpu");
    std::cout << "REPLAY rc=" << rc << " failed_reads=" << failedReads << std::endl;
  }
}
