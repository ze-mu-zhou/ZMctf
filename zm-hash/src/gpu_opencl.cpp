#include "gpu_opencl.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

// Minimal OpenCL 1.2 dynamic binding: no SDK or import library needed, the
// ICD (OpenCL.dll / libOpenCL.so) ships with the GPU driver.
using cl_int = int;
using cl_uint = unsigned;
using cl_ulong = unsigned long long;
using cl_bool = cl_uint;
using cl_bitfield = cl_ulong;
using cl_device_type = cl_bitfield;
using cl_platform_id = void *;
using cl_device_id = void *;
using cl_context = void *;
using cl_command_queue = void *;
using cl_program = void *;
using cl_kernel = void *;
using cl_mem = void *;

constexpr cl_int CL_SUCCESS = 0;
constexpr cl_device_type CL_DEVICE_TYPE_GPU = 1ull << 2;
constexpr cl_uint CL_DEVICE_MAX_COMPUTE_UNITS = 0x1002;
constexpr cl_uint CL_DEVICE_MAX_CLOCK_FREQUENCY = 0x100C;
constexpr cl_uint CL_DEVICE_NAME = 0x102B;
constexpr cl_uint CL_DRIVER_VERSION = 0x102D;
constexpr cl_uint CL_PROGRAM_BUILD_LOG = 0x1183;
constexpr cl_bitfield CL_MEM_READ_WRITE = 1;
constexpr cl_bitfield CL_MEM_READ_ONLY = 1 << 2;
constexpr cl_bitfield CL_MEM_COPY_HOST_PTR = 1 << 5;
constexpr cl_bool CL_TRUE = 1;

struct Cl {
  void *lib = nullptr;
  cl_int (*GetPlatformIDs)(cl_uint, cl_platform_id *, cl_uint *){};
  cl_int (*GetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *){};
  cl_int (*GetDeviceInfo)(cl_device_id, cl_uint, size_t, void *, size_t *){};
  cl_context (*CreateContext)(const void *, cl_uint, const cl_device_id *, void *, void *, cl_int *){};
  cl_command_queue (*CreateCommandQueue)(cl_context, cl_device_id, cl_bitfield, cl_int *){};
  cl_program (*CreateProgramWithSource)(cl_context, cl_uint, const char **, const size_t *, cl_int *){};
  cl_int (*BuildProgram)(cl_program, cl_uint, const cl_device_id *, const char *, void *, void *){};
  cl_int (*GetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *){};
  cl_kernel (*CreateKernel)(cl_program, const char *, cl_int *){};
  cl_mem (*CreateBuffer)(cl_context, cl_bitfield, size_t, void *, cl_int *){};
  cl_int (*EnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const void *, void *){};
  cl_int (*SetKernelArg)(cl_kernel, cl_uint, size_t, const void *){};
  cl_int (*EnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const void *, const size_t *, const size_t *, cl_uint, const void *, void *){};
  cl_int (*EnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void *, cl_uint, const void *, void *){};
  cl_int (*Finish)(cl_command_queue){};
  cl_int (*ReleaseMemObject)(cl_mem){};
  cl_int (*ReleaseKernel)(cl_kernel){};
  cl_int (*ReleaseProgram)(cl_program){};
  cl_int (*ReleaseCommandQueue)(cl_command_queue){};
  cl_int (*ReleaseContext)(cl_context){};
};

void *cl_sym(void *lib, const char *name) {
#ifdef _WIN32
  return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(lib), name));
#else
  return dlsym(lib, name);
#endif
}

const Cl &cl_api() {
  static const Cl cl = [] {
    Cl c{};
#ifdef _WIN32
    c.lib = LoadLibraryA("OpenCL.dll");
#else
    c.lib = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!c.lib) c.lib = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
#endif
    if (!c.lib) return c;
    const std::pair<const char *, void **> entries[] = {
        {"clGetPlatformIDs", reinterpret_cast<void **>(&c.GetPlatformIDs)},
        {"clGetDeviceIDs", reinterpret_cast<void **>(&c.GetDeviceIDs)},
        {"clGetDeviceInfo", reinterpret_cast<void **>(&c.GetDeviceInfo)},
        {"clCreateContext", reinterpret_cast<void **>(&c.CreateContext)},
        {"clCreateCommandQueue", reinterpret_cast<void **>(&c.CreateCommandQueue)},
        {"clCreateProgramWithSource", reinterpret_cast<void **>(&c.CreateProgramWithSource)},
        {"clBuildProgram", reinterpret_cast<void **>(&c.BuildProgram)},
        {"clGetProgramBuildInfo", reinterpret_cast<void **>(&c.GetProgramBuildInfo)},
        {"clCreateKernel", reinterpret_cast<void **>(&c.CreateKernel)},
        {"clCreateBuffer", reinterpret_cast<void **>(&c.CreateBuffer)},
        {"clEnqueueWriteBuffer", reinterpret_cast<void **>(&c.EnqueueWriteBuffer)},
        {"clSetKernelArg", reinterpret_cast<void **>(&c.SetKernelArg)},
        {"clEnqueueNDRangeKernel", reinterpret_cast<void **>(&c.EnqueueNDRangeKernel)},
        {"clEnqueueReadBuffer", reinterpret_cast<void **>(&c.EnqueueReadBuffer)},
        {"clFinish", reinterpret_cast<void **>(&c.Finish)},
        {"clReleaseMemObject", reinterpret_cast<void **>(&c.ReleaseMemObject)},
        {"clReleaseKernel", reinterpret_cast<void **>(&c.ReleaseKernel)},
        {"clReleaseProgram", reinterpret_cast<void **>(&c.ReleaseProgram)},
        {"clReleaseCommandQueue", reinterpret_cast<void **>(&c.ReleaseCommandQueue)},
        {"clReleaseContext", reinterpret_cast<void **>(&c.ReleaseContext)},
    };
    for (const auto &[name, slot] : entries) {
      *slot = cl_sym(c.lib, name);
      if (!*slot) { c = Cl{}; return c; }
    }
    return c;
  }();
  return cl;
}

struct GpuDeviceInfo {
  cl_platform_id platform = nullptr;
  cl_device_id device = nullptr;
  cl_uint units = 0;
  cl_uint clock_mhz = 0;
  std::string name;
  std::string driver;
  std::uint64_t weight() const {  // rough throughput estimate for chunk sizing
    return static_cast<std::uint64_t>(units ? units : 1) * (clock_mhz ? clock_mhz : 1000);
  }
};

std::vector<GpuDeviceInfo> find_gpus() {
  const Cl &cl = cl_api();
  cl_uint nplatforms = 0;
  if (cl.GetPlatformIDs(0, nullptr, &nplatforms) != CL_SUCCESS || !nplatforms) return {};
  std::vector<cl_platform_id> platforms(nplatforms);
  cl.GetPlatformIDs(nplatforms, platforms.data(), nullptr);
  std::vector<GpuDeviceInfo> gpus;
  for (const auto platform : platforms) {
    cl_uint ndev = 0;
    if (cl.GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &ndev) != CL_SUCCESS || !ndev) continue;
    std::vector<cl_device_id> devices(ndev);
    cl.GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, ndev, devices.data(), nullptr);
    for (const auto device : devices) {
      GpuDeviceInfo info;
      info.platform = platform;
      info.device = device;
      cl.GetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(info.units), &info.units, nullptr);
      cl.GetDeviceInfo(device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(info.clock_mhz), &info.clock_mhz, nullptr);
      char name[256] = {};
      if (cl.GetDeviceInfo(device, CL_DEVICE_NAME, sizeof(name) - 1, name, nullptr) == CL_SUCCESS)
        info.name = name;
      char driver[64] = {};
      if (cl.GetDeviceInfo(device, CL_DRIVER_VERSION, sizeof(driver) - 1, driver, nullptr) == CL_SUCCESS)
        info.driver = driver;
      gpus.push_back(std::move(info));
    }
  }
  std::sort(gpus.begin(), gpus.end(),
            [](const GpuDeviceInfo &a, const GpuDeviceInfo &b) { return a.units > b.units; });
  return gpus;
}

// ZM_GPUS=0,2,... picks devices by index (as sorted by find_gpus), for
// launch-tuning experiments; unset means "all GPUs".
std::vector<GpuDeviceInfo> select_gpus(std::vector<GpuDeviceInfo> gpus) {
  const char *e = std::getenv("ZM_GPUS");
  if (!e || !*e) return gpus;
  std::vector<GpuDeviceInfo> picked;
  const std::string spec = e;
  std::size_t pos = 0;
  while (pos <= spec.size()) {
    const auto comma = spec.find(',', pos);
    const auto token = spec.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
    const long idx = token.empty() ? -1 : std::strtol(token.c_str(), nullptr, 10);
    if (idx >= 0 && static_cast<std::size_t>(idx) < gpus.size()) {
      const auto dev = gpus[static_cast<std::size_t>(idx)].device;
      const auto dup = std::find_if(picked.begin(), picked.end(),
                                    [&](const GpuDeviceInfo &g) { return g.device == dev; });
      if (dup == picked.end()) picked.push_back(std::move(gpus[static_cast<std::size_t>(idx)]));
    }
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  return picked;
}

void cl_check(cl_int err, const char *what) {
  if (err != CL_SUCCESS) throw std::runtime_error(std::string("OpenCL ") + what + " 失败，错误码 " + std::to_string(err));
}

constexpr std::array<std::uint32_t, 64> MD5_K = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

constexpr std::array<unsigned, 64> MD5_S = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Message word index consumed by step i.
constexpr unsigned md5_word(unsigned i) {
  const unsigned round = i / 16;
  return round == 0 ? i
       : round == 1 ? (5 * i + 1) % 16
       : round == 2 ? (3 * i + 5) % 16
                    : (7 * i) % 16;
}

// Launch-parameter resolution: ZM_VEC/ZM_LOCAL > autotune cache > defaults.
// Defaults measured on sm_89 (RTX 4060 Laptop): VEC=16 @ 158 regs beats VEC=8
// @ 72 regs by ~1.4% despite lower occupancy — ILP wins for MD5.
// env_tune returns 0 when the variable is unset or holds an invalid value.
unsigned env_tune(const char *name, std::initializer_list<unsigned> valid) {
  const char *e = std::getenv(name);
  if (!e || !*e) return 0;
  const unsigned v = static_cast<unsigned>(std::atoi(e));
  for (const unsigned x : valid) if (x == v) return v;
  return 0;
}

std::filesystem::path tune_cache_dir() {
#ifdef _WIN32
  if (const char *p = std::getenv("LOCALAPPDATA"); p && *p) return std::filesystem::path(p) / "zm-hash";
#else
  if (const char *p = std::getenv("XDG_CACHE_HOME"); p && *p) return std::filesystem::path(p) / "zm-hash";
  if (const char *p = std::getenv("HOME"); p && *p) return std::filesystem::path(p) / ".cache" / "zm-hash";
#endif
  return {};
}

// Cache line format: "<device name> | <driver version>\t<vec>\t<local>".
std::string tune_key(const GpuDeviceInfo &dev) { return dev.name + " | " + dev.driver; }

std::optional<GpuTuning> tune_cache_lookup(const std::string &key) {
  const auto dir = tune_cache_dir();
  if (dir.empty()) return std::nullopt;
  std::ifstream f(dir / "autotune.cache");
  std::string line;
  while (std::getline(f, line)) {
    const auto p1 = line.rfind('\t');
    if (p1 == std::string::npos || p1 == 0) continue;
    const auto p0 = line.rfind('\t', p1 - 1);
    if (p0 == std::string::npos || line.substr(0, p0) != key) continue;
    const unsigned vec = static_cast<unsigned>(std::atoi(line.c_str() + p0 + 1));
    const unsigned local = static_cast<unsigned>(std::atoi(line.c_str() + p1 + 1));
    if ((vec == 4 || vec == 8 || vec == 16) && (local == 128 || local == 256 || local == 512))
      return GpuTuning{vec, local};
  }
  return std::nullopt;
}

void tune_cache_store(const std::string &key, const GpuTuning &tuning) {
  const auto dir = tune_cache_dir();
  if (dir.empty()) return;
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) return;
  const auto path = dir / "autotune.cache";
  std::vector<std::string> lines;
  {
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
      const auto tab = line.find('\t');
      if (!line.empty() && (tab == std::string::npos || line.substr(0, tab) != key)) lines.push_back(line);
    }
  }
  lines.push_back(key + '\t' + std::to_string(tuning.vec) + '\t' + std::to_string(tuning.local));
  std::ofstream f(path, std::ios::trunc);
  for (const auto &line : lines) f << line << '\n';
}

const char *KERNEL_HEAD = R"OPENCL(

typedef unsigned int u32;
typedef unsigned long u64;

inline uvec zm_rotl(const uvec x, const u32 s) { return (x << s) | (x >> (32 - s)); }
inline uvec zm_rotr(const uvec x, const u32 s) { return (x >> s) | (x << (32 - s)); }
inline u32 zm_rotr32(const u32 x, const u32 s) { return (x >> s) | (x << (32 - s)); }
inline uvec zm_splat(const u32 x) { return (uvec) (SPLAT_ARGS); }

#define ZM_F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define ZM_G(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))
#define ZM_H(x,y,z) ((x) ^ (y) ^ (z))
#define ZM_I(x,y,z) ((y) ^ ((x) | ~(z)))

__kernel void zm_md5_match(
    const u64 launch_base, const u64 roots_this,
    const u64 inner_count, const u64 stride,
    const u32 v0, const u32 v1, const u32 v2, const u32 v3,
    const u32 m0, const u32 m1, const u32 m2, const u32 m3,
    __global const uint2 *cvt, __global const uchar *cst,
    __global const uvec *inner_tab, const u32 n_inner_rt,
    const u32 max_hits, __global u32 *hit_count,
    __global u64 *hit_index, __global uint4 *hit_digest)
{
  const u64 gid = (u64) get_global_id(0);
  if (gid >= roots_this) return;

  const u64 root_index = launch_base + gid;
  const u32 ic32 = (u32) inner_count;
  const u32 nvec = (ic32 + (VEC - 1u)) / VEC;

)OPENCL";

// The kernel body is generated per launch shape, following hashcat's
// m00000_a3-optimized (m00000s) single-target kernel:
//  - each thread decodes its own root candidate (trailing positions) from the
//    global index through a tiny mixed-radix convert table — no host-side
//    decode, no per-root upload, one launch covers the whole space;
//  - the inner loop varies only message word 0 (leading candidate bytes), via
//    a host-precomputed OR table, VEC candidates per thread (u32x8 ILP);
//  - every fixed message word is folded into a per-step constant K+w (the
//    F_w1c01 = w[1] + MD5C01 trick), so steps are add+fn+rotl+add only;
//  - for exact 128-bit targets, steps 63..49 are reversed from the target
//    once per thread, then steps 48 (the first w0-consuming step, minus its
//    w0 term), 47 and 46 are folded in as constants too; inside the loop the
//    reversed c42 chain costs 8 vector ops, so the forward loop stops after
//    step 42 and the early reject fires ~33% earlier per candidate;
//    survivors recompute the tail and take a full masked compare.
//  - masked (pattern) targets cannot be reversed, so they run all 64 steps.
std::string build_kernel_source(std::size_t length, bool exact, unsigned vec) {
  std::array<bool, 16> zero{};
  for (std::size_t z = length / 4 + 1; z < 14; ++z) zero[z] = true;
  zero[15] = true;  // high length word: always 0 for length <= 55
  zero[0] = false;  // loop word

  // Scalar message words needed for constant folding / reversal.
  std::array<bool, 16> need{};
  for (unsigned i = 0; i != 64; ++i) {
    const unsigned g = md5_word(i);
    if (g != 0 && !zero[g]) need[g] = true;
  }
  need[14] = true;
  need[0] = true;

  const std::string vec_t = "uint" + std::to_string(vec);
  const std::string int_t = "int" + std::to_string(vec);
  std::string s = KERNEL_HEAD;
  const auto replace_all = [](std::string &text, const std::string &from, const std::string &to) {
    for (std::size_t p = 0; (p = text.find(from, p)) != std::string::npos; p += to.size()) text.replace(p, from.size(), to);
  };
  replace_all(s, "uvec", vec_t);
  replace_all(s, "VEC", std::to_string(vec));
  std::string splat_args;
  for (unsigned i = 0; i != vec; ++i) splat_args += (i ? ", x" : "x");
  replace_all(s, "SPLAT_ARGS", splat_args);

  char line[224];
  // In-kernel root decode: each thread expands its root index into the
  // trailing positions [n_inner, L) via the mixed-radix convert table.
  // Manually unrolled with constant position/shift per line, so dw[] stays in
  // registers; guards are uniform across threads (n_inner_rt is a scalar).
  s += "  u32 dw[14] = {0};\n";
  s += "  u64 rr = root_index;\n";
  for (std::size_t q = length; q-- > 0;) {
    std::snprintf(line, sizeof(line),
                  "  if (%u >= n_inner_rt) { const uint2 pr = cvt[%u]; const u64 qq = rr / pr.y;\n"
                  "    dw[%u] |= (u32) cst[pr.x + (u32) (rr - qq * pr.y)] << %u; rr = qq; }\n",
                  (unsigned)q, (unsigned)q, (unsigned)(q >> 2), (unsigned)((q & 3) * 8));
    s += line;
  }
  std::snprintf(line, sizeof(line), "  dw[%u] |= 0x80u << %u;\n",
                (unsigned)(length / 4), (unsigned)((length & 3) * 8));
  s += line;
  for (unsigned i = 0; i != 16; ++i) {
    if (!need[i]) continue;
    if (i == 14)
      std::snprintf(line, sizeof(line), "  const u32 w14_s = %uu;\n", (unsigned)(length * 8));
    else
      std::snprintf(line, sizeof(line), "  const u32 w%u_s = dw[%u];\n", i, i);
    s += line;
  }

  // Folded per-step constants for fixed words (K + w_g), zero words inline K.
  for (unsigned i = 0; i != 64; ++i) {
    const unsigned g = md5_word(i);
    if (g == 0 || zero[g]) continue;
    std::snprintf(line, sizeof(line), "  const u32 kc%02u = 0x%08xu + w%u_s;\n", i, MD5_K[i], g);
    s += line;
  }

  const char *vars[4] = {"a", "b", "c", "d"};
  const auto fn_of = [](unsigned i) {
    return i < 16 ? "ZM_F" : i < 32 ? "ZM_G" : i < 48 ? "ZM_H" : "ZM_I";
  };

  if (exact) {
    // Reverse steps 63..49 from (target - IV). All use fixed words, so the
    // reversed state is exact per-thread constants. Step 48 (uses w0) is
    // undone in the loop with a single vector subtract.
    s += "\n  u32 ra = v0 - 0x67452301u, rb = v1 - 0xefcdab89u;\n";
    s += "  u32 rc = v2 - 0x98badcfeu, rd = v3 - 0x10325476u;\n";
    const char *rvars[4] = {"ra", "rb", "rc", "rd"};
    for (unsigned i = 63; i >= 49; --i) {
      const unsigned t = (4 - (i % 4)) % 4;
      const unsigned g = md5_word(i);
      std::string term;
      if (!zero[g]) term = " - w" + std::to_string(g) + "_s";
      std::snprintf(line, sizeof(line), "  %s = zm_rotr32(%s - %s, %uu) - ZM_I(%s, %s, %s)%s - 0x%08xu;\n",
                    rvars[t], rvars[t], rvars[(t + 1) % 4], MD5_S[i],
                    rvars[(t + 1) % 4], rvars[(t + 2) % 4], rvars[(t + 3) % 4], term.c_str(), MD5_K[i]);
      s += line;
    }
    // After undoing steps 63..49, (ra, rb, rc, rd) = (V48, V47, V46, V45).
    // Push the reject deeper, across the w0-consuming step 48 (same depth as
    // hashcat's m00000s pre_a/pre_b/pre_c chain):
    //   V44 = rotr(V48 - V47, 6)  - I(V47, V46, V45) - w0 - K48
    //   V43 = rotr(V47 - V46, 23) - (V44 ^ V45 ^ V46) - w2 - K47
    //   V42 = rotr(V46 - V45, 16) - (V43 ^ V44 ^ V45) - K46   (w15 = 0)
    // Everything except w0 is a per-thread constant, so the loop only needs
    //   t44 = v44p - w0
    //   t43 = rv46 - (t44 ^ x46) - (K47 + w2)
    //   t42 = rv45 - (rd ^ t44 ^ t43) - K46
    // to compare against the forward c right after step 42.
    s += "  const u32 v44p = zm_rotr32(ra - rb, 6u) - ZM_I(rb, rc, rd) - 0xf4292244u;\n";
    s += "  const u32 rv46 = zm_rotr32(rb - rc, 23u);\n";
    s += "  const u32 rv45 = zm_rotr32(rc - rd, 16u);\n";
    s += "  const u32 x46 = rc ^ rd;\n";
  }

  s += "\n  const " + vec_t + " save_w0 = zm_splat(w0_s);\n";
  s += "  for (u32 it = 0; it < nvec; ++it) {\n";
  s += "    const u32 base_i = it * " + std::to_string(vec) + "u;\n";
  s += "    const " + vec_t + " w0v = save_w0 | inner_tab[it];\n";
  if (exact) {
    // c42 reject chain (see the reversal notes above); kc47 already holds
    // K47 + w2 whenever word 2 is non-zero, otherwise w2 = 0.
    const std::string k47 = zero[2] ? "0xc4ac5665u" : "kc47";
    s += "    const " + vec_t + " t44 = zm_splat(v44p) - w0v;\n";
    s += "    const " + vec_t + " t43 = zm_splat(rv46) - (t44 ^ zm_splat(x46)) - zm_splat(" + k47 + ");\n";
    s += "    const " + vec_t + " t42 = zm_splat(rv45) - (zm_splat(rd) ^ t44 ^ t43) - zm_splat(0x1fa27cf8u);\n";
  }
  s += "    " + vec_t + " a = zm_splat(0x67452301u), b = zm_splat(0xefcdab89u);\n";
  s += "    " + vec_t + " c = zm_splat(0x98badcfeu), d = zm_splat(0x10325476u);\n";

  const unsigned forward_end = exact ? 43 : 64;
  const auto emit_step = [&](unsigned i) {
    const unsigned t = (4 - (i % 4)) % 4;
    const unsigned g = md5_word(i);
    std::string kterm;
    if (g == 0)
      std::snprintf(line, sizeof(line), "0x%08xu + w0v", MD5_K[i]);
    else if (zero[g])
      std::snprintf(line, sizeof(line), "0x%08xu", MD5_K[i]);
    else
      std::snprintf(line, sizeof(line), "kc%02u", i);
    kterm = line;
    std::snprintf(line, sizeof(line), "    %s += %s + %s(%s, %s, %s); %s = zm_rotl(%s, %uu); %s += %s;\n",
                  vars[t], kterm.c_str(), fn_of(i), vars[(t + 1) % 4], vars[(t + 2) % 4], vars[(t + 3) % 4],
                  vars[t], vars[t], MD5_S[i], vars[t], vars[(t + 1) % 4]);
    s += line;
  };
  for (unsigned i = 0; i != forward_end; ++i) emit_step(i);

  const char *lanes4[4] = {"x", "y", "z", "w"};
  const auto lane_acc = [&](unsigned lane) {
    // OpenCL vector components: x/y/z/w for 4-wide, s0..s9/sa..sf otherwise.
    return vec == 4 ? std::string(lanes4[lane])
                    : std::string("s") + "0123456789abcdef"[lane];
  };
  const auto emit_report = [&](const std::string &cond) {
    for (unsigned lane = 0; lane != vec; ++lane) {
      const std::string acc = lane_acc(lane);
      s += "      if (" + cond + "." + acc + " && base_i + " + std::to_string(lane) + "u < ic32) {\n";
      s += "        const u32 slot = atomic_add(hit_count, 1u);\n";
      s += "        if (slot < max_hits) {\n";
      s += "          hit_index[slot] = (u64) (base_i + " + std::to_string(lane) + "u) * stride + root_index;\n";
      s += "          hit_digest[slot] = (uint4) (a." + acc + ", b." + acc + ", c." + acc + ", d." + acc + ");\n";
      s += "        }\n      }\n";
    }
  };

  if (exact) {
    // Early reject: after step 42, c must equal the reversed c42 chain value.
    s += "    const " + int_t + " early = (c == t42);\n";
    s += "    if (any(early)) {\n";
    for (unsigned i = 43; i != 64; ++i) {
      // Continuation steps, indented one level deeper.
      const unsigned t = (4 - (i % 4)) % 4;
      const unsigned g = md5_word(i);
      std::string kterm;
      if (g == 0)
        std::snprintf(line, sizeof(line), "0x%08xu + w0v", MD5_K[i]);
      else if (zero[g])
        std::snprintf(line, sizeof(line), "0x%08xu", MD5_K[i]);
      else
        std::snprintf(line, sizeof(line), "kc%02u", i);
      kterm = line;
      std::snprintf(line, sizeof(line), "      %s += %s + %s(%s, %s, %s); %s = zm_rotl(%s, %uu); %s += %s;\n",
                    vars[t], kterm.c_str(), fn_of(i), vars[(t + 1) % 4], vars[(t + 2) % 4], vars[(t + 3) % 4],
                    vars[t], vars[t], MD5_S[i], vars[t], vars[(t + 1) % 4]);
      s += line;
    }
    s += "      a += zm_splat(0x67452301u); b += zm_splat(0xefcdab89u);\n";
    s += "      c += zm_splat(0x98badcfeu); d += zm_splat(0x10325476u);\n";
    // Full masked re-check per lane (exact mode has full masks).
    s += "      const " + int_t + " hitv = ((a & m0v) == (v0v & m0v)) & ((b & m1v) == (v1v & m1v)) &\n";
    s += "                        ((c & m2v) == (v2v & m2v)) & ((d & m3v) == (v3v & m3v));\n";
    s += "      const " + int_t + " fire = hitv & early;\n";
    emit_report("fire");
    s += "    }\n";
  } else {
    s += "    a += zm_splat(0x67452301u); b += zm_splat(0xefcdab89u);\n";
    s += "    c += zm_splat(0x98badcfeu); d += zm_splat(0x10325476u);\n";
    s += "    const " + int_t + " hitv = ((a & m0v) == (v0v & m0v)) & ((b & m1v) == (v1v & m1v)) &\n";
    s += "                      ((c & m2v) == (v2v & m2v)) & ((d & m3v) == (v3v & m3v));\n";
    s += "    if (any(hitv)) {\n";
    emit_report("hitv");
    s += "    }\n";
  }
  s += "  }\n}\n";

  if (exact) {
    // Masked compare constants referenced by the exact path's re-check.
    std::string inject = "  const " + vec_t + " v0v = zm_splat(v0), v1v = zm_splat(v1), v2v = zm_splat(v2), v3v = zm_splat(v3);\n";
    inject += "  const " + vec_t + " m0v = zm_splat(m0), m1v = zm_splat(m1), m2v = zm_splat(m2), m3v = zm_splat(m3);\n";
    const std::string anchor = "\n  const " + vec_t + " save_w0";
    const auto pos = s.find(anchor);
    s.insert(pos, "\n" + inject);
  } else {
    std::string inject = "  const " + vec_t + " v0v = zm_splat(v0), v1v = zm_splat(v1), v2v = zm_splat(v2), v3v = zm_splat(v3);\n";
    inject += "  const " + vec_t + " m0v = zm_splat(m0), m1v = zm_splat(m1), m2v = zm_splat(m2), m3v = zm_splat(m3);\n";
    const std::string anchor = "\n  const " + vec_t + " save_w0";
    const auto pos = s.find(anchor);
    s.insert(pos, "\n" + inject);
  }
  return s;
}

struct ClMem {
  const Cl *cl;
  cl_mem mem = nullptr;
  ~ClMem() { if (mem) cl->ReleaseMemObject(mem); }
  ClMem(const ClMem &) = delete;
  ClMem &operator=(const ClMem &) = delete;
  ClMem(const Cl *c) : cl(c) {}
};

} // namespace

bool gpu_available() noexcept {
  static const bool ok = [] {
    const Cl &cl = cl_api();
    if (!cl.GetPlatformIDs) return false;
    return !find_gpus().empty();
  }();
  return ok;
}

namespace {

// Everything one worker thread needs to drive one GPU: same per-launch shape
// as the former single-device path, but chunks are pulled from a shared root
// cursor so faster devices naturally claim more of the space.
struct LaunchShape {
  std::size_t n_inner = 0;
  std::uint64_t inner_count = 1;
  std::uint64_t stride = 1;
  std::uint64_t roots_total = 0;
  std::uint32_t max_hits = 0;
  unsigned vec = 16;
  unsigned local = 256;
  std::string source;
  std::vector<std::array<std::uint32_t, 2>> cvt;
  std::vector<std::uint32_t> inner_tab;
};

struct SharedState {
  const std::uint64_t roots_total;
  const std::uint32_t max_hits;
  const std::uint64_t max_weight;
  const std::atomic<bool> *interrupted;
  std::atomic<std::uint64_t> next_root{0};
  std::atomic<std::uint64_t> total_hits{0};
  std::atomic<bool> stop{false};
};

struct DeviceWork {
  std::uint64_t processed = 0;
  std::uint64_t hit_total = 0;
  std::vector<GpuMatchHit> hits;
  std::chrono::steady_clock::time_point first_launch{};
  std::chrono::steady_clock::time_point last_finish{};
  std::string error;
};

void run_device(const Cl &cl, const GpuDeviceInfo &dev, const GpuMatchParams &params,
                const LaunchShape &shape, SharedState &shared, DeviceWork &out,
                std::barrier<> &sync, const char *dump) {
  // Phase 1: context/queue/program/buffers, per device in parallel. The
  // barrier afterwards keeps a slow JIT (e.g. an iGPU compiler) from
  // missing the whole search on short runs.
  cl_context context = nullptr;
  cl_command_queue queue = nullptr;
  cl_program program = nullptr;
  cl_kernel kernel = nullptr;
  size_t local_size = 0;
  bool ready = false;
  {
    ClMem cvt_mem(&cl), cst_mem(&cl), tab_mem(&cl);
    ClMem count_mem(&cl), index_mem(&cl), digest_mem(&cl);
    try {
      cl_int err = CL_SUCCESS;
      context = cl.CreateContext(nullptr, 1, &dev.device, nullptr, nullptr, &err);
      cl_check(err, "clCreateContext");
      queue = cl.CreateCommandQueue(context, dev.device, 0, &err);
      cl_check(err, "clCreateCommandQueue");

      const char *source_cstr = shape.source.c_str();
      const size_t source_len = shape.source.size();
      program = cl.CreateProgramWithSource(context, 1, &source_cstr, &source_len, &err);
      cl_check(err, "clCreateProgramWithSource");
      // -cl-nv-verbose puts ptxas' register/spill report into the build log;
      // enabled together with ZM_DUMP_KERNEL (log lands in <dump>.log, only
      // for the first device to avoid racing on the file).
      err = cl.BuildProgram(program, 1, &dev.device, dump ? "-cl-nv-verbose" : nullptr, nullptr, nullptr);
      if (dump || err != CL_SUCCESS) {
        size_t log_size = 0;
        cl.GetProgramBuildInfo(program, dev.device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        cl.GetProgramBuildInfo(program, dev.device, CL_PROGRAM_BUILD_LOG, log.size(), log.data(), nullptr);
        if (err != CL_SUCCESS) throw std::runtime_error("OpenCL 内核编译失败：" + log);
        const std::string logpath = std::string(dump) + ".log";
        if (FILE *f = std::fopen(logpath.c_str(), "w")) { std::fwrite(log.data(), 1, log.size(), f); std::fclose(f); }
      }
      kernel = cl.CreateKernel(program, "zm_md5_match", &err);
      cl_check(err, "clCreateKernel");

      auto make_ro = [&](const void *data, size_t size) {
        cl_int e = CL_SUCCESS;
        const std::uint8_t dummy = 0;
        if (size == 0) { data = &dummy; size = 1; }
        cl_mem m = cl.CreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, size, const_cast<void *>(data), &e);
        cl_check(e, "clCreateBuffer");
        return m;
      };
      cvt_mem.mem = make_ro(shape.cvt.data(), shape.cvt.size() * sizeof(shape.cvt[0]));
      cst_mem.mem = make_ro(params.chars.data(), params.chars.size());
      tab_mem.mem = make_ro(shape.inner_tab.data(), shape.inner_tab.size() * sizeof(std::uint32_t));
      const std::uint32_t zero = 0;
      count_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(zero), const_cast<std::uint32_t *>(&zero), &err);
      cl_check(err, "clCreateBuffer hit_count");
      index_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE, sizeof(std::uint64_t) * shape.max_hits, nullptr, &err);
      cl_check(err, "clCreateBuffer hit_index");
      digest_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE, 16 * shape.max_hits, nullptr, &err);
      cl_check(err, "clCreateBuffer hit_digest");

      auto set_u32 = [&](cl_uint n, std::uint32_t v) { cl_check(cl.SetKernelArg(kernel, n, sizeof(v), &v), "clSetKernelArg"); };
      auto set_u64 = [&](cl_uint n, std::uint64_t v) { cl_check(cl.SetKernelArg(kernel, n, sizeof(v), &v), "clSetKernelArg"); };
      auto set_mem = [&](cl_uint n, cl_mem m) { cl_check(cl.SetKernelArg(kernel, n, sizeof(m), &m), "clSetKernelArg"); };
      set_u64(2, shape.inner_count);
      set_u64(3, shape.stride);
      for (cl_uint i = 0; i != 4; ++i) {
        set_u32(4 + i, params.value[i]);
        set_u32(8 + i, params.mask[i]);
      }
      set_mem(12, cvt_mem.mem);
      set_mem(13, cst_mem.mem);
      set_mem(14, tab_mem.mem);
      set_u32(15, static_cast<std::uint32_t>(shape.n_inner));
      set_u32(16, shape.max_hits);
      set_mem(17, count_mem.mem);
      set_mem(18, index_mem.mem);
      set_mem(19, digest_mem.mem);

      // VEC=16 needs 158 regs/thread; 512-thread blocks would exceed the 64K
      // register file (CL_OUT_OF_RESOURCES), so clamp the block size there.
      local_size = shape.local;
      if (shape.vec == 16 && local_size > 256) local_size = 256;
      ready = true;
    } catch (const std::exception &e) {
      out.error = e.what();
    } catch (...) {
      out.error = "未知错误";
    }

    sync.arrive_and_wait();
    if (!ready) {
      if (kernel) cl.ReleaseKernel(kernel);
      if (program) cl.ReleaseProgram(program);
      if (queue) cl.ReleaseCommandQueue(queue);
      if (context) cl.ReleaseContext(context);
      return;
    }

    // Phase 2: dynamic work stealing. Each device pulls root chunks off the
    // shared cursor, sized adaptively toward ~200 ms per launch; the initial
    // chunk is scaled by a units*clock weight so a slow iGPU's first launch
    // does not strand the tail while its size estimate catches up.
    std::uint64_t chunk = std::clamp<std::uint64_t>(
        ((std::uint64_t{1} << 31) / shape.inner_count) * dev.weight() / shared.max_weight,
        1 << 10, 1 << 16);
    auto set_u64 = [&](cl_uint n, std::uint64_t v) { cl_check(cl.SetKernelArg(kernel, n, sizeof(v), &v), "clSetKernelArg"); };
    bool started = false;
    try {
      while (!shared.stop.load(std::memory_order_relaxed)) {
        const std::uint64_t base = shared.next_root.fetch_add(chunk, std::memory_order_relaxed);
        if (base >= shape.roots_total) break;
        const std::uint64_t roots_this = std::min(chunk, shape.roots_total - base);
        set_u64(0, base);
        set_u64(1, roots_this);
        const size_t global_size = static_cast<size_t>((roots_this + local_size - 1) / local_size) * local_size;
        const auto launch_start = std::chrono::steady_clock::now();
        cl_check(cl.EnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global_size, &local_size, 0, nullptr, nullptr),
                 "clEnqueueNDRangeKernel");
        cl_check(cl.Finish(queue), "clFinish");
        const auto launch_end = std::chrono::steady_clock::now();
        if (!started) { out.first_launch = launch_start; started = true; }
        out.last_finish = launch_end;
        out.processed += roots_this * shape.inner_count;
        std::uint32_t hits = 0;
        cl_check(cl.EnqueueReadBuffer(queue, count_mem.mem, CL_TRUE, 0, sizeof(hits), &hits, 0, nullptr, nullptr),
                 "clEnqueueReadBuffer");
        const std::uint64_t delta = hits - out.hit_total;
        out.hit_total = hits;
        if (delta && shared.total_hits.fetch_add(delta, std::memory_order_relaxed) + delta >= shared.max_hits)
          shared.stop.store(true, std::memory_order_relaxed);
        if (shared.interrupted && shared.interrupted->load(std::memory_order_relaxed)) {
          shared.stop.store(true, std::memory_order_relaxed);
          break;
        }
        const double dt = std::chrono::duration<double>(launch_end - launch_start).count();
        if (dt > 1e-9) {
          const double f = std::clamp(0.2 / dt, 0.5, 2.0);
          chunk = std::clamp<std::uint64_t>(static_cast<std::uint64_t>(static_cast<double>(chunk) * f),
                                            1 << 10, 1 << 24);
        }
      }

      const std::uint32_t stored = static_cast<std::uint32_t>(std::min<std::uint64_t>(out.hit_total, shape.max_hits));
      if (stored) {
        std::vector<std::uint64_t> indices(stored);
        std::vector<std::array<std::uint32_t, 4>> digests(stored);
        cl_check(cl.EnqueueReadBuffer(queue, index_mem.mem, CL_TRUE, 0, stored * sizeof(std::uint64_t), indices.data(), 0, nullptr, nullptr),
                 "clEnqueueReadBuffer hits");
        cl_check(cl.EnqueueReadBuffer(queue, digest_mem.mem, CL_TRUE, 0, stored * 16, digests.data(), 0, nullptr, nullptr),
                 "clEnqueueReadBuffer digests");
        out.hits.resize(stored);
        for (std::uint32_t i = 0; i != stored; ++i) out.hits[i] = GpuMatchHit{indices[i], digests[i]};
      }
    } catch (const std::exception &e) {
      out.error = e.what();
    } catch (...) {
      out.error = "未知错误";
    }
  }
  if (kernel) cl.ReleaseKernel(kernel);
  if (program) cl.ReleaseProgram(program);
  if (queue) cl.ReleaseCommandQueue(queue);
  if (context) cl.ReleaseContext(context);
}

GpuMatchResult gpu_match_impl(const GpuMatchParams &params, const std::vector<GpuDeviceInfo> &devices,
                              unsigned vec, unsigned local, bool quiet) {
  const Cl &cl = cl_api();
  if (!cl.GetPlatformIDs) throw std::runtime_error("OpenCL 不可用");

  const auto L = static_cast<std::size_t>(params.length);

  // Inner loop = leading candidate bytes (all inside message word 0, at most 4
  // positions, product capped), so the kernel can fold every other message
  // word into per-step constants and reverse round 4 for exact targets.
  LaunchShape shape;
  while (shape.n_inner < L && shape.n_inner < 4 &&
         shape.inner_count <= 65536 / params.radix[shape.n_inner]) {
    shape.inner_count *= params.radix[shape.n_inner];
    ++shape.n_inner;
  }
  if (shape.n_inner == 0 && L > 0) throw std::runtime_error("GPU 路径要求每个位置基数 ≤ 65536");

  // Outer (trailing) positions [n_inner, L): root cursor range and hit-index
  // stride. Overflow guard: hit indices must stay representable.
  for (std::size_t q = shape.n_inner; q < L; ++q) {
    if (shape.stride > std::numeric_limits<std::uint64_t>::max() / params.radix[q] / shape.inner_count)
      throw std::runtime_error("候选空间过大，GPU 路径不支持");
    shape.stride *= params.radix[q];
  }
  const bool exact = params.mask[0] == 0xffffffffu && params.mask[1] == 0xffffffffu &&
                     params.mask[2] == 0xffffffffu && params.mask[3] == 0xffffffffu;

  // Inner table: entries iterate leading positions with position n_inner-1
  // fastest, consistent with the global enumeration index (it * stride + root).
  shape.vec = vec;
  shape.local = local;
  const std::uint64_t inner_vec = (shape.inner_count + shape.vec - 1) / shape.vec;
  shape.inner_tab.assign(inner_vec * shape.vec, 0);
  for (std::uint64_t it = 0; it < shape.inner_count; ++it) {
    std::uint64_t v = it;
    std::uint32_t w0 = 0;
    for (std::size_t q = shape.n_inner; q-- > 0;) {
      const auto rd = params.radix[q];
      const auto dig = static_cast<std::uint32_t>(v % rd);
      v /= rd;
      w0 |= static_cast<std::uint32_t>(params.chars[params.offsets[q] + dig]) << ((q & 3) * 8);
    }
    shape.inner_tab[it] = w0;  // flat layout: entry it lands at lane it % vec
  }

  shape.roots_total = std::min(shape.stride, (params.limit + shape.inner_count - 1) / shape.inner_count);
  shape.max_hits = static_cast<std::uint32_t>(std::min<std::uint64_t>(params.max_hits, 65536));
  // Mixed-radix convert table: per position {charset offset, radix}; the
  // charset bytes buffer is uploaded verbatim (offsets index into it).
  shape.cvt.resize(L);
  for (std::size_t q = 0; q < L; ++q) shape.cvt[q] = {params.offsets[q], params.radix[q]};
  shape.source = build_kernel_source(L, exact, shape.vec);

  const char *const dump = std::getenv("ZM_DUMP_KERNEL");
  if (dump && *dump) {
    if (FILE *f = std::fopen(dump, "w")) { std::fwrite(shape.source.data(), 1, shape.source.size(), f); std::fclose(f); }
  }

  std::uint64_t max_weight = 1;
  for (const auto &d : devices) max_weight = std::max(max_weight, d.weight());
  SharedState shared{shape.roots_total, shape.max_hits, max_weight, params.interrupted};
  std::vector<DeviceWork> works(devices.size());
  std::barrier sync(static_cast<std::ptrdiff_t>(devices.size()));
  std::vector<std::thread> threads;
  threads.reserve(devices.size());
  for (std::size_t i = 0; i != devices.size(); ++i)
    threads.emplace_back(run_device, std::cref(cl), std::cref(devices[i]), std::cref(params),
                         std::cref(shape), std::ref(shared), std::ref(works[i]), std::ref(sync),
                         i == 0 && dump && *dump ? dump : nullptr);
  for (auto &t : threads) t.join();

  GpuMatchResult result;
  std::size_t succeeded = 0;
  std::string first_error;
  auto span_begin = std::chrono::steady_clock::time_point::max();
  auto span_end = std::chrono::steady_clock::time_point::min();
  for (std::size_t i = 0; i != devices.size(); ++i) {
    auto &w = works[i];
    if (!w.error.empty()) {
      if (first_error.empty()) first_error = w.error;
      if (!quiet)
        std::fprintf(stderr, "GPU[%zu] %s 初始化失败，已跳过：%s\n", i, devices[i].name.c_str(), w.error.c_str());
      continue;
    }
    ++succeeded;
    result.hit_total += w.hit_total;
    result.processed += w.processed;
    std::move(w.hits.begin(), w.hits.end(), std::back_inserter(result.hits));
    if (!w.processed) continue;
    span_begin = std::min(span_begin, w.first_launch);
    span_end = std::max(span_end, w.last_finish);
    if (!quiet) {
      const double busy = std::chrono::duration<double>(w.last_finish - w.first_launch).count();
      std::fprintf(stderr, "GPU[%zu] %s：%llu 候选（%.2f hashes/s）\n", i, devices[i].name.c_str(),
                   static_cast<unsigned long long>(w.processed),
                   busy > 0 ? static_cast<double>(w.processed) / busy : 0.0);
    }
  }
  if (!succeeded) throw std::runtime_error(first_error.empty() ? "所有 GPU 设备均不可用" : first_error);
  result.processed = std::min(params.limit, result.processed);
  // Each device buffers up to max_hits of its own; cap the merged list so
  // --max-output stays a global limit.
  if (result.hits.size() > shape.max_hits) {
    std::sort(result.hits.begin(), result.hits.end(),
              [](const GpuMatchHit &a, const GpuMatchHit &b) { return a.index < b.index; });
    result.hits.resize(shape.max_hits);
  }
  if (span_end > span_begin)
    result.seconds = std::chrono::duration<double>(span_end - span_begin).count();
  return result;
}

} // namespace

GpuMatchResult gpu_match(const GpuMatchParams &params) {
  const Cl &cl = cl_api();
  if (!cl.GetPlatformIDs) throw std::runtime_error("OpenCL 不可用");
  const auto devices = select_gpus(find_gpus());
  if (devices.empty()) throw std::runtime_error("未找到 GPU 设备");

  const unsigned env_vec = env_tune("ZM_VEC", {4, 8, 16});
  const unsigned env_local = env_tune("ZM_LOCAL", {128, 256, 512});
  const auto cached = tune_cache_lookup(tune_key(devices[0]));
  const unsigned vec = env_vec ? env_vec : cached ? cached->vec : 16;
  const unsigned local = env_local ? env_local : cached ? cached->local : 256;
  const char *source = (env_vec || env_local) ? "环境变量" : cached ? "autotune 缓存" : "默认值";
  std::fprintf(stderr, "发射参数：VEC=%u LOCAL=%u（%s）\n", vec, local, source);
  return gpu_match_impl(params, devices, vec, local, false);
}

GpuTuning gpu_autotune(std::atomic<bool> *interrupted) {
  const Cl &cl = cl_api();
  if (!cl.GetPlatformIDs) throw std::runtime_error("OpenCL 不可用");
  const auto devices = select_gpus(find_gpus());
  if (devices.empty()) throw std::runtime_error("未找到 GPU 设备");
  const GpuDeviceInfo &dev = devices[0];  // find_gpus sorts by compute units
  std::fprintf(stderr, "autotune：在 %s 上实测发射参数组合（其余 GPU 沿用同一组合）\n", dev.name.c_str());

  // Fixed synthetic exact-target space: length 10, digits (1e10 candidates).
  // The vec/local ranking is occupancy-bound and carries over to other
  // lengths; exact mode is the common hash-crack path (early-reject).
  GpuMatchParams base;
  base.length = 10;
  for (std::uint32_t q = 0; q != 10; ++q) {
    base.offsets.push_back(q * 10);
    for (char ch = '0'; ch <= '9'; ++ch) base.chars.push_back(static_cast<std::uint8_t>(ch));
    base.radix.push_back(10);
  }
  base.offsets.push_back(100);
  base.value.fill(0x42424242u);
  base.mask.fill(0xffffffffu);
  base.max_hits = 16;
  base.interrupted = interrupted;

  auto run_once = [&](unsigned vec, unsigned local, std::uint64_t limit) {
    GpuMatchParams p = base;
    p.limit = limit;
    const auto r = gpu_match_impl(p, {dev}, vec, local, true);
    return r.seconds > 1e-9 ? static_cast<double>(r.processed) / r.seconds : 0.0;
  };

  // Calibrate the per-run size toward ~0.4 s of kernel time.
  const double probe = run_once(16, 256, 1u << 26);
  if (probe <= 0) throw std::runtime_error("校准运行失败");
  const auto run_limit = std::clamp<std::uint64_t>(static_cast<std::uint64_t>(probe * 0.4), 1u << 24, 1ull << 33);

  const unsigned vecs[] = {16, 8, 4};      // defaults first: ties keep 16/256
  const unsigned locals[] = {256, 128, 512};
  GpuTuning best;
  double best_rate = 0;
  bool stop = false;
  for (const unsigned vec : vecs) {
    for (const unsigned local : locals) {
      if (stop) continue;
      if (vec == 16 && local > 256) continue;  // register-file clamp, see run_device
      if (interrupted && interrupted->load(std::memory_order_relaxed)) { stop = true; continue; }
      try {
        run_once(vec, local, run_limit);  // warmup, also primes the driver JIT cache
        std::array<double, 5> samples{};
        for (auto &s : samples) s = run_once(vec, local, run_limit);
        std::sort(samples.begin(), samples.end());
        const double median = samples[samples.size() / 2];
        std::fprintf(stderr, "  VEC=%-2u LOCAL=%-3u  %.2f GH/s\n", vec, local, median / 1e9);
        if (median > best_rate) { best_rate = median; best = {vec, local}; }
      } catch (const std::exception &e) {
        std::fprintf(stderr, "  VEC=%-2u LOCAL=%-3u  失败：%s\n", vec, local, e.what());
      }
    }
  }
  if (best_rate <= 0) throw std::runtime_error("所有参数组合均失败");
  if (stop) std::fprintf(stderr, "已收到 Ctrl+C，用已完成组合中的最优值。\n");
  tune_cache_store(tune_key(dev), best);
  return best;
}
