#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

// GPU (OpenCL) match search, kernel structure ported from hashcat's
// m00000_a3-optimized: each GPU thread decodes its own "root" candidate
// (trailing positions) from the global index via a mixed-radix convert table,
// iterates the leading bytes (message word 0) via a precomputed OR table with
// all fixed words folded into per-step constants, and exact 128-bit targets
// early-reject after step 42 by reversing rounds from the digest.
struct GpuMatchParams {
  std::uint32_t length = 0;
  std::vector<std::uint8_t> chars;     // concatenated per-position charsets
  std::vector<std::uint32_t> offsets;  // length + 1 entries
  std::vector<std::uint32_t> radix;    // per position
  std::uint64_t limit = 0;             // candidates to search
  std::array<std::uint32_t, 4> value{};  // digest word match, little-endian words
  std::array<std::uint32_t, 4> mask{};
  std::uint64_t max_hits = 4096;       // hit buffer capacity
  std::atomic<bool> *interrupted = nullptr;
};

struct GpuMatchHit {
  std::uint64_t index;
  std::array<std::uint32_t, 4> digest;
};

struct GpuMatchResult {
  std::vector<GpuMatchHit> hits;
  std::uint64_t hit_total = 0;  // may exceed hits.size() when the buffer capped
  std::uint64_t processed = 0;
  double seconds = 0;
};

bool gpu_available() noexcept;
// Throws std::runtime_error on OpenCL errors.
GpuMatchResult gpu_match(const GpuMatchParams &params);

struct GpuTuning {
  unsigned vec = 16;
  unsigned local = 256;
};

// Benchmarks the vec x local launch-parameter grid on the fastest GPU (fixed
// synthetic length-10 digits exact-target space, 1 warmup + 5 timed runs per
// combo, median rate wins) and caches the best combo keyed by device name and
// driver version. Later gpu_match calls use the cached values unless
// ZM_VEC/ZM_LOCAL override them. Throws std::runtime_error if no GPU works.
GpuTuning gpu_autotune(std::atomic<bool> *interrupted = nullptr);
