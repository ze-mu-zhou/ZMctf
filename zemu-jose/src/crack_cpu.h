/** crack_cpu.h — HS* 密钥爆破(字典 + hashcat 风格掩码),CPU 多线程。
 * HS256 走 HmacSha256FixedMsg 预计算热路径(SHA-NI);HS384/512 走流式。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "sha2.h"

namespace jose {

/** hashcat 风格掩码 → 每位的字符集 */
inline bool parseMask(const std::string& mask, std::vector<std::string>& pos) {
  static const std::string L = "abcdefghijklmnopqrstuvwxyz";
  static const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const std::string D = "0123456789";
  static const std::string S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  static const std::string A = L + U + D + S;
  for (std::size_t i = 0; i < mask.size(); i++) {
    if (mask[i] == '?') {
      if (i + 1 >= mask.size()) return false;
      char t = mask[++i];
      if (t == 'l') pos.push_back(L);
      else if (t == 'u') pos.push_back(U);
      else if (t == 'd') pos.push_back(D);
      else if (t == 's') pos.push_back(S);
      else if (t == 'a') pos.push_back(A);
      else if (t == '?') pos.emplace_back("?");
      else return false;
    } else {
      pos.emplace_back(1, mask[i]);
    }
  }
  return !pos.empty();
}

/** 掩码线性序号 → 候选串(栈上缓冲,无分配)。
 * hashcat 语义:最右位变化最快(序号低位对应掩码末位)。 */
inline void maskUnrank(const std::vector<std::string>& pos, std::uint64_t idx, char* out) {
  for (std::size_t i = pos.size(); i-- > 0;) {
    std::uint64_t size = pos[i].size();
    out[i] = pos[i][idx % size];
    idx /= size;
  }
}

/** 掩码总组合数(溢出返回 UINT64_MAX) */
inline std::uint64_t maskTotal(const std::vector<std::string>& pos) {
  std::uint64_t t = 1;
  for (auto& c : pos) {
    if (c.empty()) return 0;
    if (t > UINT64_MAX / c.size()) return UINT64_MAX;
    t *= c.size();
  }
  return t;
}

/** 爆破共享状态 + HS256 预计算(一次性) */
struct CrackShared {
  static constexpr std::size_t MAX_MASK_LEN = 64;  // 掩码位数上限(buf[64] 栈缓冲)
  int hashBits = 256;
  std::vector<std::uint8_t> expect;                  // 期望签名
  std::vector<std::uint8_t> signingInput;            // header.payload 原文(384/512 流式用)
  const std::vector<std::string>* words = nullptr;   // 字典(可空)
  const std::vector<std::string>* pos = nullptr;     // 掩码(可空)
  std::unique_ptr<sha2::HmacSha256FixedMsg> fm;      // HS256 热路径
  std::unique_ptr<sha2::HmacSha512FixedMsg> fm512;   // HS384/512 热路径
  std::atomic<std::uint64_t> attempts{0};
  std::atomic<bool> found{false};
  std::atomic<bool> abort{false};
  std::string foundSecret;
};

/** 尝试一个候选密钥(keyLen ≤ 64),命中则记录 */
inline void tryCandidate(CrackShared& s, const char* key, std::size_t keyLen,
                         std::uint64_t& localCount) {
  if (s.found.load(std::memory_order_relaxed)) return;
  if (s.hashBits == 256) {
    std::uint8_t mac[32];
    s.fm->mac((const std::uint8_t*)key, keyLen, mac);
    if (std::memcmp(mac, s.expect.data(), 32) == 0) {
      bool expected = false;
      if (s.found.compare_exchange_strong(expected, true)) s.foundSecret.assign(key, keyLen);
    }
  } else {
    std::uint8_t mac[64];
    s.fm512->mac((const std::uint8_t*)key, keyLen, mac);
    if (std::memcmp(mac, s.expect.data(), s.hashBits / 8) == 0) {
      bool expected = false;
      if (s.found.compare_exchange_strong(expected, true)) s.foundSecret.assign(key, keyLen);
    }
  }
  // 本地计数,每 256 次同步一次(避免原子竞争)
  if ((++localCount & 255) == 0) s.attempts.fetch_add(256, std::memory_order_relaxed);
}

/** 字典区间 [begin, end) */
inline void crackDictRange(CrackShared& s, std::size_t begin, std::size_t end,
                           std::atomic<bool>* externalStop = nullptr) {
  std::uint64_t local = 0;
  for (std::size_t i = begin; i < end && !s.abort.load(std::memory_order_relaxed) &&
       (!externalStop || !externalStop->load(std::memory_order_relaxed)); i++) {
    if (s.found.load(std::memory_order_relaxed)) break;
    const std::string& w = (*s.words)[i];
    tryCandidate(s, w.data(), w.size(), local);
    if (s.found.load(std::memory_order_relaxed) && externalStop)
      externalStop->store(true, std::memory_order_relaxed);
  }
  s.attempts.fetch_add(local & 255, std::memory_order_relaxed);
}

/** 掩码区间 [begin, end)。要求 pos->size() ≤ CrackShared::MAX_MASK_LEN(入口处校验) */
inline void crackMaskRange(CrackShared& s, std::uint64_t begin, std::uint64_t end,
                           std::atomic<bool>* externalStop = nullptr) {
  std::uint64_t local = 0;
  char buf[CrackShared::MAX_MASK_LEN];
  std::uint64_t i = begin;
#if defined(__GNUC__) || defined(__clang__)
  // 掩码每位长度固定,可安全地把 8 个候选映射到 AVX-512 的 8 个 lane。
  if (s.hashBits != 256 && sha2::hasAvx512F() && end - i >= 8) {
    const std::size_t keyLen = s.pos->size();
    char batch[8][CrackShared::MAX_MASK_LEN];
    const std::uint8_t* keys[8];
    std::uint8_t macs[8][64];
    std::uint8_t* outs[8];
    for (int lane = 0; lane < 8; lane++) {
      keys[lane] = (const std::uint8_t*)batch[lane];
      outs[lane] = macs[lane];
    }
    for (; end - i >= 8 && !s.abort.load(std::memory_order_relaxed) &&
         (!externalStop || !externalStop->load(std::memory_order_relaxed)); i += 8) {
      if (s.found.load(std::memory_order_relaxed)) break;
      for (int lane = 0; lane < 8; lane++) {
        maskUnrank(*s.pos, i + (std::uint64_t)lane, batch[lane]);
      }
      s.fm512->mac8(keys, keyLen, outs);
      for (int lane = 0; lane < 8; lane++) {
        if (std::memcmp(macs[lane], s.expect.data(), s.hashBits / 8) == 0) {
          bool expected = false;
          if (s.found.compare_exchange_strong(expected, true))
            s.foundSecret.assign(batch[lane], keyLen);
          if (externalStop) externalStop->store(true, std::memory_order_relaxed);
        }
      }
      local += 8;
      if ((local & 255) == 0) s.attempts.fetch_add(256, std::memory_order_relaxed);
    }
  }
#endif
  for (; i < end && !s.abort.load(std::memory_order_relaxed) &&
       (!externalStop || !externalStop->load(std::memory_order_relaxed)); i++) {
    if (s.found.load(std::memory_order_relaxed)) break;
    maskUnrank(*s.pos, i, buf);
    tryCandidate(s, buf, s.pos->size(), local);
    if (s.found.load(std::memory_order_relaxed) && externalStop)
      externalStop->store(true, std::memory_order_relaxed);
  }
  s.attempts.fetch_add(local & 255, std::memory_order_relaxed);
}

struct HybridCtl {
  std::atomic<std::uint64_t> head{0};
  std::atomic<std::uint64_t> tail{0};
  std::atomic<bool> stop{false};
};

inline bool claimHybridTail(HybridCtl& ctl, std::uint64_t& start, std::uint64_t& end) {
  constexpr std::uint64_t CHUNK = 65536;
  std::uint64_t hi = ctl.tail.load(std::memory_order_relaxed);
  while (hi != 0 && !ctl.stop.load(std::memory_order_relaxed)) {
    const std::uint64_t lo = hi > CHUNK ? hi - CHUNK : 0;
    if (ctl.tail.compare_exchange_weak(hi, lo, std::memory_order_relaxed)) {
      start = lo;
      end = hi;
      return true;
    }
  }
  return false;
}

inline void crackMaskHybrid(CrackShared& s, int threads, HybridCtl& ctl) {
  std::vector<std::thread> pool;
  for (int i = 0; i < threads; i++) {
    pool.emplace_back([&] {
      while (!ctl.stop.load(std::memory_order_relaxed) && !s.found.load(std::memory_order_relaxed)) {
        std::uint64_t start = 0, end = 0;
        if (!claimHybridTail(ctl, start, end)) break;
        const std::uint64_t h = ctl.head.load(std::memory_order_relaxed);
        if (end <= h) break;
        if (start < h) start = h;
        if (start < end) crackMaskRange(s, start, end, &ctl.stop);
      }
    });
  }
  for (auto& th : pool) th.join();
}

inline void crackDictHybrid(CrackShared& s, int threads, HybridCtl& ctl) {
  std::vector<std::thread> pool;
  for (int i = 0; i < threads; i++) {
    pool.emplace_back([&] {
      while (!ctl.stop.load(std::memory_order_relaxed) && !s.found.load(std::memory_order_relaxed)) {
        std::uint64_t start = 0, end = 0;
        if (!claimHybridTail(ctl, start, end)) break;
        const std::uint64_t h = ctl.head.load(std::memory_order_relaxed);
        if (end <= h) break;
        if (start < h) start = h;
        if (start < end) crackDictRange(s, (std::size_t)start, (std::size_t)end, &ctl.stop);
      }
    });
  }
  for (auto& th : pool) th.join();
}

}  // namespace jose
