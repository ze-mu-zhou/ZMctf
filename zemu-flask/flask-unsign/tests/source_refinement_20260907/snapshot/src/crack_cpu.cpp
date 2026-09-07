#include "crack_cpu.h"
#include "thread_group.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <thread>

#ifdef _WIN32
#include <windows.h> // 原生 Sleep:winpthreads 的 sleep_for 会拖慢同进程线程池(实测 -30%)
#endif

std::atomic<bool> g_crackAbort{false};

bool parseMask(const std::string& mask, std::vector<std::string>& pos) {
  static const std::string L = "abcdefghijklmnopqrstuvwxyz";
  static const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const std::string D = "0123456789";
  static const std::string S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // hashcat ?s(含空格)
  static const std::string A = L + U + D + S;                          // hashcat ?a = 95 可打印
  for (size_t i = 0; i < mask.size(); i++) {
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
      pos.emplace_back(1, mask[i]); // 字面字符原样保留
    }
  }
  return !pos.empty();
}

std::string maskCandidate(uint64_t idx, const std::vector<std::string>& pos) {
  std::string s(pos.size(), ' ');
  for (int k = (int)pos.size() - 1; k >= 0; k--) {
    const std::string& cs = pos[k];
    s[k] = cs[idx % cs.size()];
    idx /= cs.size();
  }
  return s;
}

/**
 * 线程内联进度上报:worker 在批次边界自查时钟(每批一次 QPC,~0.2% 开销),
 * 首个到点的线程负责打印。不用独立监视线程——实测多一个睡眠线程会把
 * 32 线程池的字典吞吐拖慢 ~30%(调度扰动),winpthreads/native Sleep 均如此。
 */
struct ProgressInl {
  std::chrono::steady_clock::time_point t0;
  std::atomic<uint64_t> lastMs{0}; // 上次打印时刻(ms since t0);CAS 保证只一个线程打
  uint64_t total = 0;
  bool on = true;

  void begin(uint64_t total_) {
    t0 = std::chrono::steady_clock::now();
    total = total_;
    on = !std::getenv("ZK_NOPROG");
  }
  void tick(const std::atomic<uint64_t>& att) {
    if (!on) return;
    uint64_t ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0).count();
    uint64_t last = lastMs.load(std::memory_order_relaxed);
    if (ms < last + 10000) return; // 10s 一报(10s 内完成的任务无输出)
    if (!lastMs.compare_exchange_strong(last, ms, std::memory_order_relaxed)) return;
    double el = ms / 1000.0;
    uint64_t a = att.load(std::memory_order_relaxed);
    double rate = el > 0 ? a / el : 0;
    char line[128];
    if (total > 0)
      snprintf(line, sizeof line, "[~] 进度 %llu/%llu(%.1f%%),%.0fM/s\n",
               (unsigned long long)a, (unsigned long long)total,
               a * 100.0 / total, rate / 1e6);
    else
      snprintf(line, sizeof line, "[~] 已尝试 %llu,%.0fM/s\n",
               (unsigned long long)a, rate / 1e6);
    std::cerr << line;
  }
};

/** 引擎运行时共享态:worker 里周期回写 attempts 供进度显示;命中写 secret(仅一个真命中) */
struct RunCtx {
  std::atomic<uint64_t> attempts{0};
  std::atomic<bool> found{false};
  std::atomic<bool> stop{false};
  std::string secret;
};

/** 线程池骨架:计时 + 汇总 */
template <typename Worker>
static CrackResult runPool(int threads, uint64_t total, RunCtx& rc, ProgressInl& prog, Worker worker,
                           std::atomic<bool>* peerStop = nullptr) {
  CrackResult res;
  auto t0 = std::chrono::steady_clock::now();
  int n = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  try {
    ThreadGroup pool(rc.stop, peerStop);
    for (int i = 0; i < n && !pool.stopped(); i++) pool.launch(worker);
    pool.finish();
  } catch (const std::exception& e) {
    res.error = e.what();
  }
  res.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  // On failure this is the published count, a lower bound: a throwing worker
  // may still have an unflushed local batch. Never expose partial success.
  res.attempts = rc.attempts.load();
  if (!res.error.empty()) return res;
  res.found = rc.found.load();
  res.secret = rc.secret;
  return res;
}

/**
 * 加载字典为连续表示:整块读入后原地紧凑化(写游标永不越过读游标,in-place 安全),
 * 扫描中跟踪最长词(免 GPU 打包阶段二次 O(n) 扫)。
 * 行尾处理与旧 getline 实现一致:去掉全部尾部 \r,空行跳过。
 */
bool loadWordSet(const std::string& path, WordSet& out, std::string& error) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) {
    error = "打不开字典: " + path;
    return false;
  }
  const std::streamoff sz = f.tellg();
  if (sz < 0 || (uint64_t)sz > UINT32_MAX) {
    error = sz < 0 ? "读取字典失败: " + path
                   : "字典超过 4GB(连续表示的 u32 偏移上限),请拆分: " + path;
    return false;
  }
  out.bytes.resize((size_t)sz);
  f.seekg(0);
  if (sz > 0 && !f.read(out.bytes.data(), sz)) {
    error = "读取字典失败: " + path;
    return false;
  }
  f.close();

  const char* p = out.bytes.data();
  const size_t n = out.bytes.size();
  out.off.clear();
  out.off.reserve(n / 24 + 16); // 经验均词长,防多次倍增;不足仍按 push_back 增长
  out.off.push_back(0);
  uint32_t w = 0; // 写游标(紧凑化目标),w <= 读游标恒成立
  uint32_t maxLen = 0;
  size_t i = 0;
  while (i < n) {
    const void* nl = memchr(p + i, '\n', n - i);
    const size_t eol = nl ? (size_t)((const char*)nl - p) : n;
    size_t len = eol - i;
    while (len > 0 && p[i + len - 1] == '\r') len--; // 与旧实现一致:去全部尾部 \r
    if (len > 0) {
      if ((size_t)w != i) memmove(out.bytes.data() + w, p + i, len);
      w += (uint32_t)len;
      out.off.push_back(w);
      if (len > maxLen) maxLen = (uint32_t)len;
    }
    i = eol + 1;
  }
  out.bytes.resize(w);
  // vector 只缩 size 不缩 capacity:紧凑化省得多则归还尾部容量(如几乎全空行的文件,
  // 否则缓存按容量计费时会长期持有整个文件大小的空闲缓冲);off 同理(reserve 估计
  // + 倍增增长可能留出冗余)。轻微浪费不收缩,省一次全量拷贝。
  if ((size_t)w < out.bytes.capacity() / 2) out.bytes.shrink_to_fit();
  if (out.off.capacity() > out.off.size() + out.off.size() / 4) out.off.shrink_to_fit();
  out.maxLen = maxLen;
  if (out.off.size() <= 1) {
    error = "字典为空";
    return false;
  }
  return true;
}

CrackResult crackCpuWordlist(const std::string& wordlistPath, int threads,
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                             VerifyBatchFn verifyBatch, int batchSize) {
  WordSet words;
  CrackResult res;
  if (!loadWordSet(wordlistPath, words, res.error)) return res;
  return crackCpuWords(words, threads, verify, ctx, verifyBatch, batchSize);
}

/** CPU 字典爆破(内存字典:与 GPU 路径共用一次加载,避免二次读盘) */
CrackResult crackCpuWords(const WordSet& words, int threads,
                          bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                          VerifyBatchFn verifyBatch, int batchSize) {
  RunCtx rc;
  if (words.empty()) {
    CrackResult res;
    res.error = "字典为空";
    return res;
  }
  std::atomic<size_t> idx{0};
  ProgressInl prog;
  prog.begin(words.size());
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  return runPool(threads, words.size(), rc, prog, [&] {
    uint64_t local = 0;
    // 直读连续缓冲(不整批拷贝):批量验证快 8~16 倍后拷贝是纯开销
    std::vector<const uint8_t*> bkeys((size_t)B); // 批量槽:直接指进 words.bytes
    std::vector<size_t> bklen((size_t)B);
    while (!rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      // 每线程每次领 1024 个,减少原子争抢
      size_t begin = idx.fetch_add(1024, std::memory_order_relaxed);
      if (begin >= words.size()) break;
      size_t end = begin + 1024 < words.size() ? begin + 1024 : words.size();
      const size_t m = end - begin;
      const uint32_t* off = words.off.data() + begin; // 本块偏移视图
      const char* base = words.bytes.data();
      for (size_t i = 0; i < m;) {
        if (B > 1 && m - i >= (size_t)B) {
          // —— 批量路径:一次 SIMD 验证 B 个变长候选 ——
          for (int b = 0; b < B; b++) {
            bkeys[(size_t)b] = (const uint8_t*)base + off[i + (size_t)b];
            bklen[(size_t)b] = off[i + (size_t)b + 1] - off[i + (size_t)b];
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret.assign(base + off[i + (size_t)hit],
                               off[i + (size_t)hit + 1] - off[i + (size_t)hit]);
            break;
          }
          local += (uint64_t)B;
          i += (size_t)B;
          continue;
        }
        // —— 标量路径:批尾余数 / 未启用批量 ——
        local++;
        const uint8_t* cand = (const uint8_t*)base + off[i];
        const size_t clen = off[i + 1] - off[i];
        if (verify(cand, clen, ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret.assign((const char*)cand, clen);
          break;
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      prog.tick(rc.attempts);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
}

/* ============ 混合模式:CPU 从尾部降序吃块,与 GPU(头部升序)对向推进 ============ */

// CPU 侧领块粒度:太大则命中/取消的停止延迟高,太小则游标原子争抢;64K ≈ 0.6ms/线程
static const uint64_t HYBRID_CHUNK = 65536;

// 从尾部无下溢地领取一段区间;不足一个 chunk 时把 tail 钳到 0。
static bool claimHybridTail(HybridCtl& ctl, uint64_t& start, uint64_t& end) {
  uint64_t hi = ctl.tail.load(std::memory_order_relaxed);
  while (hi != 0) {
    uint64_t lo = hi > HYBRID_CHUNK ? hi - HYBRID_CHUNK : 0;
    if (ctl.tail.compare_exchange_weak(hi, lo, std::memory_order_relaxed)) {
      start = lo;
      end = hi;
      return true;
    }
  }
  return false;
}

CrackResult crackCpuMaskRange(const std::vector<std::string>& pos, int threads,
                              bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                              HybridCtl& ctl,
                              VerifyBatchFn verifyBatch, int batchSize) {
  CrackResult res;
  const size_t L = pos.size();
  RunCtx rc;
  ProgressInl prog;
  prog.on = false; // 混合模式进度由 GPU 侧统一汇报
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  res = runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表)
    std::string cand(L, ' ');
    // 批量流专用状态:每槽持有独立候选拷贝(与 crackCpuMask 批量段同构)
    std::vector<std::string> bcand((size_t)B, std::string(L, ' '));
    std::vector<const uint8_t*> bkeys((size_t)B);
    std::vector<size_t> bklen((size_t)B);
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = 0, end = 0;
      if (!claimHybridTail(ctl, start, end)) break;
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break; // 剩余空间已全被 GPU 认领
      if (start < h) start = h; // 与 GPU 认领区重叠部分丢弃:可能重复验,不会漏
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end;) {
        if (B > 1 && end - i >= (uint64_t)B) {
          // 批量路径:槽位 b = 候选 i+b,先推进滚动源再整串拷入(顺序不能反)
          for (int b = 0; b < B; b++) {
            if (b > 0) {
              for (size_t k = L; k-- > 0;) {
                if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
                idx[k] = 0; cand[k] = pos[k][0];
              }
            }
            bcand[(size_t)b] = cand;
            bkeys[(size_t)b] = (const uint8_t*)bcand[(size_t)b].data(); bklen[(size_t)b] = L;
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = bcand[(size_t)hit];
            ctl.stop.store(true, std::memory_order_relaxed);
            break;
          }
          // 批内推进了 B-1 次;再进一位对齐下批起点 i+B
          for (size_t k = L; k-- > 0;) {
            if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
            idx[k] = 0; cand[k] = pos[k][0];
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  }, &ctl.stop);
  return res;
}

CrackResult crackCpuWordsRange(const WordSet& words, int threads,
                               bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                               HybridCtl& ctl,
                               VerifyBatchFn verifyBatch, int batchSize) {
  RunCtx rc;
  ProgressInl prog;
  prog.on = false;
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  return runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<const uint8_t*> bkeys((size_t)B); // 批量槽:直接指进 words.bytes
    std::vector<size_t> bklen((size_t)B);
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = 0, end = 0;
      if (!claimHybridTail(ctl, start, end)) break;
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break;
      if (start < h) start = h;
      const uint64_t m = end - start;
      const uint32_t* off = words.off.data() + start; // 本块偏移视图(直读,拷贝纯亏)
      const char* base = words.bytes.data();
      for (uint64_t i = 0; i < m;) {
        if (B > 1 && m - i >= (uint64_t)B) {
          // 批量路径:一次 SIMD 验证 B 个变长候选
          for (int b = 0; b < B; b++) {
            bkeys[(size_t)b] = (const uint8_t*)base + off[i + (uint64_t)b];
            bklen[(size_t)b] = off[i + (uint64_t)b + 1] - off[i + (uint64_t)b];
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret.assign(base + off[i + (uint64_t)hit],
                               off[i + (uint64_t)hit + 1] - off[i + (uint64_t)hit]);
            ctl.stop.store(true, std::memory_order_relaxed);
            break;
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        local++;
        const uint8_t* cand = (const uint8_t*)base + off[i];
        const size_t clen = off[i + 1] - off[i];
        if (verify(cand, clen, ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret.assign((const char*)cand, clen);
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  }, &ctl.stop);
}

CrackResult crackCpuMask(const std::vector<std::string>& pos, int threads,
                         bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                         VerifyBatchFn verifyBatch, int batchSize) {
  CrackResult res;
  uint64_t total = 1;
  for (const auto& cs : pos) {
    if (total > UINT64_MAX / cs.size()) {
      res.error = "组合数过大(超过 2^64)";
      return res;
    }
    total *= (uint64_t)cs.size();
  }
  const uint64_t CHUNK = 4096;
  const size_t L = pos.size();
  std::atomic<uint64_t> base{0};
  RunCtx rc;
  ProgressInl prog;
  prog.begin(total);
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  res = runPool(threads, total, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表),进位递增替代逐候选除法链
    std::string cand(L, ' ');     // 定长候选缓冲,原地改写,无逐候选 string 构造

    // 批量流专用状态:每槽持有独立候选拷贝(bkeys 必须各指各的)
    std::vector<std::string> bcand((size_t)B, std::string(L, ' '));
    std::vector<const uint8_t*> bkeys((size_t)B);
    std::vector<size_t> bklen((size_t)B);

    while (!rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = base.fetch_add(CHUNK, std::memory_order_relaxed);
      if (start >= total) break;
      uint64_t end = start + CHUNK < total ? start + CHUNK : total;
      // 块首:序号 → 里程表(混合进制除法链,每块仅一次),与 maskCandidate 序一致
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end;) {
        if (B > 1 && end - i >= (uint64_t)B) {
          // —— 批量路径:组装 B 个连续候选(先推进滚动源,再整串拷入槽位) ——
          // 槽位 b 的内容必须等于候选 i+b:推进一步后再拷贝,顺序不能反
          for (int b = 0; b < B; b++) {
            if (b > 0) {
              for (size_t k = L; k-- > 0;) {
                if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
                idx[k] = 0; cand[k] = pos[k][0];
              }
            }
            bcand[(size_t)b] = cand;
            bkeys[(size_t)b] = (const uint8_t*)bcand[(size_t)b].data(); bklen[(size_t)b] = L;
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = bcand[(size_t)hit];
            break;
          }
          // 批内推进了 B-1 次(cand=i+B-1);再进一位对齐下批起点 i+B
          for (size_t k = L; k-- > 0;) {
            if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
            idx[k] = 0; cand[k] = pos[k][0];
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        // —— 标量路径:块尾余数 / 未启用批量 ——
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          break;
        }
        // 里程表进位:末位最快,绝大多数迭代 O(1)
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      prog.tick(rc.attempts);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
  return res;
}
