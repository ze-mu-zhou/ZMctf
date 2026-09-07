#include <windows.h>
#include <psapi.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

// Isolated loading experiment; does not replace the production search engine.
struct Entry { uint32_t offset, length; };
using Clock = std::chrono::steady_clock;
int main(int argc, char** argv) {
  if (argc != 3) return 2;
  std::string mode = argv[1];
  std::ifstream f(argv[2], std::ios::binary | std::ios::ate);
  if (!f) return 2;
  size_t bytes = (size_t)f.tellg();
  if (bytes > UINT32_MAX) return 2;
  f.seekg(0);
  std::vector<std::string> words;
  std::unique_ptr<char[]> data;
  std::vector<Entry> entries;
  auto t0 = Clock::now();
  if (mode == "getline" || mode == "reserve") {
    if (mode == "reserve") words.reserve(bytes / 10); // Estimate fits this fixture.
    std::string line;
    while (std::getline(f, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
      if (!line.empty()) words.push_back(line);
    }
  } else if (mode == "flat") {
    data = std::make_unique_for_overwrite<char[]>(bytes);
    f.read(data.get(), bytes);
    if ((size_t)f.gcount() != bytes) return 2;
    entries.reserve(bytes / 10);
    size_t begin = 0;
    while (begin < bytes) {
      const char* nl = (const char*)std::memchr(data.get() + begin, '\n', bytes - begin);
      size_t end = nl ? (size_t)(nl - data.get()) : bytes;
      size_t trimmed = end;
      while (trimmed > begin && (data[trimmed-1] == '\r' || data[trimmed-1] == '\n')) --trimmed;
      if (trimmed > begin) entries.push_back({(uint32_t)begin, (uint32_t)(trimmed - begin)});
      begin = end + 1;
    }
  } else return 2;
  double load = std::chrono::duration<double>(Clock::now() - t0).count();
  PROCESS_MEMORY_COUNTERS pm{};
  GetProcessMemoryInfo(GetCurrentProcess(), &pm, sizeof(pm));
  size_t count = mode == "flat" ? entries.size() : words.size();
  size_t capacity = mode == "flat" ? entries.capacity() : words.capacity();
  // Full content/order checksum outside the timed load stage, including NUL bytes.
  uint64_t checksum = 14695981039346656037ULL;
  for (size_t i = 0; i < count; ++i) {
    const char* p = mode == "flat" ? data.get()+entries[i].offset : words[i].data();
    size_t n = mode == "flat" ? entries[i].length : words[i].size();
    for (size_t j = 0; j < n; ++j) { checksum ^= (uint8_t)p[j]; checksum *= 1099511628211ULL; }
    checksum ^= n; checksum *= 1099511628211ULL;
  }
  auto td = Clock::now();
  std::vector<std::string>().swap(words);
  std::vector<Entry>().swap(entries);
  data.reset();
  double destroy = std::chrono::duration<double>(Clock::now() - td).count();
  printf("{\"mode\":\"%s\",\"file_bytes\":%zu,\"count\":%zu,\"capacity\":%zu,\"sizeof_string\":%zu,\"sizeof_entry\":%zu,\"load_s\":%.9f,\"destroy_s\":%.9f,\"peak_working_set\":%zu,\"checksum\":\"%llu\"}\n",
      mode.c_str(),bytes,count,capacity,sizeof(std::string),sizeof(Entry),load,destroy,
      (size_t)pm.PeakWorkingSetSize,(unsigned long long)checksum);
}
