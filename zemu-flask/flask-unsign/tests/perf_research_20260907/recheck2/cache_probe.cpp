#include "src/flask.cpp"
#include <iostream>
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  WordSet words;
  std::string error;
  if (!loadWordSet(argv[1], words, error)) { std::cerr << error; return 3; }
  uint64_t sz; int64_t mt;
  if (!dictFileStat(argv[1], sz, mt)) return 4;
  auto* entry = dictCacheStore(argv[1], words, sz, mt);
  std::cout << "budget=" << dictCacheBudget() << " admitted=" << !!entry;
  if (entry) {
    std::cout << " accounted=" << entry->bytes()
              << " capacity_bytes=" << entry->words.bytes.capacity() + entry->words.off.capacity()*sizeof(uint32_t)
              << " words=" << entry->words.size();
  }
  std::cout << '\n';
}
