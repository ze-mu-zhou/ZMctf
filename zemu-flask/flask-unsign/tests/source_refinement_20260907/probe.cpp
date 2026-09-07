int main() {
  unsigned long long x;
  __CPROVER_assume(x < 100);
  auto f = [&]() { return x + 1; };
  __CPROVER_assert(f() > x, "lambda arithmetic");
}
