// Checks the rule that keeps the REST per-account caches to one database.
//
// The caches are keyed by account id, and beldex-lws-rebuild renumbers
// accounts, so after a /switch_db the same id can name a different account.
// Serving a cached entry across that boundary hands one user another user's
// totals. `cache_generation` decides, per request, whether the cache may be
// used at all and clears it when a newer database is seen.
//
// Built as `lws-cache-generation-test` when BUILD_TESTS=ON. Takes no
// arguments; prints one line per case and exits non-zero on any failure.

#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>

#include "util/cache_generation.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }
}

int main()
{
  // id -> "whose totals these are"
  std::unordered_map<std::uint32_t, std::string> cache;
  lws::cache_generation db;
  const auto clear = [&cache] { cache.clear(); };

  check(!db.admit(0, clear), "an unknown database (0) may not use the cache");

  check(db.admit(1, clear), "the first database may use the cache");
  cache[7] = "alice";
  check(db.admit(1, clear) && cache.count(7) == 1, "entries persist while the database is unchanged");

  // /switch_db: the rebuilt database numbers bob as 7.
  check(db.admit(2, clear), "a request from the new database may use the cache");
  check(cache.empty(), "seeing the new database cleared the old entries");
  cache[7] = "bob";

  // A request that started before the switch is still running.
  check(!db.admit(1, clear), "a request still on the old database is kept out");
  check(cache.count(7) == 1 && cache[7] == "bob", "and it did not disturb the new entries");
  check(db.current() == 2, "the cache stays on the newest database");

  check(db.admit(5, clear) && cache.empty(), "a later switch clears again");

  std::cout << (failures ? "FAILED" : "PASSED") << " (" << failures << " failure(s))\n";
  return failures ? 1 : 0;
}
