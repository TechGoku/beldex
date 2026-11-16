// Checks for the two opt-in signup limits: the per-client rate limit
// (`--signup-rate-limit`) and the account ceiling (`--max-accounts`).
//
// Both default to 0, which must mean "no limit": /login creating an account on
// first sight is what wallets rely on, so an unconfigured server has to behave
// exactly as before. The rest checks each limit actually bites when set.
//
// Built as `lws-signup-limit-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "db/data.h"
#include "db/storage.h"
#include "error.h"
#include "util/signup_limit.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  crypto::hash hash_of(std::uint64_t n)
  {
    crypto::hash out{};
    std::memcpy(out.data, &n, sizeof(n));
    return out;
  }

  lws::db::account_address make_address(crypto::secret_key& view_key)
  {
    crypto::public_key view_public{};
    crypto::generate_keys(view_public, view_key);

    lws::db::account_address address{};
    address.view_public = view_public;
    address.spend_public = crypto::rand<crypto::public_key>();
    return address;
  }

  void rate_limit_cases()
  {
    using clock = lws::signup_limiter::clock;
    const clock::time_point t0 = clock::now();

    {
      lws::signup_limiter limits{};
      bool all = true;
      for (unsigned i = 0; i < 1000; ++i)
        all = all && limits.allow("203.0.113.7", 0, t0);
      check(all, "limit 0 allows every signup");
      check(limits.tracked() == 0, "limit 0 records nothing");
    }

    {
      lws::signup_limiter limits{};
      const bool first3 = limits.allow("203.0.113.7", 3, t0) &&
                          limits.allow("203.0.113.7", 3, t0) &&
                          limits.allow("203.0.113.7", 3, t0);
      check(first3, "limit 3 allows three signups from one client");
      check(!limits.allow("203.0.113.7", 3, t0), "the fourth in the same hour is refused");
      check(limits.allow("198.51.100.1", 3, t0), "another client is unaffected");
      check(!limits.allow("203.0.113.7", 3, t0 + std::chrono::minutes{59}), "still refused after 59 minutes");
      check(limits.allow("203.0.113.7", 3, t0 + std::chrono::minutes{60}), "allowed again once the hour is up");
    }

    {
      lws::signup_limiter limits{};
      check(limits.allow("2001:db8:1:2::1", 1, t0), "first signup from an IPv6 /64");
      check(!limits.allow("2001:db8:1:2:ffff::9", 1, t0), "another address in the same /64 shares the allowance");
      check(limits.allow("2001:db8:1:3::1", 1, t0), "a different /64 has its own allowance");
      check(lws::signup_bucket("192.0.2.5") == "192.0.2.5", "IPv4 is counted per address");
      check(lws::signup_bucket("not-an-address") == "not-an-address", "an unparsable host is used verbatim");
    }

    {
      lws::signup_limiter limits{2};
      limits.allow("192.0.2.1", 1, t0);
      limits.allow("192.0.2.2", 1, t0);
      check(limits.tracked() == 2, "table holds up to its bound");
      check(limits.allow("192.0.2.3", 1, t0), "a new client is not blocked by a full table");
      check(limits.tracked() <= 2, "table never grows past its bound");
    }
  }

  void account_cap_cases(const boost::filesystem::path& dir)
  {
    auto disk = lws::db::storage::open(dir.string().c_str(), 100);

    std::vector<crypto::hash> chain;
    for (std::uint64_t i = 0; i <= 10; ++i)
      chain.push_back(hash_of(0x51600000u + i));
    if (const auto rc = disk.sync_chain(lws::db::block_id(0), {chain.data(), chain.size()}); !rc)
      throw std::runtime_error{"sync_chain failed: " + rc.error().message()};

    const auto add = [&disk] (std::uint64_t cap) {
      crypto::secret_key key{};
      const lws::db::account_address address = make_address(key);
      return disk.add_account(address, key, lws::db::default_account, cap);
    };

    bool uncapped = true;
    for (unsigned i = 0; i < 5; ++i)
      uncapped = uncapped && bool(add(0));
    check(uncapped, "max_accounts 0 adds accounts without a ceiling");

    // Five exist now; a ceiling of 7 leaves room for exactly two more.
    check(bool(add(7)), "6th account allowed under a ceiling of 7");
    check(bool(add(7)), "7th account allowed under a ceiling of 7");
    const auto refused = add(7);
    check(!refused && refused == lws::error::account_max, "8th account refused with account_max");
    check(bool(add(0)), "the default (0) still adds past an earlier ceiling");
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-signup-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    rate_limit_cases();
    account_cap_cases(dir);
  }
  catch (const std::exception& e)
  {
    std::cout << "  FAIL exception: " << e.what() << '\n';
    ++failures;
  }

  boost::system::error_code ignored{};
  boost::filesystem::remove_all(dir, ignored);

  std::cout << (failures ? "FAILED" : "PASSED") << " (" << failures << " failure(s))\n";
  return failures ? 1 : 0;
}
