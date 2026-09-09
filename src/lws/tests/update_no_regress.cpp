// Regression check for storage::update() moving an account's scan_height
// BACKWARDS.
//
// The scanner partitions accounts into thread groups and drives each group from
// the LOWEST scan_height in it (scanner.cpp: `users.begin()->scan_height()`).
// storage::update() then stamped the height reached by that batch onto EVERY
// account in the group. So an account already at the chain tip, grouped with
// one that an admin had just rescanned, was rewritten back down to the rescan
// height: its wallet saw `scanned_height` jump backwards and it re-scanned the
// whole chain for nothing. With 50k accounts one rescan did that to everybody
// sharing the boundary thread.
//
// This builds exactly that group - one account rescanned to a low height, one
// sitting at the tip - runs one update() over a low block range, and asserts
// the tip account did not move. It also asserts update() still reports BOTH
// accounts as updated, because the scan loop treats `updated != users.size()`
// as a failure and restarts the thread on it.
//
// Built as `lws-update-no-regress-test` when BUILD_TESTS=ON. Takes no
// arguments; prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "db/account.h"
#include "db/data.h"
#include "db/storage.h"
#include "crypto/crypto.h"
#include "epee/span.h"

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

  //! \return The stored account record for `address`.
  lws::db::account fetch(lws::db::storage& disk, const lws::db::account_address& address)
  {
    auto reader = MONERO_UNWRAP(disk.start_read());
    const auto found = reader.get_account(address);
    if (!found)
      throw std::runtime_error{"get_account failed: " + found.error().message()};
    return found->second;
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-noregress-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    auto disk = lws::db::storage::open(dir.string().c_str(), 100);

    constexpr const std::uint64_t tip = 400;
    std::vector<crypto::hash> chain;
    chain.reserve(tip + 1);
    for (std::uint64_t i = 0; i <= tip; ++i)
      chain.push_back(hash_of(0xABCDEF00u + i));

    // Seed height 1, then extend to `tip`, matching the daemon's own sequence.
    if (const auto rc = disk.sync_chain(lws::db::block_id(0), {chain.data(), 2}); !rc)
      throw std::runtime_error{"sync_chain (seed) failed: " + rc.error().message()};
    if (const auto rc = disk.sync_chain(lws::db::block_id(1), {chain.data() + 1, chain.size() - 1}); !rc)
      throw std::runtime_error{"sync_chain (extend) failed: " + rc.error().message()};

    // `behind` stands in for a rescanned account, `at_tip` for everyone else.
    crypto::secret_key behind_key{}, tip_key{};
    const lws::db::account_address behind_addr = make_address(behind_key);
    const lws::db::account_address tip_addr = make_address(tip_key);

    if (const auto rc = disk.add_account(behind_addr, behind_key); !rc)
      throw std::runtime_error{"add_account(behind) failed: " + rc.error().message()};
    if (const auto rc = disk.add_account(tip_addr, tip_key); !rc)
      throw std::runtime_error{"add_account(at tip) failed: " + rc.error().message()};

    constexpr const std::uint64_t rescan_to = 10;
    {
      const auto rc = disk.rescan(
        lws::db::block_id(rescan_to),
        epee::span<const lws::db::account_address>{std::addressof(behind_addr), 1});
      if (!rc)
        throw std::runtime_error{"rescan failed: " + rc.error().message()};
    }

    check(std::uint64_t(fetch(disk, behind_addr).scan_height) == rescan_to,
          "rescanned account starts at height 10");
    check(std::uint64_t(fetch(disk, tip_addr).scan_height) == tip,
          "other account starts at the chain tip (400)");

    /* One batch, exactly as a scan thread would submit it for this group: the
       range starts at the group's lowest scan_height, not the tip account's. */
    constexpr const std::uint64_t batch = 65;
    const std::uint64_t last_update = rescan_to + batch - 1; // 74

    std::vector<lws::account> users;
    users.emplace_back(fetch(disk, behind_addr), std::vector<lws::db::output_id>{});
    users.emplace_back(fetch(disk, tip_addr), std::vector<lws::db::output_id>{});

    const auto updated = disk.update(
      lws::db::block_id(rescan_to),
      epee::span<const crypto::hash>{chain.data() + rescan_to, batch},
      epee::to_span(users)
    );
    if (!updated)
      throw std::runtime_error{"update failed: " + updated.error().message()};

    const std::uint64_t behind_now = std::uint64_t(fetch(disk, behind_addr).scan_height);
    const std::uint64_t tip_now = std::uint64_t(fetch(disk, tip_addr).scan_height);

    check(behind_now == last_update,
          "rescanned account advanced to the end of the batch (74)");

    // The actual regression. Before the fix this was `last_update` (74).
    check(tip_now == tip,
          "account at the tip was NOT dragged backwards (still 400)");

    /* The scan loop restarts its thread whenever update() reports fewer
       accounts than it was handed, so skipping the tip account must not mean
       reporting it as un-updated - that would trade a wrong height for an
       endless restart loop. */
    check(*updated == users.size(),
          "update() still reports every account as updated");
  }
  catch (const std::exception& e)
  {
    std::cerr << "unexpected exception: " << e.what() << std::endl;
    ++failures;
  }

  boost::system::error_code ec{};
  boost::filesystem::remove_all(dir, ec);

  std::cout << (failures ? "FAILED" : "PASSED") << std::endl;
  return failures ? 1 : 0;
}
