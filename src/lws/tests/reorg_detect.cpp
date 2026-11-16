// Checks that storage::update() refuses a scan batch that is not on the
// stored chain, and keeps the stored chain in step with scanning.
//
// The hash comparison in update() used to be commented out. Reorg detection
// then rested on sync_chain alone, which only compares hashes already in the
// `blocks` table - and that table was only extended between scan passes, so it
// trailed account scan heights by thousands of blocks. A block replaced above
// the stored tip went unnoticed: what was scanned from it stayed, and the
// block that replaced it was never scanned.
//
// This runs that sequence: an account scans past the stored tip, the chain
// reorganises underneath it, and the next batch arrives from the new branch.
//
// Built as `lws-reorg-detect-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "db/account.h"
#include "db/data.h"
#include "db/storage.h"
#include "epee/span.h"
#include "error.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  //! A block hash on branch `branch` at height `n`.
  crypto::hash hash_of(std::uint64_t branch, std::uint64_t n)
  {
    crypto::hash out{};
    std::memcpy(out.data, &branch, sizeof(branch));
    std::memcpy(out.data + sizeof(branch), &n, sizeof(n));
    return out;
  }

  //! Hashes for heights [first, last] on `branch`.
  std::vector<crypto::hash> range(std::uint64_t branch, std::uint64_t first, std::uint64_t last)
  {
    std::vector<crypto::hash> out;
    for (std::uint64_t n = first; n <= last; ++n)
      out.push_back(hash_of(branch, n));
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

  lws::db::account fetch(lws::db::storage& disk, const lws::db::account_address& address)
  {
    auto reader = MONERO_UNWRAP(disk.start_read());
    const auto found = reader.get_account(address);
    if (!found)
      throw std::runtime_error{"get_account failed: " + found.error().message()};
    return found->second;
  }

  std::uint64_t stored_tip(lws::db::storage& disk)
  {
    auto reader = MONERO_UNWRAP(disk.start_read());
    return std::uint64_t(MONERO_UNWRAP(reader.get_last_block()).id);
  }

  crypto::hash stored_hash(lws::db::storage& disk, std::uint64_t height)
  {
    auto reader = MONERO_UNWRAP(disk.start_read());
    return MONERO_UNWRAP(reader.get_block_hash(lws::db::block_id(height)));
  }

  expect<std::size_t> scan(lws::db::storage& disk, const lws::db::account_address& address,
                           std::uint64_t height, const std::vector<crypto::hash>& chain)
  {
    std::vector<lws::account> users;
    users.emplace_back(fetch(disk, address), std::vector<lws::db::output_id>{});
    return disk.update(lws::db::block_id(height), epee::to_span(chain), epee::to_span(users));
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-reorg-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    auto disk = lws::db::storage::open(dir.string().c_str(), 100);

    // Branch 1 up to height 100, synced the way the daemon delivers it.
    {
      const auto seed = range(1, 0, 1);
      const auto rest = range(1, 1, 100);
      if (const auto rc = disk.sync_chain(lws::db::block_id(0), epee::to_span(seed)); !rc)
        throw std::runtime_error{"sync_chain (seed) failed: " + rc.error().message()};
      if (const auto rc = disk.sync_chain(lws::db::block_id(1), epee::to_span(rest)); !rc)
        throw std::runtime_error{"sync_chain (extend) failed: " + rc.error().message()};
    }

    crypto::secret_key key{};
    const lws::db::account_address address = make_address(key);
    if (const auto rc = disk.add_account(address, key); !rc)
      throw std::runtime_error{"add_account failed: " + rc.error().message()};
    check(std::uint64_t(fetch(disk, address).scan_height) == 100, "account starts at the stored tip (100)");

    // Scan past the stored tip: anchor 100, new blocks 101..120.
    {
      const auto rc = scan(disk, address, 100, range(1, 100, 120));
      check(bool(rc), "a batch on the stored chain is accepted");
    }
    check(std::uint64_t(fetch(disk, address).scan_height) == 120, "account advanced to 120");
    check(stored_tip(disk) == 120, "stored chain extended to the account's scan height");
    check(stored_hash(disk, 115) == hash_of(1, 115), "appended hashes are the scanned ones");

    // A batch wholly below the tip, still on branch 1, changes nothing stored.
    {
      const auto rc = scan(disk, address, 90, range(1, 90, 110));
      check(bool(rc), "a batch below the tip that matches is accepted");
      check(stored_tip(disk) == 120, "the stored tip is unchanged by it");
    }

    // The chain reorganises from height 110: branch 2 replaces 110 onward. The
    // next batch, anchored at the account's height, comes from branch 2.
    std::vector<crypto::hash> branch2 = range(1, 100, 109);
    {
      const auto tail = range(2, 110, 130);
      branch2.insert(branch2.end(), tail.begin(), tail.end());
    }
    {
      const std::vector<crypto::hash> batch(branch2.begin() + 20, branch2.end()); // heights 120..130
      const auto rc = scan(disk, address, 120, batch);
      check(!rc && rc == lws::error::blockchain_reorg, "a batch from the new branch is refused as a reorg");
    }
    check(std::uint64_t(fetch(disk, address).scan_height) == 120, "the refused batch wrote nothing to the account");
    check(stored_tip(disk) == 120 && stored_hash(disk, 120) == hash_of(1, 120), "the refused batch wrote nothing to the chain");

    // The scanner's next pass syncs; that finds the fork and rolls back.
    if (const auto rc = disk.sync_chain(lws::db::block_id(100), epee::to_span(branch2)); !rc)
      throw std::runtime_error{"sync_chain (reorg) failed: " + rc.error().message()};
    check(std::uint64_t(fetch(disk, address).scan_height) < 110, "sync rolled the account back below the fork");
    check(stored_hash(disk, 110) == hash_of(2, 110), "the stored chain now follows the new branch");

    // A batch that starts above the stored tip cannot be checked.
    {
      const auto rc = scan(disk, address, 500, range(2, 500, 510));
      check(!rc && rc == lws::error::bad_blockchain, "a batch above the stored tip is refused");
    }
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
