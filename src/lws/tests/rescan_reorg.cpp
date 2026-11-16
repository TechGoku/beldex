// Checks that a chain reorganisation removes what an account recorded from
// the orphaned blocks even when an admin rescan has lowered that account's
// scan height below the fork.
//
// A rescan lowers the scan height but keeps the stored outputs and spends.
// rollback_accounts used to visit only accounts at or above the fork height,
// so a rescanned account below it kept outputs from blocks that were no longer
// on the chain, and they stayed in its balance after it rescanned past them.
//
// Built as `lws-rescan-reorg-test` when BUILD_TESTS=ON. Takes no arguments;
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

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  crypto::hash hash_of(std::uint64_t branch, std::uint64_t n)
  {
    crypto::hash out{};
    std::memcpy(out.data, &branch, sizeof(branch));
    std::memcpy(out.data + sizeof(branch), &n, sizeof(n));
    return out;
  }

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

  //! Heights of every output stored for `address`.
  std::vector<std::uint64_t> output_heights(lws::db::storage& disk, const lws::db::account_address& address)
  {
    const lws::db::account_id id = fetch(disk, address).id;
    auto reader = MONERO_UNWRAP(disk.start_read());
    auto outputs = MONERO_UNWRAP(reader.get_outputs(id));
    std::vector<std::uint64_t> heights;
    for (auto it = outputs.make_iterator(); !it.is_end(); ++it)
      heights.push_back(std::uint64_t(it.get_value<MONERO_FIELD(lws::db::output, link.height)>()));
    return heights;
  }

  lws::db::output make_output(std::uint64_t height, std::uint64_t global)
  {
    lws::db::output out{};
    out.link.height = lws::db::block_id(height);
    out.link.tx_hash = hash_of(9, height);
    out.spend_meta.id = lws::db::output_id{0, global};
    out.spend_meta.amount = 1000;
    out.pub = crypto::rand<crypto::public_key>();
    return out;
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-rescan-reorg-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    auto disk = lws::db::storage::open(dir.string().c_str(), 100);
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

    // Scan the account from 10 to 74, receiving outputs at heights 30 and 50.
    {
      const auto rc = disk.rescan(lws::db::block_id(10), epee::span<const lws::db::account_address>{&address, 1});
      if (!rc)
        throw std::runtime_error{"rescan failed: " + rc.error().message()};
      std::vector<lws::account> users;
      users.emplace_back(fetch(disk, address), std::vector<lws::db::output_id>{});
      users.back().add_out(make_output(30, 3000));
      users.back().add_out(make_output(50, 5000));
      const auto chain = range(1, 10, 74);
      const auto updated = disk.update(lws::db::block_id(10), epee::to_span(chain), epee::to_span(users));
      if (!updated)
        throw std::runtime_error{"update failed: " + updated.error().message()};
    }
    check(output_heights(disk, address) == std::vector<std::uint64_t>{30, 50}, "outputs recorded at 30 and 50");

    // An admin rescans the account from height 20. Its stored outputs stay.
    {
      const auto rc = disk.rescan(lws::db::block_id(20), epee::span<const lws::db::account_address>{&address, 1});
      if (!rc)
        throw std::runtime_error{"rescan failed: " + rc.error().message()};
    }
    check(std::uint64_t(fetch(disk, address).scan_height) == 20, "rescan lowered the scan height to 20");

    // Before it catches up, the chain reorganises from height 40.
    {
      std::vector<crypto::hash> branch2 = range(1, 30, 39);
      const auto tail = range(2, 40, 100);
      branch2.insert(branch2.end(), tail.begin(), tail.end());
      if (const auto rc = disk.sync_chain(lws::db::block_id(30), epee::to_span(branch2)); !rc)
        throw std::runtime_error{"sync_chain (reorg) failed: " + rc.error().message()};
    }

    const auto after = output_heights(disk, address);
    check(after == std::vector<std::uint64_t>{30}, "the output from the orphaned block at 50 was removed");
    check(std::uint64_t(fetch(disk, address).scan_height) == 20, "the account's scan height was left at 20");
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
