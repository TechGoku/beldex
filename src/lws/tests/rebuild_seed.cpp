// Checks the seeding sequence beldex-lws-rebuild uses to populate a shadow
// database from a live one.
//
// The shadow must end up with EXACTLY the live account set - every address, in
// the right status, at the requested rebuild height - and with no outputs at
// all, because a rebuild that carried outputs over would not be a rescan. The
// specific failure this guards against is seeding only the active accounts:
// that looks like a clean rebuild right up until somebody reactivates an
// account and finds it missing.
//
// It exercises the same calls rebuild_main.cpp makes, in the same order:
// add_account, then rescan() to place the account at the rebuild height, then
// change_status() to mirror a non-active status. The order matters -
// change_status moves an account between status keys, so doing it first would
// make the rescan miss it.
//
// Built as `lws-rebuild-seed-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <algorithm>
#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

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

  struct seed
  {
    lws::db::account_address address;
    crypto::secret_key key;
    lws::db::account_status status;
    std::uint64_t scan_height;
  };

  struct address_less
  {
    bool operator()(const lws::db::account_address& l, const lws::db::account_address& r) const noexcept
    {
      const int spend = std::memcmp(
        std::addressof(l.spend_public), std::addressof(r.spend_public), sizeof(l.spend_public));
      if (spend != 0)
        return spend < 0;
      return std::memcmp(
        std::addressof(l.view_public), std::addressof(r.view_public), sizeof(l.view_public)) < 0;
    }
  };

  void build_chain(lws::db::storage& disk, std::vector<crypto::hash>& chain, std::uint64_t tip)
  {
    chain.clear();
    chain.reserve(tip + 1);
    for (std::uint64_t i = 0; i <= tip; ++i)
      chain.push_back(hash_of(0xC0FFEE00u + i));

    if (const auto rc = disk.sync_chain(lws::db::block_id(0), {chain.data(), 2}); !rc)
      throw std::runtime_error{"sync_chain (seed) failed: " + rc.error().message()};
    if (const auto rc = disk.sync_chain(lws::db::block_id(1), {chain.data() + 1, chain.size() - 1}); !rc)
      throw std::runtime_error{"sync_chain (extend) failed: " + rc.error().message()};
  }

  //! Read every account, in every status, exactly as the rebuild does.
  std::vector<seed> read_all(lws::db::storage& disk)
  {
    std::vector<seed> out;
    auto reader = MONERO_UNWRAP(disk.start_read());

    const lws::db::account_status all[] = {
      lws::db::account_status::active,
      lws::db::account_status::inactive,
      lws::db::account_status::hidden
    };
    for (const lws::db::account_status status : all)
    {
      auto users = MONERO_UNWRAP(reader.get_accounts(status));
      for (auto user = users.make_iterator(); !user.is_end(); ++user)
      {
        const lws::db::account acct = *user;
        seed entry{};
        entry.address = acct.address;
        std::memcpy(std::addressof(entry.key), std::addressof(acct.key), sizeof(entry.key));
        entry.status = status;
        entry.scan_height = std::uint64_t(acct.scan_height);
        out.push_back(entry);
      }
    }
    reader.finish_read();

    std::sort(out.begin(), out.end(),
              [](const seed& l, const seed& r) { return address_less{}(l.address, r.address); });
    return out;
  }
}

int main()
{
  const boost::filesystem::path root =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-rebuild-%%%%%%%%");
  const boost::filesystem::path live_dir = root / "live";
  const boost::filesystem::path shadow_dir = root / "shadow";
  boost::filesystem::create_directories(live_dir);
  boost::filesystem::create_directories(shadow_dir);

  try
  {
    constexpr const std::uint64_t tip = 300;
    constexpr const std::uint64_t rebuild_height = 25;

    std::vector<seed> expected;
    {
      auto live = lws::db::storage::open(live_dir.string().c_str(), 100);
      std::vector<crypto::hash> chain;
      build_chain(live, chain, tip);

      // Three of each status, so a seed that only walks `active` is caught.
      const lws::db::account_status statuses[] = {
        lws::db::account_status::active,
        lws::db::account_status::inactive,
        lws::db::account_status::hidden
      };

      for (const lws::db::account_status status : statuses)
      {
        for (unsigned i = 0; i < 3; ++i)
        {
          crypto::secret_key key{};
          crypto::public_key view_public{};
          crypto::generate_keys(view_public, key);

          lws::db::account_address address{};
          address.view_public = view_public;
          address.spend_public = crypto::rand<crypto::public_key>();

          if (const auto rc = live.add_account(address, key); !rc)
            throw std::runtime_error{"add_account failed: " + rc.error().message()};

          if (status != lws::db::account_status::active)
          {
            const epee::span<const lws::db::account_address> one{std::addressof(address), 1};
            if (const auto rc = live.change_status(status, one); !rc)
              throw std::runtime_error{"change_status failed: " + rc.error().message()};
          }

          seed entry{};
          entry.address = address;
          entry.key = key;
          entry.status = status;
          expected.push_back(entry);
        }
      }
    }

    // ---- seed the shadow the way beldex-lws-rebuild does -----------------
    {
      auto shadow = lws::db::storage::open(shadow_dir.string().c_str(), 100);
      std::vector<crypto::hash> chain;
      build_chain(shadow, chain, tip); // the rebuild syncs its own chain first

      std::vector<lws::db::account_address> added;
      std::map<lws::db::account_status, std::vector<lws::db::account_address>> by_status;

      for (const seed& entry : expected)
      {
        if (const auto rc = shadow.add_account(entry.address, entry.key); !rc)
          throw std::runtime_error{"shadow add_account failed: " + rc.error().message()};
        added.push_back(entry.address);
        if (entry.status != lws::db::account_status::active)
          by_status[entry.status].push_back(entry.address);
      }

      if (const auto rc = shadow.rescan(lws::db::block_id(rebuild_height), epee::to_span(added)); !rc)
        throw std::runtime_error{"shadow rescan failed: " + rc.error().message()};

      for (const auto& group : by_status)
      {
        if (const auto rc = shadow.change_status(group.first, epee::to_span(group.second)); !rc)
          throw std::runtime_error{"shadow change_status failed: " + rc.error().message()};
      }
    }

    // ---- compare ---------------------------------------------------------
    auto live = lws::db::storage::open_readonly(live_dir.string().c_str());
    auto shadow = lws::db::storage::open_readonly(shadow_dir.string().c_str());

    const std::vector<seed> live_set = read_all(live);
    const std::vector<seed> shadow_set = read_all(shadow);

    check(live_set.size() == expected.size(),
          "live database holds all 9 accounts across the three statuses");
    check(shadow_set.size() == live_set.size(),
          "shadow holds exactly as many accounts as the live database");

    bool addresses_match = shadow_set.size() == live_set.size();
    bool statuses_match = addresses_match;
    bool heights_match = addresses_match;
    for (std::size_t i = 0; addresses_match && i < live_set.size(); ++i)
    {
      if (address_less{}(live_set[i].address, shadow_set[i].address) ||
          address_less{}(shadow_set[i].address, live_set[i].address))
      {
        addresses_match = false;
        break;
      }
      statuses_match = statuses_match && live_set[i].status == shadow_set[i].status;
      heights_match = heights_match && shadow_set[i].scan_height == rebuild_height;
    }

    check(addresses_match, "every live address is present in the shadow");
    check(statuses_match, "active/inactive/hidden statuses were mirrored");
    check(heights_match, "every seeded account sits at the rebuild height (25)");

    // The point of a rebuild: the shadow starts with nothing to carry forward.
    std::size_t shadow_outputs = 0;
    {
      auto reader = MONERO_UNWRAP(shadow.start_read());
      auto users = MONERO_UNWRAP(reader.get_accounts(lws::db::account_status::active));
      for (auto user = users.make_iterator(); !user.is_end(); ++user)
      {
        auto outs = MONERO_UNWRAP(reader.get_outputs(user.get_value<MONERO_FIELD(lws::db::account, id)>()));
        shadow_outputs += outs.count();
      }
      reader.finish_read();
    }
    check(shadow_outputs == 0, "shadow starts with no outputs, so every row is rebuilt");

    /* Pending import requests are user-visible state: a wallet told "Accepted,
       waiting for approval" must still be waiting on something after a switch.
       Mirrored the way the rebuild's sync loop mirrors them. */
    {
      auto live_rw = lws::db::storage::open(live_dir.string().c_str(), 100);
      const lws::db::account_address& subject = expected.front().address;
      if (const auto rc = live_rw.import_request(subject, lws::db::block_id(5)); !rc)
        throw std::runtime_error{"import_request failed: " + rc.error().message()};

      auto shadow_rw = lws::db::storage::open(shadow_dir.string().c_str(), 100);
      if (const auto rc = shadow_rw.import_request(subject, lws::db::block_id(5)); !rc)
        throw std::runtime_error{"shadow import_request failed: " + rc.error().message()};

      /* One read txn per environment at a time: LMDB gives a thread a single
         reader slot per environment, so holding two at once here is
         MDB_BAD_RSLOT. Each reader is finished before the next is opened. */
      bool live_has = false, shadow_has = false, same_account = false;
      lws::db::account_address live_subject{};
      {
        auto reader = MONERO_UNWRAP(live_rw.start_read());
        const auto found = reader.get_request(lws::db::request::import_scan, subject);
        live_has = bool(found);
        if (found)
          live_subject = found->address;
        reader.finish_read();
      }
      {
        auto reader = MONERO_UNWRAP(shadow_rw.start_read());
        const auto found = reader.get_request(lws::db::request::import_scan, subject);
        shadow_has = bool(found);
        same_account = live_has && found &&
          std::memcmp(std::addressof(live_subject), std::addressof(found->address),
                      sizeof(live_subject)) == 0;
        reader.finish_read();
      }

      check(live_has, "live database holds the pending import request");
      check(shadow_has, "mirrored import request is present in the shadow");
      check(same_account, "mirrored request is for the same account");
    }
  }
  catch (const std::exception& e)
  {
    std::cerr << "unexpected exception: " << e.what() << std::endl;
    ++failures;
  }

  boost::system::error_code ec{};
  boost::filesystem::remove_all(root, ec);

  std::cout << (failures ? "FAILED" : "PASSED") << std::endl;
  return failures ? 1 : 0;
}
