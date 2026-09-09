// Checks that storage::open_readonly() genuinely does not modify the database.
//
// storage::open() opens a WRITE transaction and may run the schema migration
// inside it, so every tool that opened a database - `beldex-lws-admin
// list_accounts` included - became a writer: it contended for the single LMDB
// writer lock with the running daemon and could rewrite rows in a database it
// did not own. open_readonly() exists so inspection is safe against a live
// server, and this is the check that keeps it that way.
//
// Two properties are asserted:
//   * data.mdb is byte-for-byte identical after a read-only open that reads the
//     chain tip and the whole account table out of it;
//   * a write attempted through such a handle fails instead of succeeding,
//     because LMDB refuses a write transaction on an MDB_RDONLY environment.
//
// Built as `lws-readonly-open-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
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

  std::vector<char> read_file(const boost::filesystem::path& path)
  {
    std::ifstream file{path.string(), std::ios::binary};
    return std::vector<char>{
      std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
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
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-rdonly-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    constexpr const std::uint64_t tip = 50;
    std::vector<crypto::hash> chain;
    chain.reserve(tip + 1);
    for (std::uint64_t i = 0; i <= tip; ++i)
      chain.push_back(hash_of(0x5EED0000u + i));

    std::vector<lws::db::account_address> written;
    {
      auto disk = lws::db::storage::open(dir.string().c_str(), 100);
      if (const auto rc = disk.sync_chain(lws::db::block_id(0), {chain.data(), 2}); !rc)
        throw std::runtime_error{"sync_chain (seed) failed: " + rc.error().message()};
      if (const auto rc = disk.sync_chain(lws::db::block_id(1), {chain.data() + 1, chain.size() - 1}); !rc)
        throw std::runtime_error{"sync_chain (extend) failed: " + rc.error().message()};

      for (unsigned i = 0; i < 5; ++i)
      {
        crypto::secret_key key{};
        const lws::db::account_address address = make_address(key);
        if (const auto rc = disk.add_account(address, key); !rc)
          throw std::runtime_error{"add_account failed: " + rc.error().message()};
        written.push_back(address);
      }
    } // closed, so nothing of ours is still attached

    const boost::filesystem::path data_file = dir / "data.mdb";
    const std::vector<char> before = read_file(data_file);
    check(!before.empty(), "populated database written to disk");

    std::size_t seen = 0;
    std::uint64_t height = 0;
    {
      auto disk = lws::db::storage::open_readonly(dir.string().c_str());
      check(disk.is_read_only(), "handle reports itself read-only");

      auto reader = MONERO_UNWRAP(disk.start_read());
      const auto last = reader.get_last_block();
      height = last ? std::uint64_t(last->id) : 0;

      auto users = MONERO_UNWRAP(reader.get_accounts(lws::db::account_status::active));
      for (auto user = users.make_iterator(); !user.is_end(); ++user)
        ++seen;
      reader.finish_read();

      /* A write must fail rather than quietly succeed. LMDB returns EACCES for
         a write transaction on an MDB_RDONLY environment, so this is enforced
         by the environment itself and not merely by convention. */
      crypto::secret_key key{};
      const lws::db::account_address address = make_address(key);
      const auto rc = disk.add_account(address, key);
      check(!rc, "add_account through a read-only handle fails");
    }

    check(height == tip, "read-only open read the chain tip back (50)");
    check(seen == written.size(), "read-only open read every account back (5)");

    const std::vector<char> after = read_file(data_file);
    check(before.size() == after.size() && before == after,
          "data.mdb is byte-for-byte unchanged after the read-only open");
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
