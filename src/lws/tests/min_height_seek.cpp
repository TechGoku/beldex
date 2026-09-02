// Integration check for storage_reader::get_outputs/get_spends(id, min_height).
//
// Builds a throwaway LMDB, writes outputs and spends at known heights through
// the normal storage::update() path, then asserts that a seeked stream returns
// exactly the tail of the full stream - i.e. that the MDB_GET_BOTH_RANGE probe
// lands on the first record at height >= min_height under the real
// output_compare/spend_compare dup comparators.
//
// Covers the boundary cases the REST handlers rely on: min_height is inclusive,
// min_height == 0 does not seek at all, a cursor past the chain tip yields an
// empty stream rather than an error, and an account with no records does not
// fault on the seek path. Also simulates the handlers' whole-block pagination
// loop (max_count + next_min_height) over the seek primitive and asserts that
// walking every page reconstructs the full stream with no gap or overlap.
//
// Built as `lws-min-height-seek-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <cstdint>
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

  lws::db::output make_output(std::uint64_t height, std::uint64_t index)
  {
    lws::db::output out{};
    out.link.height = lws::db::block_id(height);
    out.link.tx_hash = hash_of(height * 1000 + index);
    out.spend_meta.id = lws::db::output_id{height, index};
    out.spend_meta.amount = 1000 + index;
    out.spend_meta.mixin_count = 9;
    out.spend_meta.index = std::uint32_t(index);
    out.pub = crypto::rand<crypto::public_key>();
    out.timestamp = height;
    return out;
  }

  lws::db::spend make_spend(std::uint64_t height, const lws::db::output& source)
  {
    lws::db::spend sp{};
    sp.link.height = lws::db::block_id(height);
    sp.link.tx_hash = hash_of(height * 7919 + 1);
    sp.image = crypto::rand<crypto::key_image>();
    sp.source = source.spend_meta.id;
    sp.timestamp = height;
    sp.mixin_count = 9;
    return sp;
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("lws-seek-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  try
  {
    auto disk = lws::db::storage::open(dir.string().c_str(), 100);

    // chain[i] is the hash at height i; chain[0] is the genesis anchor. A fresh
    // DB has no blocks, so sync_chain appends heights 1.. from chain[1].
    constexpr const std::uint64_t blocks = 400;
    std::vector<crypto::hash> chain;
    chain.reserve(blocks + 1);
    for (std::uint64_t i = 0; i <= blocks; ++i)
      chain.push_back(hash_of(0xABCDEF00u + i));

    // Seed height 1 first so a new account starts there rather than at the tip.
    if (const auto rc = disk.sync_chain(lws::db::block_id(0), {chain.data(), 2}); !rc)
      throw std::runtime_error{"sync_chain (seed) failed: " + rc.error().message()};

    crypto::secret_key view_key{};
    crypto::public_key view_public{};
    crypto::generate_keys(view_public, view_key);

    lws::db::account_address address{};
    address.view_public = view_public;
    address.spend_public = crypto::rand<crypto::public_key>();

    if (const auto rc = disk.add_account(address, view_key); !rc)
      throw std::runtime_error{"add_account failed: " + rc.error().message()};

    // Extend to `blocks`, anchored on height 1 (which is now stored).
    if (const auto rc = disk.sync_chain(lws::db::block_id(1), {chain.data() + 1, chain.size() - 1}); !rc)
      throw std::runtime_error{"sync_chain (extend) failed: " + rc.error().message()};

    // Records at heights 10, 20, ... 400 - two outputs and one spend each.
    std::vector<lws::db::output> written_outs;
    std::vector<lws::db::spend> written_spends;
    {
      auto reader = disk.start_read();
      const auto stored = reader->get_account(address);
      if (!stored)
        throw std::runtime_error{"get_account failed"};
      reader->finish_read();

      lws::account user{stored->second, {}};
      for (std::uint64_t height = 10; height <= blocks; height += 10)
      {
        for (std::uint64_t index = 0; index < 2; ++index)
        {
          const auto out = make_output(height, index);
          written_outs.push_back(out);
          user.add_out(out);
        }
        const auto sp = make_spend(height, written_outs.back());
        written_spends.push_back(sp);
        user.add_spend(sp);
      }

      std::vector<lws::account> users;
      users.push_back(std::move(user));
      const std::uint64_t from = std::uint64_t(users.front().scan_height());
      const auto updated = disk.update(
        users.front().scan_height(),
        {chain.data() + from, chain.size() - from},
        epee::to_span(users)
      );
      if (!updated)
        throw std::runtime_error{"update failed: " + updated.error().message()};
      if (*updated != 1)
        throw std::runtime_error{"update touched no account"};
    }

    auto reader = disk.start_read();
    const auto stored = reader->get_account(address);
    if (!stored)
      throw std::runtime_error{"get_account (2) failed"};
    const lws::db::account_id id = stored->second.id;

    const auto full_out_heights = [&] {
      std::vector<std::uint64_t> heights;
      auto stream = reader->get_outputs(id);
      for (const lws::db::output& o : stream->make_range())
        heights.push_back(std::uint64_t(o.link.height));
      return heights;
    }();
    const auto full_spend_heights = [&] {
      std::vector<std::uint64_t> heights;
      auto stream = reader->get_spends(id);
      for (const lws::db::spend& s : stream->make_range())
        heights.push_back(std::uint64_t(s.link.height));
      return heights;
    }();

    std::cout << "full walk: " << full_out_heights.size() << " outputs, "
              << full_spend_heights.size() << " spends\n";
    check(full_out_heights.size() == written_outs.size(), "all outputs stored");
    check(full_spend_heights.size() == written_spends.size(), "all spends stored");

    const auto tail = [](const std::vector<std::uint64_t>& all, std::uint64_t min_height) {
      std::vector<std::uint64_t> out;
      for (const std::uint64_t h : all)
        if (h >= min_height)
          out.push_back(h);
      return out;
    };

    // min_height on a block boundary (inclusive), off a boundary, at the very
    // first record, past the tip, and 0 (which must not seek at all).
    for (const std::uint64_t min_height : {std::uint64_t(0), std::uint64_t(1), std::uint64_t(10),
                                           std::uint64_t(11), std::uint64_t(200), std::uint64_t(400),
                                           std::uint64_t(401), std::uint64_t(100000)})
    {
      std::vector<std::uint64_t> seeked_outs;
      {
        auto stream = min_height ?
          reader->get_outputs(id, lws::db::block_id(min_height)) : reader->get_outputs(id);
        if (!stream)
          throw std::runtime_error{"get_outputs seek failed"};
        for (const lws::db::output& o : stream->make_range())
          seeked_outs.push_back(std::uint64_t(o.link.height));
      }

      std::vector<std::uint64_t> seeked_spends;
      {
        auto stream = min_height ?
          reader->get_spends(id, lws::db::block_id(min_height)) : reader->get_spends(id);
        if (!stream)
          throw std::runtime_error{"get_spends seek failed"};
        for (const lws::db::spend& s : stream->make_range())
          seeked_spends.push_back(std::uint64_t(s.link.height));
      }

      check(seeked_outs == tail(full_out_heights, min_height),
            "outputs at min_height=" + std::to_string(min_height) + " ("
              + std::to_string(seeked_outs.size()) + " of " + std::to_string(full_out_heights.size()) + ")");
      check(seeked_spends == tail(full_spend_heights, min_height),
            "spends at min_height=" + std::to_string(min_height) + " ("
              + std::to_string(seeked_spends.size()) + " of " + std::to_string(full_spend_heights.size()) + ")");
    }

    // Pagination: simulate the REST handler's whole-block page loop over the
    // seek primitive - take up to max_count records, but stop only at a block
    // boundary (never split a block), and resume at the returned next_min_height
    // - and assert it reconstructs the full stream in order with a strictly
    // advancing cursor (no gap, no overlap). Outputs have two records per block,
    // so a page_size that lands mid-block exercises the whole-block straddle.
    const auto page_once = [&](std::uint64_t min_height, std::uint64_t max_count,
                               std::uint64_t& next_min_height) {
      std::vector<std::uint64_t> page;
      auto stream = min_height ?
        reader->get_outputs(id, lws::db::block_id(min_height)) : reader->get_outputs(id);
      if (!stream)
        throw std::runtime_error{"page get_outputs seek failed"};
      std::uint64_t returned = 0, last_h = 0;
      next_min_height = 0;
      for (const lws::db::output& o : stream->make_range())
      {
        const std::uint64_t h = std::uint64_t(o.link.height);
        if (max_count != 0 && returned >= max_count && h != last_h)
        {
          next_min_height = h; // resume here next page (inclusive seek)
          break;
        }
        page.push_back(h);
        ++returned;
        last_h = h;
      }
      return page;
    };

    for (const std::uint64_t page_size : {std::uint64_t(1), std::uint64_t(3),
                                          std::uint64_t(7), std::uint64_t(1000)})
    {
      std::vector<std::uint64_t> walked;
      std::uint64_t mh = 0, next = 0, pages = 0, iterations = 0;
      bool cursor_ok = true, guard_ok = true;
      do {
        const auto page = page_once(mh, page_size, next);
        walked.insert(walked.end(), page.begin(), page.end());
        ++pages;
        if (next != 0) // cursor must land strictly past the last returned block
          cursor_ok = cursor_ok && (!page.empty() && next > page.back());
        if (++iterations > blocks + 5) { guard_ok = false; break; } // runaway guard
        mh = next;
      } while (next != 0);

      check(walked == full_out_heights,
            "paged walk reconstructs full stream (page_size=" + std::to_string(page_size)
              + ", " + std::to_string(pages) + " pages)");
      check(cursor_ok, "cursor advances whole-block, no overlap (page_size=" + std::to_string(page_size) + ")");
      check(guard_ok, "pagination terminates (page_size=" + std::to_string(page_size) + ")");
    }

    // An account with no records at all must not blow up on the seek path.
    {
      crypto::secret_key empty_key{};
      crypto::public_key empty_public{};
      crypto::generate_keys(empty_public, empty_key);
      lws::db::account_address empty_address{};
      empty_address.view_public = empty_public;
      empty_address.spend_public = crypto::rand<crypto::public_key>();
      reader->finish_read();
      if (!disk.add_account(empty_address, empty_key))
        throw std::runtime_error{"add_account (empty) failed"};

      auto reader2 = disk.start_read();
      const auto empty_stored = reader2->get_account(empty_address);
      auto stream = reader2->get_outputs(empty_stored->second.id, lws::db::block_id(1));
      check(bool(stream) && stream->make_iterator().is_end(), "empty account seeks to an empty stream");
    }
  }
  catch (const std::exception& e)
  {
    std::cerr << "EXCEPTION: " << e.what() << '\n';
    ++failures;
  }

  boost::system::error_code ignored;
  boost::filesystem::remove_all(dir, ignored);

  std::cout << (failures ? "FAILED" : "PASSED") << " (" << failures << " failure(s))\n";
  return failures ? 1 : 0;
}
