#include "scanner.h"

#include <algorithm>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/range/combine.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <cpr/cpr.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <type_traits>
#include <map>
#include <set>
#include <unordered_map>
#include <utility>
#include <fstream>

#include "common/error.h"
#include "common/hex.h"                               // monero/src
#include "crypto/crypto.h"                            // monero/src
#include "crypto/wallet/crypto.h"                     // monero/src
#include "cryptonote_basic/cryptonote_basic.h"        // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "epee/span.h"                                // monero/src
#include "epee/misc_log_ex.h"                         // monero/src

#include "config.h"
#include "error.h"
#include "scanner.h"
#include "db/account.h"
#include "util/transactions.h"
#include "rpc/daemon_zmq.h"
#include "rpc/json.h"
#include "wire/json/read.h"
#include "lmdb/util.h"
#include "wallet/node_rpc_proxy.h"
#include "wallet/wallet2.h"
#include <oxenmq/oxenmq.h>

// #include "common/types.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace lws
{
  std::atomic<bool> scanner::running{true};

  namespace
  {
    constexpr const std::chrono::seconds account_poll_interval{10};
    //! How often to sweep orphaned LMDB readers and log map utilisation.
    constexpr const std::chrono::minutes db_maintenance_interval{5};

    /* Coalescing window for account-set changes (S1).

       `check_loop` returns - tearing down and restarting the entire thread
       group - the moment the active account set differs from the set it was
       started with. One signup did that. With continuous signups the scanner
       spent its time restarting rather than scanning: each restart joins every
       thread (waiting out an in-flight block batch, seconds), rebuilds every
       account's output projection, re-partitions and relaunches. At any real
       signup rate the restarts arrive faster than a pass completes and the
       scanner makes no forward progress at all.

       Detected changes are now absorbed for this window before restarting, so
       the restart rate is bounded to one per window no matter how many accounts
       are created - and every change that lands inside the window is picked up
       by the same restart, for free. The scan threads keep running and keep
       committing blocks throughout, so the delay costs nothing: `add_account`
       starts a new account at the chain tip, so it has no backlog to miss, and
       a deactivated account merely gets scanned slightly longer than needed.

       The bound applies to rescans too. An admin `rescan` is picked up within
       the window rather than instantly, which is well inside the tolerance for
       an operation that then has to re-walk the chain anyway. */
    constexpr const std::chrono::seconds account_change_coalesce{30};

    /* Shared, very short lived dedup cache for get_blocks_fast.

       Every scan thread ran its own fetch loop, so with `--scan-threads N` the
       daemon served N copies of the same block stream - N times the RPC load,
       bandwidth and JSON parsing - because accounts are grouped by scan height
       and most sit at the tip, i.e. threads mostly ask for the SAME heights.

       Threads asking for the same `start_height` within the TTL share one
       response. The window is deliberately tiny: blocks at a given height are
       append-only in the normal case, and a reorg arriving inside it is still
       caught downstream - `scan_loop` rejects a response whose `start_height`
       does not match its request, and `sync_chain` detects hash divergence and
       rolls back. */
    constexpr const std::chrono::seconds block_fetch_ttl{2};
    constexpr const std::size_t block_fetch_cache_max = 4;

    struct block_fetch_cache
    {
      std::mutex lock;
      std::map<std::uint64_t, std::pair<std::chrono::steady_clock::time_point,
                                        std::shared_ptr<const std::string>>> entries;
    };
    block_fetch_cache& shared_block_cache()
    {
      static block_fetch_cache instance;
      return instance;
    }

    //! \return Cached response for `height`, or nullptr when absent/stale.
    std::shared_ptr<const std::string> lookup_block_fetch(std::uint64_t height)
    {
      auto& cache = shared_block_cache();
      const std::lock_guard<std::mutex> guard{cache.lock};
      const auto found = cache.entries.find(height);
      if (found == cache.entries.end())
        return nullptr;
      if (block_fetch_ttl < std::chrono::steady_clock::now() - found->second.first)
      {
        cache.entries.erase(found);
        return nullptr;
      }
      return found->second.second;
    }

    void store_block_fetch(std::uint64_t height, std::shared_ptr<const std::string> body)
    {
      auto& cache = shared_block_cache();
      const std::lock_guard<std::mutex> guard{cache.lock};
      const auto now = std::chrono::steady_clock::now();
      for (auto i = cache.entries.begin(); i != cache.entries.end(); )
        i = (block_fetch_ttl < now - i->second.first) ? cache.entries.erase(i) : std::next(i);
      while (block_fetch_cache_max <= cache.entries.size())
        cache.entries.erase(cache.entries.begin());
      cache.entries[height] = {now, std::move(body)};
    }
    constexpr const std::chrono::minutes block_rpc_timeout{2};
    constexpr const std::chrono::seconds send_timeout{30};
    constexpr const std::chrono::seconds sync_rpc_timeout{30};

    struct thread_sync
    {
      boost::mutex sync;
      boost::condition_variable user_poll;
      std::atomic<bool> update;
    };
    struct thread_data
    {
      explicit thread_data(db::storage disk, std::vector<lws::account> users)
          : disk(std::move(disk)), users(std::move(users))
      {}

      db::storage disk;
      std::vector<lws::account> users;
    };

    static bool is_ipc_uri(const std::string& uri)
    {
      return uri.rfind("ipc://", 0) == 0;
    }

    static bool is_http_uri(const std::string& uri)
    {
      return uri.rfind("http://", 0) == 0 ||
             uri.rfind("https://", 0) == 0;
    }

    // -------------------------------------------------------------------------
    // IPC helper — logs all parts, throws with daemon's error message on failure
    // -------------------------------------------------------------------------
    /* Serialises only the ENQUEUE of an IPC request, not the wait for its reply.

       Every scan thread shares one OxenMQ instance and one connection, and the
       lock used to be taken at the call site around the whole request - i.e.
       held for the entire daemon round-trip, up to 60s. That made IPC scanning
       strictly single-threaded no matter what `--scan-threads` said: N threads
       took turns waiting on the daemon instead of overlapping their waits.

       Narrowed rather than removed. OxenMQ dispatches through its own proxy
       thread and its `request()` is expected to be callable concurrently, but
       that is not something this change set can exercise - the IPC path needs a
       beldexd built with OMQ enabled, which the local test rig does not have.
       Keeping the enqueue serialised is correct either way and costs nothing
       measurable (it is a queue push, not a network wait), while moving the
       reply wait outside restores the parallelism. The promise/future are
       function-locals and the wait still happens inside this function, so their
       lifetimes are unchanged.

       To close this out fully: run `--scan-threads 4` against an OMQ-enabled
       beldexd and confirm concurrent `rpc.get_blocks_fast` calls in flight. */
    static std::mutex ipc_enqueue_mutex;

    static std::string ipc_request(
        oxenmq::OxenMQ& lmq,
        oxenmq::ConnectionID& conn,
        const std::string& method,
        const std::string& params_json,
        std::chrono::seconds timeout = std::chrono::seconds{60})
    {
      std::promise<std::string> prom;
      auto fut = prom.get_future();

      {
        const std::lock_guard<std::mutex> enqueue{ipc_enqueue_mutex};
        lmq.request(
        conn,
        method,
        [&prom, &method](bool success, std::vector<std::string> data)
        {
          try {
            if (!success)
            {
              std::string err = data.empty() ? "(no data)" : data[0];
              throw std::runtime_error{
                "IPC daemon rejected '" + method + "': " + err};
            }
            if (data.size() < 2)
              throw std::runtime_error{
                "IPC response missing body for '" + method + "'"};
            prom.set_value(data[1]);
          } catch (...) {
            prom.set_exception(std::current_exception());
          }
        },
        params_json,
        oxenmq::send_option::request_timeout{timeout}
        );
      }

      if (fut.wait_for(timeout + std::chrono::seconds{30}) != std::future_status::ready)
        throw std::runtime_error{"IPC timeout: " + method};

      return fut.get();
    }

    void checked_wait(const std::chrono::nanoseconds wait)
    {
      static constexpr const std::chrono::milliseconds interval{500};

      const auto start = std::chrono::steady_clock::now();
      while (scanner::is_running())
      {
        const auto current = std::chrono::steady_clock::now() - start;
        if (wait <= current)
          break;
        const auto sleep_time = std::min(wait - current, std::chrono::nanoseconds{interval});
        std::this_thread::sleep_for(std::chrono::nanoseconds{sleep_time.count()});
      }
    }

    struct by_height
    {
      bool operator()(account const& left, account const& right) const noexcept
      {
        return left.scan_height() < right.scan_height();
      }
    };

    void scan_transaction(
        epee::span<lws::account> users,
        const db::block_id height,
        const std::uint64_t timestamp,
      crypto::hash const& tx_hash,
      cryptonote::transaction const& tx,
      std::vector<std::uint64_t> const& out_ids)
    {
      boost::optional<crypto::key_image> locked_key_image;  
      if (cryptonote::txversion::v4_tx_types < tx.version)
        throw std::runtime_error{"Unsupported tx version"};

      cryptonote::tx_extra_pub_key key;
      boost::optional<crypto::hash> prefix_hash;
      boost::optional<cryptonote::tx_extra_nonce> extra_nonce;
      std::pair<std::uint8_t, db::output::payment_id_> payment_id;

      {
        std::vector<cryptonote::tx_extra_field> extra;
        cryptonote::parse_tx_extra(tx.extra, extra);

        /* Use the FIRST TX_EXTRA_TAG_PUBKEY.

           A Beldex miner_tx carries several of them - a 99-byte extra is
           3 x (1 tag + 32 key) - and the previous loop kept going while
           lookups succeeded, so `key` ended up holding the LAST pubkey rather
           than the first. Every derivation was then computed against the wrong
           key, no output ever matched, and the account was silently reported
           with a zero balance. Verified on a private testnet: 1802 mined
           coinbase outputs, 0 matched before this change and 1802 after,
           against a wallet2 ground truth of 1802 BDX.

           `find_tx_extra_field_by_type` leaves `key` untouched when it returns
           false, so an absent pubkey is detected explicitly rather than
           deriving against a stale or zero key. */
        if (!cryptonote::find_tx_extra_field_by_type(extra, key, 0))
          return; // no tx public key - nothing in this tx can belong to a user

        extra_nonce.emplace();
        if (cryptonote::find_tx_extra_field_by_type(extra, *extra_nonce))
        {
          if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.long_))
            payment_id.first = sizeof(crypto::hash);
        }
        else
          extra_nonce = boost::none;

        // Reuse the already-parsed `extra` here instead of calling
        // get_field_from_tx_extra(tx.extra, ...), which would re-run
        // parse_tx_extra over tx.extra a second time. Same result.
        cryptonote::tx_extra_tx_key_image_proofs key_image_proofs;
        if (cryptonote::find_tx_extra_field_by_type(extra, key_image_proofs) &&
            !key_image_proofs.proofs.empty())
        {
          // Assign the key_image from the first proof to locked_key_image
          locked_key_image = key_image_proofs.proofs.front().key_image;
        }
      } // destruct `extra` vector

      for (account &user : users)
      {
        // std::cout << "entered in users " << std::endl;
        if (height <= user.scan_height())
          continue; // to next user

        crypto::key_derivation derived;
        if (!crypto::wallet::generate_key_derivation(key.pub_key, user.view_key(), derived))
          continue; // to next user

        /* Per-user copy. `payment_id` above holds the LONG payment id, which is
           unencrypted and therefore identical for every user - that part is
           shared correctly. The SHORT payment id, however, is ENCRYPTED and must
           be decrypted with THIS user's key derivation.

           Previously the shared struct was decrypted in place by whichever user
           matched first; `payment_id.first` was then non-zero, so every later
           user skipped decryption and was stored the FIRST user's decrypted
           payment id. Two tracked accounts receiving in the same transaction
           leaked one's payment id into the other's history. */
        std::pair<std::uint8_t, db::output::payment_id_> user_payment_id = payment_id;

        db::extra ext{};
        std::uint32_t mixin = 0;
        for (auto const& in : tx.vin)
        {
          // std::cout << "entered in vin " << std::endl;
          cryptonote::txin_to_key const* const in_data =
              std::get_if<cryptonote::txin_to_key>(std::addressof(in));
          if (in_data)
          {
            mixin = boost::numeric_cast<std::uint32_t>(
              std::max(std::size_t(1), in_data->key_offsets.size()) - 1
            );

            std::uint64_t goffset = 0;
            for (std::uint64_t offset : in_data->key_offsets)
            {
              goffset += offset;
              if (user.has_spendable(db::output_id{in_data->amount, goffset}))
              {
                user.add_spend(
                    db::spend{
                        db::transaction_link{height, tx_hash},
                        in_data->k_image,
                        db::output_id{in_data->amount, goffset},
                        timestamp,
                        tx.unlock_time,
                        mixin,
                        {0, 0, 0}, // reserved
                        payment_id.first,
                    payment_id.second.long_
                  }
                );
              }
            }
          }
          else if (std::get_if<cryptonote::txin_gen>(std::addressof(in)))
            ext = db::extra(ext | db::coinbase_output);
        }

        std::size_t index = -1;
        for (auto const& out : tx.vout)
        {
          // std::cout << "entered in vout " << std::endl;
          ++index;

          cryptonote::txout_to_key const* const out_data =
              std::get_if<cryptonote::txout_to_key>(std::addressof(out.target));
          if (!out_data)
            continue; // to next output

          crypto::public_key derived_pub;
          const bool received =
              crypto::wallet::derive_subaddress_public_key(out_data->key, derived, index, derived_pub) &&
              derived_pub == user.spend_public();

          if (!received)
            continue; // to next output

          if (!prefix_hash)
          {
            prefix_hash.emplace();
            cryptonote::get_transaction_prefix_hash(tx, *prefix_hash);
          }

          std::uint64_t amount = out.amount;
          
          rct::key mask = rct::identity();
          if (!amount && !(ext & db::coinbase_output) && cryptonote::txversion::v1 < tx.version)
          {
            
            const bool bulletproof2 = true;
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk.at(index).mask, tx.rct_signatures.ecdhInfo.at(index), derived, index, bulletproof2
            );
            if (!decrypted)
            {
              MWARNING(user.address() << " failed to decrypt amount for tx " << tx_hash << ", skipping output");
              continue; // to next output
            }
            amount = decrypted->first;
            // std::cout << "amount after decrypt : " << amount << std::endl;
            mask = decrypted->second;
            ext = db::extra(ext | db::ringct_output);
          }

          if (extra_nonce)
          {
            if (!user_payment_id.first && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce->nonce, user_payment_id.second.short_))
            {
              user_payment_id.first = sizeof(crypto::hash8);
              lws::decrypt_payment_id(user_payment_id.second.short_, derived);
            }
          }

          const bool added = user.add_out(
              db::output{
                  db::transaction_link{height, tx_hash},
                  db::output::spend_meta_{
                      db::output_id{0, out_ids.at(index)},
                      amount,
                      mixin,
                      boost::numeric_cast<std::uint32_t>(index),
                key.pub_key
              },
                  timestamp,
                  tx.unlock_time,
                  *prefix_hash,
                  locked_key_image ? *locked_key_image : crypto::key_image{},
                  out_data->key,
                  mask,
                  {0, 0, 0, 0, 0, 0, 0}, // reserved bytes
                  db::pack(ext, user_payment_id.first),
                  user_payment_id.second
            }
          );

          if (!added)
            MWARNING("Output not added, duplicate public key encountered");
        } // for all tx outs
      } // for all users
    }

    // -------------------------------------------------------------------------
    // scan_loop
    //
    // IPC adaptive batch sizing:
    //   This self-tunes to the largest batch the daemon can handle without
    //   timing out, giving throughput close to HTTP.
    // -------------------------------------------------------------------------
    static void scan_loop(thread_sync& self,
                          std::string daemon_rpc,
                          std::shared_ptr<thread_data> data) noexcept
    {
      try
      {
        // boost::thread doesn't support move-only types + attributes
        // rpc::client client{std::move(data->client)};
        db::storage disk{std::move(data->disk)};
        std::vector<lws::account> users{std::move(data->users)};

        assert(!users.empty());
        assert(std::is_sorted(users.begin(), users.end(), by_height{}));

        data.reset();

        struct stop_
        {
          thread_sync& self;
          ~stop_() noexcept
          {
            self.update = true;
            self.user_poll.notify_one();
          }
        } stop{self};

        uint64_t start_height =
            std::max<uint64_t>(1, static_cast<uint64_t>(users.begin()->scan_height()));

        const bool use_ipc = is_ipc_uri(daemon_rpc);

        // ---- IPC one-time setup ----
        static oxenmq::OxenMQ lmq;
        static oxenmq::ConnectionID conn;
        static std::once_flag ipc_init_flag;

        if (use_ipc)
        {
          std::call_once(ipc_init_flag, [&]() {
            lmq.MAX_MSG_SIZE = 200 * 1024 * 1024;
            lmq.start();
            conn = lmq.connect_remote(
              daemon_rpc,
              [](oxenmq::ConnectionID) {
                MINFO("IPC connected (scan_loop)");
              },
              [](oxenmq::ConnectionID, std::string_view err) {
                MERROR("IPC connection failed (scan_loop): " << err);
              }
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
          });
        }

        // Adaptive batch size for IPC — self-tunes based on daemon response
        int consecutive_successes = 0;

        // ---- Transport abstraction ----
        auto fetch_blocks_uncached = [&](uint64_t height) -> std::string
        {
          if (use_ipc)
          {
            // No "count" or "max_count" param — daemon ignores unknown params
            // and always returns its internal default (which appears to be ~64
            // blocks). We control pace via retry logic instead.
            nlohmann::json params = {{"start_height", height}};

            MINFO("IPC fetch_blocks: height=" << height);

            // Lock now lives inside ipc_request, around the enqueue only.
            std::string raw = ipc_request(lmq, conn,
                                          "rpc.get_blocks_fast",
                                          params.dump(),
                                          std::chrono::seconds{60});

            // Log how many blocks we actually got back
            try {
              auto j = nlohmann::json::parse(raw);
              if (j.contains("blocks"))
              {
                size_t got = j["blocks"].size();
                MINFO("IPC fetch_blocks: received " << got << " blocks");
              }
            } catch (...) {}

            nlohmann::json wrapped = {
              {"jsonrpc", "2.0"},
              {"id", 0},
              {"result", nlohmann::json::parse(raw)}
            };
            return wrapped.dump();
          }
          else // HTTP
          {
            nlohmann::json request = {
              {"jsonrpc", "2.0"},
              {"id",      "0"},
              {"method",  "get_blocks_fast"},
              {"params",  {{"start_height", height}}}
            };

            auto response = cpr::Post(
              cpr::Url{daemon_rpc},
              cpr::Body{request.dump()},
              cpr::Header{{"Content-Type", "application/json"}},
              cpr::Timeout{block_rpc_timeout}
            );

            if (response.text.empty())
              throw std::runtime_error{"Block retrieval timeout,HTTP daemon connection failed"};

            return response.text;
          }
        };

        // Share one fetch between threads asking for the same height (see
        // shared_block_cache above); a copy is returned because the caller
        // moves the buffer into the parser.
        auto fetch_blocks = [&](uint64_t height) -> std::string
        {
          if (auto hit = lookup_block_fetch(height))
            return *hit;
          auto body = std::make_shared<const std::string>(fetch_blocks_uncached(height));
          store_block_fetch(height, body);
          return *body;
        };

        // ---- Main scan loop ----
        std::vector<crypto::hash> blockchain{};

        while (!self.update && scanner::is_running())
        {
          blockchain.clear();

          std::string raw_response = fetch_blocks(start_height);

          // Single parse: the wire reader (daemon_zmq.cpp) now un-stringifies the
          // nested block / transactions / output_indices and does the ecdh
          // mask+amount normalization, the miner_tx rct default, and the
          // tx_hashes null-drop internally. This replaces the old nlohmann
          // "parse -> mutate DOM -> dump -> re-parse into struct" double pass.
          auto fetched = MONERO_UNWRAP(
            wire::json::from_bytes<rpc::json<rpc::get_blocks_fast>::response>(std::move(raw_response))
          );

          if (fetched.result.status == "Failed")
            throw std::runtime_error{"Daemon unexpectedly returned zero blocks and status failed"};

          // Per-height block-hash overrides (Beldex minor_tx_hashes).
          std::unordered_map<uint, crypto::hash> heightWithHash;
          for (const auto& entry : fetched.result.minor_tx_hashes)
            heightWithHash[static_cast<uint>(entry.height)] = entry.hash;

          // Post-parse fixups the old nlohmann pass performed on the mutated DOM,
          // now applied to the typed data with identical logic.
          {
            auto& blocks_v = fetched.result.blocks;
            auto& indices_v = fetched.result.output_indices;
            for (std::size_t ch = 0; ch < blocks_v.size(); ++ch)
            {
              auto& bwt = blocks_v[ch];
              // If either the block's tx_hashes or its transactions came back
              // empty, clear both so their counts agree.
              if (bwt.block.tx_hashes.empty() || bwt.transactions.empty())
              {
                bwt.transactions.clear();
                bwt.block.tx_hashes.clear();
              }
              // output_indices[ch] carries the miner-tx indices as element 0, so
              // it should hold transactions.size()+1 entries; if not, drop the
              // empty inner arrays (mirrors the old size-mismatch fixup, incl.
              // its size_t wrap when output_indices[ch] is empty).
              if (ch < indices_v.size() &&
                  bwt.transactions.size() != indices_v[ch].size() - 1)
              {
                std::vector<std::vector<std::uint64_t>> filtered;
                filtered.reserve(indices_v[ch].size());
                for (auto& inner : indices_v[ch])
                  if (!inner.empty())
                    filtered.push_back(std::move(inner));
                indices_v[ch] = std::move(filtered);
              }
            }
          }

          if (fetched.result.blocks.empty())
            throw std::runtime_error{"Daemon unexpectedly returned zero blocks"};

          if (fetched.result.start_height != start_height)   //req.start_height
          {
            MWARNING("Daemon sent wrong blocks, resetting state");
            return;
          }

          // prep for next blocks retrieval
          start_height = fetched.result.start_height + fetched.result.blocks.size() - 1;
          // block_request = rpc::client::make_message("get_blocks_fast", req);

          if (fetched.result.blocks.size() <= 1)
          {
            MINFO("At chain tip, waiting for next block...");
            std::this_thread::sleep_for(10s);
            continue; // to next get_blocks_fast read
          }

          if (fetched.result.blocks.size() != fetched.result.output_indices.size())
            throw std::runtime_error{"Bad daemon response - need same number of blocks and indices"};

          blockchain.push_back(cryptonote::get_block_hash(fetched.result.blocks.front().block));

          auto blocks = epee::to_span(fetched.result.blocks);
          auto indices = epee::to_span(fetched.result.output_indices);

          if (fetched.result.start_height != 1)
          {
            // skip overlap block
            blocks.remove_prefix(1);
            indices.remove_prefix(1);
          }
          else
            fetched.result.start_height = 0;

          for (auto block_data : boost::combine(blocks, indices))
          {
            ++(fetched.result.start_height);

            cryptonote::block const& block = boost::get<0>(block_data).block;
            auto const& txes              = boost::get<0>(block_data).transactions;

            if (block.tx_hashes.size() != txes.size())
              throw std::runtime_error{
                "Bad daemon response - need same number of txes and tx hashes"};

            auto local_indices = epee::to_span(boost::get<1>(block_data));
            if (local_indices.empty())
              throw std::runtime_error{
                "Bad daemon response - missing coinbase tx indices"};

            crypto::hash miner_tx_hash;
            if (!cryptonote::get_transaction_hash(block.miner_tx, miner_tx_hash))
              throw std::runtime_error{"Failed to calculate miner tx hash"};

            const crypto::hash& block_hash =
                heightWithHash.count(fetched.result.start_height)
                  ? heightWithHash[fetched.result.start_height]
                  : miner_tx_hash;

            scan_transaction(
              epee::to_mut_span(users),
              db::block_id(fetched.result.start_height),
              block.timestamp,
              block_hash,
              block.miner_tx,
              *(local_indices.begin())
            );

            local_indices.remove_prefix(1);

            if (txes.size() != local_indices.size())
              throw std::runtime_error{
                "Bad daemon response - need same number of txes and indices"};

            for (auto tx_data : boost::combine(block.tx_hashes, txes, local_indices))
            {
              scan_transaction(
                  epee::to_mut_span(users),
                  db::block_id(fetched.result.start_height),
                  block.timestamp,
                  boost::get<0>(tx_data),
                  boost::get<1>(tx_data),
                  boost::get<2>(tx_data)
                );
            }

            blockchain.push_back(cryptonote::get_block_hash(block));
          }

          expect<std::size_t> updated = disk.update(
            users.front().scan_height(), epee::to_span(blockchain), epee::to_span(users)
          );
          if (!updated)
          {
            if (updated == lws::error::blockchain_reorg)
            {
              MINFO("Blockchain reorg detected, resetting state");
              return;
            }
            MONERO_THROW(updated.error(), "Failed to update accounts on disk");
          }

          MINFO("Processed " << blocks.size() << " block(s) against " << users.size() << " account(s)");
          if (*updated != users.size())
          {
            MWARNING("Only updated " << *updated << " account(s) out of " << users.size() << ", resetting");
            return;
          }

          for (account& user : users)
            user.updated(db::block_id(fetched.result.start_height));

        } // while scan loop
      }
      /* Recover rather than terminate.

         These handlers used to call `scanner::stop()`, the global process kill
         switch, for ANY exception - a get_blocks_fast timeout, a beldexd
         restart, one malformed response. A brief daemon outage took the whole
         LWS down and every wallet stopped updating until someone restarted it.

         Returning instead unwinds this thread; the `stop_` guard signals
         `check_loop`, which joins the thread group and returns, and
         `scanner::run` then re-reads the account list and starts a fresh scan.
         That is the existing restart path - it just has to not be poisoned by
         a global stop first. `scanner::run` paces the retries (see the backoff
         there) so a persistent fault cannot spin. A real shutdown still works:
         it sets `running` false via the signal handler, which `scanner::run`
         checks before restarting. */
      catch (std::exception const& e)
      {
        MERROR("Scan thread aborted, will restart: " << e.what());
      }
      catch (...)
      {
        MERROR("Scan thread aborted on unknown exception, will restart");
      }
    }

    /*!
      Launches `thread_count` threads to run `scan_loop`, and then polls for
      active account changes in background
    */
    void check_loop(db::storage disk, std::size_t thread_count, std::string daemon_rpc,std::vector<lws::account> users, std::vector<db::account_id> active, std::map<db::account_id, db::block_id> start_heights)
    {
      assert(0 < thread_count);
      assert(0 < users.size());
      // std::cout << "thread_count : " << thread_count << std::endl;
      // std::cout << "users.size() : " << users.size() << std::endl;
      thread_sync self{};
      std::vector<boost::thread> threads{};

      struct join_
      {
        thread_sync& self;
        std::vector<boost::thread>& threads;
        // rpc::context& ctx;

        ~join_() noexcept
        {
          self.update = true;
          // ctx.raise_abort_scan();
          for (auto& thread : threads)
            thread.join();
        }
      } join{self, threads/*, ctx*/};

      /*
        The algorithm here is extremely basic. Users are divided evenly amongst
        the configurable thread count, and grouped by scan height. If an old
        account appears, some accounts (grouped on that thread) will be delayed
        in processing waiting for that account to catch up. Its not the greatest,
        but this "will have to do" for the first cut.
        Its not expected that many people will be running
        "enterprise level" of nodes where accounts are constantly added.

        Another "issue" is that each thread works independently instead of more
        cooperatively for scanning. This requires a bit more synchronization, so
        was left for later. Its likely worth doing to reduce the number of
        transfers from the daemon, and the bottleneck on the writes into LMDB.

        If the active user list changes, all threads are stopped/joined, and
        everything is re-started.
      */

      boost::thread::attributes attrs;
      attrs.set_stack_size(5 * 1024 * 1024);

      threads.reserve(thread_count);
      std::sort(users.begin(), users.end(), by_height{});  //users are sorted by their scan height

      MINFO("Starting scan loops on " << std::min(thread_count, users.size()) << " thread(s) with " << users.size() << " account(s)");

      while (!users.empty() && --thread_count)
      {
        const std::size_t per_thread = std::max(std::size_t(1), users.size() / (thread_count + 1));
        const std::size_t count = std::min(per_thread, users.size());
        std::vector<lws::account> thread_users{
          std::make_move_iterator(users.end() - count), std::make_move_iterator(users.end())
        };
        users.erase(users.end() - count, users.end());

        //   rpc::client client = MONERO_UNWRAP(ctx.connect());
        //   client.watch_scan_signals();
        //  std::cout << "entered in to the users thereads\n";
        auto data = std::make_shared<thread_data>(disk.clone(), std::move(thread_users));
        threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self),daemon_rpc,std::move(data)));
      }

      if (!users.empty())
      {
        // rpc::client client = MONERO_UNWRAP(ctx.connect());
        // client.watch_scan_signals();
        // std::cout << "entered in to the users users\n";
        auto data = std::make_shared<thread_data>(disk.clone(), std::move(users));
        threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self), daemon_rpc,std::move(data)));
      }

      auto last_check = std::chrono::steady_clock::now();

      /* Kept across `check_loop` invocations on purpose. The loop is torn down
         and restarted every time the active account set changes, so a
         per-invocation timer would be reset constantly on a busy server and
         maintenance would never actually run. */
      static auto last_maintenance = std::chrono::steady_clock::now();

      lmdb::suspended_txn read_txn{};
      db::cursor::accounts accounts_cur{};
      boost::unique_lock<boost::mutex> lock{self.sync};

      /* First moment an account-set change was seen, if one is outstanding.
         See `account_change_coalesce` - the restart is deferred until the
         window expires so a burst of signups costs one restart, not one each. */
      bool change_pending = false;
      std::chrono::steady_clock::time_point change_first_seen{};

      while (scanner::is_running())
      {
        for (;;)
        {
          //! \TODO use signalfd + ZMQ? Windows is the difficult case...
          // self.user_poll.wait_for(lock, boost::chrono::seconds{1});
          std::this_thread::sleep_for(1s);
          if (self.update || !scanner::is_running())
            return;
          auto this_check = std::chrono::steady_clock::now();
          if (account_poll_interval <= (this_check - last_check))
          {
            last_check = this_check;
            break;
          }
        }

        /* Periodic LMDB housekeeping. The reader sweep is what stops a
           long-running server growing its map without bound: a slot orphaned
           by a killed process blocks reclamation of every page freed since its
           snapshot. Cheap, and never fails the caller. */
        {
          const auto now_maint = std::chrono::steady_clock::now();
          if (db_maintenance_interval <= (now_maint - last_maintenance))
          {
            last_maintenance = now_maint;
            db::run_maintenance(disk, "scanner");
          }
        }

        auto reader = disk.start_read(std::move(read_txn));
        if (!reader)
        {
          if (reader.matches(std::errc::no_lock_available))
          {
            MWARNING("Failed to open DB read handle, retrying later");
            continue;
          }
          MONERO_THROW(reader.error(), "Failed to open DB read handle");
        }

        auto current_users = MONERO_UNWRAP(
          reader->get_accounts(db::account_status::active, std::move(accounts_cur))
        );

        bool changed = (current_users.count() != active.size());

        for (auto user = current_users.make_iterator(); !user.is_end() && !changed; ++user)
        {
          const db::account_id user_id = user.get_value<MONERO_FIELD(db::account, id)>();
          if (!std::binary_search(active.begin(), active.end(), user_id))
          {
            changed = true;
            break;
          }

          /* A rescan lowers an account's scan_height without changing the set of
             active accounts. The membership checks above cannot see that, so the
             running threads kept their in-memory height and sat idle at the chain
             tip - an admin `rescan` silently did nothing until the scanner
             happened to restart for some other reason. Detect the height moving
             backwards and restart so the rescan actually takes effect. */
          const db::block_id current_height =
            user.get_value<MONERO_FIELD(db::account, scan_height)>();
          const auto started = start_heights.find(user_id);
          if (started != start_heights.end() && current_height < started->second)
          {
            MINFO("Rescan detected for account " << lmdb::to_native(user_id)
                  << " (height " << lmdb::to_native(started->second) << " -> "
                  << lmdb::to_native(current_height) << ")");
            changed = true;
            break;
          }
        }

        /* Coalesce (S1). The threads keep scanning and committing throughout the
           window, so deferring the restart never loses work - it only stops the
           restart rate from tracking the signup rate. Once armed the timer is
           not disarmed: a change that reverts within the window (account added
           then deactivated) still gets one restart, which is correct and cheap. */
        {
          const auto now_change = std::chrono::steady_clock::now();
          if (changed && !change_pending)
          {
            change_pending = true;
            change_first_seen = now_change;
            MINFO("Change in active user accounts detected; coalescing further "
                  "changes for " << account_change_coalesce.count()
                  << "s before restarting scan threads");
          }
          if (change_pending && account_change_coalesce <= (now_change - change_first_seen))
          {
            MINFO("Restarting scan threads to pick up account changes");
            return;
          }
        }

        read_txn = reader->finish_read();
        accounts_cur = current_users.give_cursor();
      } // while scanning
    }

  } // anonymous 

  // ---------------------------------------------------------------------------
  // scanner::sync
  // ---------------------------------------------------------------------------
  bool scanner::sync(db::storage disk, std::string daemon_rpc)
  {
    MINFO("Starting blockchain sync with daemon");

    const bool use_ipc = is_ipc_uri(daemon_rpc);

    static oxenmq::OxenMQ lmq{nullptr, oxenmq::LogLevel::warn};
    static oxenmq::ConnectionID conn;
    static bool lmq_started = false;

    if (use_ipc && !lmq_started)
    {
      lmq.MAX_MSG_SIZE = 200 * 1024 * 1024;
      lmq.start();
      conn = lmq.connect_remote(
        daemon_rpc,
        [](oxenmq::ConnectionID) { MINFO("IPC connected"); },
        [](oxenmq::ConnectionID, std::string_view err) {
          MERROR("IPC connection failed: " << err);
        }
      );
      lmq_started = true;
    }

    try
    {
      /* Refuse to sync against a daemon on a different network.

         Nothing verified this: `check_blockchain()` (the genesis/checkpoint
         check) is commented out in storage.cpp, so pointing an existing mainnet
         database at a testnet daemon - an easy operational slip - was silently
         accepted. `sync_chain` would then treat the foreign chain as a reorg and
         roll back real accounts. Checking the daemon's own `nettype` against the
         configured `--network` catches that before a single block is written. */
      if (!use_ipc)
      {
        json info_req = {
          {"jsonrpc", "2.0"}, {"id", "0"}, {"method", "get_info"}
        };
        auto info_res = cpr::Post(
          cpr::Url{daemon_rpc},
          cpr::Body{info_req.dump()},
          cpr::Header{{"Content-Type", "application/json"}},
          cpr::Timeout{sync_rpc_timeout}
        );
        if (!info_res.text.empty())
        {
          const json parsed = json::parse(info_res.text, nullptr, false);
          if (!parsed.is_discarded() && parsed.contains("result") &&
              parsed["result"].is_object() && parsed["result"].contains("nettype"))
          {
            const std::string daemon_net = parsed["result"]["nettype"].get<std::string>();
            const char* expected =
              lws::config::network == cryptonote::network_type::MAINNET ? "mainnet" :
              lws::config::network == cryptonote::network_type::TESTNET ? "testnet" :
              lws::config::network == cryptonote::network_type::DEVNET  ? "devnet"  : nullptr;
            if (expected && daemon_net != expected)
            {
              MERROR("Refusing to sync: daemon is on '" << daemon_net
                     << "' but this server is configured for '" << expected
                     << "'. Check --network and --daemon.");
              scanner::stop();
              return false;
            }
          }
        }
      }

      json details;
      // Heights are uint64 on the wire and in the DB; `int` truncated them and
      // would overflow at 2^31 blocks.
      std::uint64_t a = 0;
      std::vector<crypto::hash> blk_ids;

      {
        auto reader = disk.start_read();
        if (!reader)
          throw std::runtime_error("DB read failed");

        auto chain = reader->get_chain_sync();
        if (!chain)
          throw std::runtime_error("Failed to get chain height");

        a = *chain;
        MINFO("Last_height_from Db : " << a);
      }

      for (;;)
      {
        json response_json;

        if (!use_ipc)
        {
          json request = {
            {"jsonrpc", "2.0"},
            {"id",      "0"},
            {"method",  "get_hashes"},
            {"params",  {{"start_height", a}}}
          };

          auto response = cpr::Post(
            cpr::Url{daemon_rpc},
            cpr::Body{request.dump()},
            cpr::Header{{"Content-Type", "application/json"}},
            cpr::Timeout{sync_rpc_timeout}
          );

          if (response.text.empty())
            throw std::runtime_error{"daemon connection failed"};

          response_json = json::parse(response.text);

          if (!response_json.contains("result"))
            throw std::runtime_error("Invalid JSON-RPC response");

          details = response_json["result"];
        }
        else
        {
          json params = {{"start_height", a}};
          std::string result = ipc_request(lmq, conn, "rpc.get_hashes",
                                           params.dump(),
                                           std::chrono::seconds{10});
          details = json::parse(result);
        }

            /* Every field below used to be read with `operator[]` on a possibly
           absent key, and the hex conversion result was discarded - a malformed
           reply left a garbage hash in `blk_ids` or threw, and (before F3) a
           throw here terminated the process. Validate explicitly. */
        if (!details.is_object())
          throw std::runtime_error{"Daemon returned a non-object get_hashes result"};
        if (details.value("status", std::string{"OK"}) == "Failed")
          throw std::runtime_error{"Daemon unexpectedly returned zero hashes and status failed"};
        if (!details.contains("m_block_ids") || !details["m_block_ids"].is_array())
          throw std::runtime_error{"Daemon get_hashes reply missing m_block_ids"};
        if (!details.contains("start_height") || !details.contains("current_height"))
          throw std::runtime_error{"Daemon get_hashes reply missing height fields"};

        for (const auto& block_data : details["m_block_ids"])
        {
          if (!block_data.is_string())
            throw std::runtime_error{"Daemon get_hashes returned a non-string block id"};
          const std::string id = block_data.get<std::string>();
          if (!tools::hex_to_type(id, blk_ids.emplace_back()))
            throw std::runtime_error{"Daemon get_hashes returned a malformed block id"};
        }

        const std::uint64_t block_ids_size = details["m_block_ids"].size();
        const std::uint64_t start_height = details["start_height"].get<std::uint64_t>();
        const std::uint64_t current_height = details["current_height"].get<std::uint64_t>();

        // Unsigned now, so compare rather than subtract (a daemon reporting
        // current_height < start_height would have wrapped).
        if (blk_ids.size() <= 1 || current_height <= start_height + 1)
        {
          MINFO("synced daemon upto the top chain");
          break;
        }

        const expect<void> synced =
          disk.sync_chain(db::block_id(details["start_height"]), epee::to_span(blk_ids));
        if (!synced)
          throw std::runtime_error{"Failed to sync chain hashes to DB: " + synced.error().message()};
        blk_ids.clear();
        a = block_ids_size + start_height - 1;
      }
    }
    /* As in `scan_loop`: a failed chain sync (daemon down, malformed reply)
       must not terminate the process. Leave the chain where it got to and let
       the caller retry; `scanner::run` calls `sync` again each pass. */
    catch (const std::exception& e)
    {
      MERROR("Chain sync failed, will retry: " << e.what());
      return false;
    }
    catch (...)
    {
      MERROR("Chain sync failed on unknown exception, will retry");
      return false;
    }
    return true;
  }

  // ---------------------------------------------------------------------------
  // scanner::run
  // ---------------------------------------------------------------------------
  void scanner::run(db::storage disk, std::string daemon_rpc, std::size_t thread_count)
  {
    run(std::move(disk), std::vector<std::string>{std::move(daemon_rpc)}, thread_count);
  }

  void scanner::run(db::storage disk, std::vector<std::string> daemon_rpcs, std::size_t thread_count)
  {
    thread_count = std::max(std::size_t(1), thread_count);

    if (daemon_rpcs.empty())
      daemon_rpcs.emplace_back();

    /* Index of the daemon this pass talks to. Rotated only when a pass ends
       almost immediately, which is the existing signal that the daemon is
       unreachable rather than that there was no work to do - so a healthy
       single-daemon deployment never rotates, and a dead primary is abandoned
       after one short pass instead of stalling every wallet until an operator
       intervenes. */
    std::size_t endpoint = 0;

    /* Per-account output projection carried across restarts; see the reuse
       check in the reload loop below. Bounded so a very large account
       population cannot grow this without limit - past the bound, accounts
       simply fall back to reloading from LMDB as before. */
    struct cached_outputs
    {
      db::block_id height;
      std::vector<db::output_id> receives;
    };
    std::map<db::account_id, cached_outputs> output_cache;
    std::size_t cache_entries = 0;
    constexpr const std::size_t max_cached_accounts = 100000;

    // Exponential backoff for passes that abort immediately (see below).
    constexpr const std::chrono::seconds initial_retry_delay{2};
    constexpr const std::chrono::seconds max_retry_delay{60};
    constexpr const std::chrono::seconds min_healthy_pass{5};
    std::chrono::seconds retry_delay = initial_retry_delay;

    for (;;)
    {
      const auto last = std::chrono::steady_clock::now();
      const std::string& daemon_rpc = daemon_rpcs[endpoint];

      std::vector<db::account_id> active;
      std::vector<lws::account>   users;
      //! Scan height each account had when this pass began; used to spot rescans.
      std::map<db::account_id, db::block_id> start_heights;

      {
        MINFO("Retrieving current active account list");

        auto reader   = MONERO_UNWRAP(disk.start_read());
        auto accounts = MONERO_UNWRAP(reader.get_accounts(db::account_status::active));

        std::size_t reloaded_from_db = 0, served_from_cache = 0;
        std::set<db::account_id> seen_this_pass;

        for (db::account user : accounts.make_range())
        {
          seen_this_pass.insert(user.id);

          /* Reuse the previous pass's output projection when this account has
             not scanned anything since.

             `check_loop` tears down and restarts the whole thread group
             whenever the active account set changes - i.e. on every signup -
             and this loop then re-walked EVERY account's ENTIRE output history
             out of LMDB to rebuild `receives`/`pubs`. That is O(accounts x
             outputs) of disk reads per restart, so at any real signup rate the
             scanner spent its time reloading instead of scanning.

             Outputs and the account's scan_height are committed in the same
             transaction (`storage::update`), so an unchanged scan_height means
             the stored outputs are unchanged too and the cached vectors are
             exactly in sync. A height that moved falls through to a full
             reload, which is always correct. */
          const auto cached = output_cache.find(user.id);
          if (cached != output_cache.end() && cached->second.height == user.scan_height)
          {
            users.emplace_back(user, cached->second.receives);
            ++served_from_cache;
          }
          else
          {
            std::vector<db::output_id> receives{};
            auto receive_list = MONERO_UNWRAP(reader.get_outputs(user.id));

            const std::size_t elems = receive_list.count();
            receives.reserve(elems);

            // Only the output id is needed now (see account::add_out), so the
            // one-time public key is no longer read back for every output.
            for (auto output = receive_list.make_iterator(); !output.is_end(); ++output)
              receives.emplace_back(output.get_value<MONERO_FIELD(db::output, spend_meta.id)>());

            if (cache_entries + 1 <= max_cached_accounts)
            {
              output_cache[user.id] = cached_outputs{user.scan_height, receives};
              cache_entries = output_cache.size();
            }
            users.emplace_back(user, std::move(receives));
            ++reloaded_from_db;
          }

          start_heights.emplace(user.id, user.scan_height);
          active.insert(
            std::lower_bound(active.begin(), active.end(), user.id), user.id
          );
        }

        // Drop cache entries for accounts that are no longer active.
        for (auto i = output_cache.begin(); i != output_cache.end(); )
          i = seen_this_pass.count(i->first) ? std::next(i) : output_cache.erase(i);
        cache_entries = output_cache.size();

        MINFO("Loaded " << users.size() << " account(s): "
              << reloaded_from_db << " from DB, " << served_from_cache << " reused");

        reader.finish_read();
      } // cleanup DB reader

      if (users.empty())
      {
        MINFO("No active accounts");
        checked_wait(account_poll_interval - (std::chrono::steady_clock::now() - last));
      }
      else
        check_loop(disk.clone(),thread_count, daemon_rpc,std::move(users), std::move(active), std::move(start_heights));

      if (!scanner::is_running())
        return;

      /* Back off when a pass ends almost immediately.

         `check_loop` returning quickly means the scan threads aborted (daemon
         unreachable, malformed response) rather than doing useful work. Without
         this the loop would restart instantly and spin at 100% CPU hammering a
         dead daemon - which is what made terminating on error look preferable.
         A pass that ran for a sensible period is treated as healthy and retried
         immediately, so normal operation is unaffected. */
      const auto elapsed = std::chrono::steady_clock::now() - last;
      if (elapsed < min_healthy_pass)
      {
        if (retry_delay < max_retry_delay)
          retry_delay = std::min(max_retry_delay, retry_delay * 2);
        if (1 < daemon_rpcs.size())
        {
          endpoint = (endpoint + 1) % daemon_rpcs.size();
          MWARNING("Scan pass failed against " << daemon_rpc
                   << "; failing over to " << daemon_rpcs[endpoint]);
        }
        MWARNING("Scan pass ended after "
                 << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                 << "ms; retrying in "
                 << std::chrono::duration_cast<std::chrono::seconds>(retry_delay).count() << "s");
        checked_wait(retry_delay);
        if (!scanner::is_running())
          return;
      }
      else
        retry_delay = initial_retry_delay; // healthy pass - reset the backoff

      /* Rotate on a failed chain sync as well as on a short scan pass.

         A short pass is only produced once there are accounts to scan; an idle
         server (no accounts yet, or all at the tip) never generates one, so on
         a fresh deployment a dead primary would have been retried forever. A
         failed `sync` is the direct signal that this endpoint is unreachable. */
      if (!sync(disk.clone(), daemon_rpc) && 1 < daemon_rpcs.size())
      {
        const std::size_t next = (endpoint + 1) % daemon_rpcs.size();
        MWARNING("Chain sync failed against " << daemon_rpc
                 << "; failing over to " << daemon_rpcs[next]);
        endpoint = next;
      }
    }
  }

} // namespace lws