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
    static std::string ipc_request(
        oxenmq::OxenMQ& lmq,
        oxenmq::ConnectionID& conn,
        const std::string& method,
        const std::string& params_json,
        std::chrono::seconds timeout = std::chrono::seconds{60})
    {
      std::promise<std::string> prom;
      auto fut = prom.get_future();

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

        size_t pk_index = 0;
        while(true)
        {
          if (!cryptonote::find_tx_extra_field_by_type(extra, key, pk_index++))
          {
            if (pk_index > 1)
              break;
          }
        }

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
          else if (cryptonote::txin_zc_input const* const zc_data =
                     std::get_if<cryptonote::txin_zc_input>(std::addressof(in)))
          {
            /* HF22: the input side of a privacy-token spend - a burn, a mint, or
               a token transfer. Without this branch the spend is silently not
               recorded, and the account keeps counting an output it no longer
               owns: a burn that consumed 1,000,000 and returned 750,000 in
               change reported 1,750,000, because the change was added and
               nothing was ever taken away.

               Token outputs are stored under amount 0 (see the storing side
               below), so the lookup uses 0 rather than an input amount - which
               txin_zc_input does not carry, the value being hidden in the
               commitment. */
            mixin = boost::numeric_cast<std::uint32_t>(
              std::max(std::size_t(1), zc_data->key_offsets.size()) - 1
            );

            std::uint64_t goffset = 0;
            for (std::uint64_t offset : zc_data->key_offsets)
            {
              goffset += offset;
              if (user.has_spendable(db::output_id{0, goffset}))
              {
                user.add_spend(
                    db::spend{
                        db::transaction_link{height, tx_hash},
                        zc_data->k_image,
                        db::output_id{0, goffset},
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
        // HF22: rct_signatures.outPk / ecdhInfo cover only the NATIVE outputs,
        // while `index` walks every vout. A token tx interleaves zarcanum
        // outputs with native ones (fee change, registration collateral), so
        // indexing those vectors by vout position runs off the end -- a 12
        // output registration has just 2 entries. Track the native ordinal
        // separately. output_indices is unaffected: the daemon emits one entry
        // per vout, so out_ids stays indexed by `index`.
        std::size_t native_index = 0;
        for (auto const& out : tx.vout)
        {
          // std::cout << "entered in vout " << std::endl;
          ++index;
          const bool is_native_out =
              std::get_if<cryptonote::tx_out_zarcanum>(std::addressof(out.target)) == nullptr;
          const std::size_t this_native_index = native_index;
          if (is_native_out)
            ++native_index;

          cryptonote::txout_to_key const* const out_data =
              std::get_if<cryptonote::txout_to_key>(std::addressof(out.target));
          // HF22: a private-token output is a tx_out_zarcanum, which carries its
          // one-time key as `stealth_address` rather than `key`. Ownership is
          // decided identically from there. Before this, the get_if above
          // returned null for these and every token output was silently skipped.
          cryptonote::tx_out_zarcanum const* const zout_data =
              std::get_if<cryptonote::tx_out_zarcanum>(std::addressof(out.target));
          if (!out_data && !zout_data)
            continue; // to next output

          const crypto::public_key& out_pub =
              out_data ? out_data->key : zout_data->stealth_address;

          crypto::public_key derived_pub;
          const bool received =
              crypto::wallet::derive_subaddress_public_key(out_pub, derived, index, derived_pub) &&
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
          crypto::token_id token_id = crypto::null_tid;
          if (zout_data)
          {
            // HF22: recover the plaintext token id and amount. `acc` is unused
            // by decode_zarcanum_output -- everything it needs comes from the
            // derivation and the output itself -- which is what lets a
            // view-only server decode these at all. It re-derives the amount
            // commitment and returns false on mismatch, so a corrupt or
            // misattributed output is rejected rather than stored wrong.
            const cryptonote::account_keys view_only{};
            rct::key amount_mask{};
            rct::key token_blinding_mask{};
            if (!cryptonote::decode_zarcanum_output(
                  view_only, *zout_data, derived, index,
                  amount, token_id, amount_mask, token_blinding_mask))
            {
              MWARNING(user.address() << " failed to decode private-token output for tx "
                       << tx_hash << ", skipping output");
              continue; // to next output
            }
            mask = amount_mask;
            ext = db::extra(ext | db::ringct_output);
          }
          else if (!amount && !(ext & db::coinbase_output) && cryptonote::txversion::v1 < tx.version)
          {
            
            const bool bulletproof2 = true;
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk.at(this_native_index).mask,
              tx.rct_signatures.ecdhInfo.at(this_native_index), derived, index, bulletproof2
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
            if (!payment_id.first && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.short_))
            {
              payment_id.first = sizeof(crypto::hash8);
              lws::decrypt_payment_id(payment_id.second.short_, derived);
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
                  // Since txversion v3 the per-output unlock times are the
                  // authoritative ones; tx.unlock_time is a legacy tx-wide
                  // value and is 0 on any modern transaction. HF22 relies on
                  // this: a registration locks ONLY its collateral output, so
                  // reading the tx-level field reports a wallet's locked
                  // collateral as immediately spendable.
                  tx.get_unlock_time(index),
                  *prefix_hash,
                  locked_key_image ? *locked_key_image : crypto::key_image{},
                  out_pub,
                  mask,
                  {0, 0, 0, 0, 0, 0, 0}, // reserved bytes
                  db::pack(ext, payment_id.first),
                  payment_id.second,
                  // HF22 private tokens. All zero for an ordinary BDX output.
                  // The blinded id, commitment and encrypted amount are stored
                  // verbatim because the wallet re-derives its own blinding
                  // scalar from them when spending; that scalar has no other
                  // source and the server cannot supply it.
                  zout_data ? reinterpret_cast<const crypto::public_key&>(token_id) : crypto::public_key{},
                  zout_data ? reinterpret_cast<const crypto::public_key&>(zout_data->blinded_token_id) : crypto::public_key{},
                  zout_data ? zout_data->amount_commitment : crypto::public_key{},
                  zout_data ? zout_data->encrypted_amount : std::uint64_t(0)
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
        static std::mutex ipc_fetch_mutex;

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
        auto fetch_blocks = [&](uint64_t height) -> std::string
        {
          if (use_ipc)
          {
            // No "count" or "max_count" param — daemon ignores unknown params
            // and always returns its internal default (which appears to be ~64
            // blocks). We control pace via retry logic instead.
            nlohmann::json params = {{"start_height", height}};

            MINFO("IPC fetch_blocks: height=" << height);

            std::string raw;
            {
              std::lock_guard<std::mutex> lock(ipc_fetch_mutex);
              raw = ipc_request(lmq, conn,
                                "rpc.get_blocks_fast",
                                params.dump(),
                                std::chrono::seconds{60});
            }

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
      catch (std::exception const& e)
      {
        scanner::stop();
        MERROR(e.what());
      }
      catch (...)
      {
        scanner::stop();
        MERROR("Unknown exception");
      }
    }

    /*!
      Launches `thread_count` threads to run `scan_loop`, and then polls for
      active account changes in background
    */
    void check_loop(db::storage disk, std::size_t thread_count, std::string daemon_rpc,std::vector<lws::account> users, std::vector<db::account_id> active)
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

      lmdb::suspended_txn read_txn{};
      db::cursor::accounts accounts_cur{};
      boost::unique_lock<boost::mutex> lock{self.sync};

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
        if (current_users.count() != active.size())
        {
          MINFO("Change in active user accounts detected, stopping scan threads...");
          return;
        }

        for (auto user = current_users.make_iterator(); !user.is_end(); ++user)
        {
          const db::account_id user_id = user.get_value<MONERO_FIELD(db::account, id)>();
          if (!std::binary_search(active.begin(), active.end(), user_id))
          {
            MINFO("Change in active user accounts detected, stopping scan threads...");
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
  void scanner::sync(db::storage disk, std::string daemon_rpc)
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
      json details;
        int a =0;
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

            if(details["status"]=="Failed")
        {
          throw std::runtime_error{"Daemon unexpectedly returned zero hashes and status failed"};
        }
        for (auto block_data : details["m_block_ids"])
        {
          std::string id = block_data;
          tools::hex_to_type(id, blk_ids.emplace_back());
        }

        int block_ids_size = details["m_block_ids"].size();
        int start_height = details["start_height"];
        int current_height = details["current_height"];

        if (blk_ids.size() <= 1 || (current_height - start_height) <= 1)
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
    catch (const std::exception& e)
    {
      scanner::stop();
      MERROR(e.what());
    }
    catch (...)
    {
      scanner::stop();
      MERROR("Unknown exception");
    }
  }

  // ---------------------------------------------------------------------------
  // scanner::run — unchanged
  // ---------------------------------------------------------------------------
   void scanner::run(db::storage disk, std::string daemon_rpc,std::size_t thread_count)
  {
    thread_count = std::max(std::size_t(1), thread_count);

    for (;;)
    {
      const auto last = std::chrono::steady_clock::now();

      std::vector<db::account_id> active;
      std::vector<lws::account>   users;

      {
        MINFO("Retrieving current active account list");

        auto reader   = MONERO_UNWRAP(disk.start_read());
        auto accounts = MONERO_UNWRAP(reader.get_accounts(db::account_status::active));

        for (db::account user : accounts.make_range())
        {
          std::vector<db::output_id> receives{};
          std::vector<crypto::public_key> pubs{};
          auto receive_list = MONERO_UNWRAP(reader.get_outputs(user.id));

          const std::size_t elems = receive_list.count();
          receives.reserve(elems);
          pubs.reserve(elems);

          for (auto output = receive_list.make_iterator(); !output.is_end(); ++output)
          {
            receives.emplace_back(output.get_value<MONERO_FIELD(db::output, spend_meta.id)>());
            pubs.emplace_back(output.get_value<MONERO_FIELD(db::output, pub)>());
          }

          users.emplace_back(user, std::move(receives), std::move(pubs));
          active.insert(
            std::lower_bound(active.begin(), active.end(), user.id), user.id
          );
        }

        reader.finish_read();
      } // cleanup DB reader

      if (users.empty())
      {
        MINFO("No active accounts");
        checked_wait(account_poll_interval - (std::chrono::steady_clock::now() - last));
      }
      else
        check_loop(disk.clone(),thread_count, daemon_rpc,std::move(users), std::move(active));

      if (!scanner::is_running())
        return;

      sync(disk.clone(), daemon_rpc);
    }
  }

} // namespace lws