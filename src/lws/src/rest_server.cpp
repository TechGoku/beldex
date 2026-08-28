#include "rest_server.h"

#include <algorithm>
#include <boost/utility/string_ref.hpp>
#include <cctype>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <cpr/cpr.h>
#include <zlib.h>

#include "common/error.h"                       // beldex/src
#include "common/hex.h"
#include "common/expect.h"
#include "crypto/crypto.h"                      // beldex/src
#include "cryptonote_config.h"                  // beldex/src
#include "lmdb/util.h"                          // beldex/src
#include "rpc/core_rpc_server_commands_defs.h"  // beldex/src

#include "error.h"
#include "db/data.h"
#include "db/storage.h"
#include "rpc/admin.h"
#include "rpc/client.h"
#include "util/http_server.h"
#include "util/gamma_picker.h"
#include "util/random_outputs.h"
#include "util/source_location.h"
#include "wire/crypto.h"
#include "rpc/light_wallet.h"
#include "wire/json.h"
#include "config.h"
namespace lws
{
  namespace
  {
    namespace http = epee::net_utils::http;

    // ---- optional gzip of large REST responses (a transfer win for big
    // accounts; a no-op for clients that don't advertise gzip) ----

    //! \return true if the client's Accept-Encoding header advertises gzip.
    bool client_accepts_gzip(const http::http_request_info& query)
    {
      for (const auto& field : query.m_header_info.m_etc_fields)
      {
        if (field.first.size() == sizeof("Accept-Encoding") - 1 &&
            std::equal(
              field.first.begin(), field.first.end(), "Accept-Encoding",
              [](char a, char b) {
                return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
              }))
          return field.second.find("gzip") != std::string::npos;
      }
      return false;
    }

    /*! gzip-compress `size` bytes at `in`; \return empty on failure so the caller
        keeps the plain body.

        Takes a raw span rather than a `std::string` so the serialized response can
        be compressed straight out of its `byte_slice`, without first being copied
        into the response body. For a large account that copy was a full extra
        allocation of the uncompressed payload. */
    std::string gzip_compress(const void* in, std::size_t size)
    {
      if (size > 0x7fffffffULL) // keep well within zlib's 32-bit avail_* fields
        return {};
      z_stream zs{};
      // windowBits 15|16 selects the gzip (RFC 1952) wrapper. Level 1 (fastest):
      // the payload is dominated by high-entropy hex, so higher levels spend CPU
      // for little extra ratio.
      if (deflateInit2(&zs, 1, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
      std::string out;
      out.resize(deflateBound(&zs, static_cast<uLong>(size)));
      zs.next_in = reinterpret_cast<Bytef*>(const_cast<void*>(in));
      zs.avail_in = static_cast<uInt>(size);
      zs.next_out = reinterpret_cast<Bytef*>(&out[0]);
      zs.avail_out = static_cast<uInt>(out.size());
      const int rc = deflate(&zs, Z_FINISH);
      const uLong produced = zs.total_out;
      deflateEnd(&zs);
      if (rc != Z_STREAM_END)
        return {};
      out.resize(produced);
      return out;
    }

    struct context : epee::net_utils::connection_context_base
    {
      context()
          : epee::net_utils::connection_context_base()
      {}
    };

    bool is_hidden(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:
      case db::account_status::inactive:
        return false;
      default:
      case db::account_status::hidden:
        break;
      }
      return true;
    }

    bool is_locked(std::uint64_t unlock_time, db::block_id last) noexcept
    {
      if (unlock_time > cryptonote::MAX_BLOCK_NUMBER)
        return std::chrono::seconds{unlock_time} > std::chrono::system_clock::now().time_since_epoch();
      return db::block_id(unlock_time) > last;
    }

    bool key_check(const rpc::account_credentials& creds)
    {
      crypto::public_key verify{};
      if (!crypto::secret_key_to_public_key(creds.key, verify))
        return false;
      if (verify != creds.address.view_public)
        return false;
      return true;
    }

    std::vector<db::output::spend_meta_>::const_iterator
    find_metadata(std::vector<db::output::spend_meta_> const& metas, db::output_id id)
    {
      struct by_output_id
      {
        bool operator()(db::output::spend_meta_ const& left, db::output_id right) const noexcept
        {
          return left.id < right;
        }
        bool operator()(db::output_id left, db::output::spend_meta_ const& right) const noexcept
        {
          return left < right.id;
        }
      };
      return std::lower_bound(metas.begin(), metas.end(), id, by_output_id{});
    }

    // Beldex's /json_rpc wraps some responses in a single-element array, and
    // does so inconsistently: sometimes the whole envelope ([{...}]), sometimes
    // just the "result" ({"result":[{...}]}). Either form makes a string
    // subscript / value() throw json type_error.305/306. These helpers peel any
    // single-element array wrapper(s) so callers see the underlying object.
    // (get_master_node_cache handled the envelope form ad hoc since 7d73ebe21;
    // the tx-creation paths handled neither, which broke transaction building.)
    //
    // NB: only ever apply these to a value that must be an object (the envelope
    // or the "result"); genuine data arrays (histograms, outs, distributions)
    // are iterated directly and must never be passed here.
    const json& deep_unwrap(const json& j)
    {
      const json* p = &j;
      while (p->is_array() && p->size() == 1)
        p = std::addressof(p->front());
      return *p;
    }

    void unwrap_json_rpc(json& j)
    {
      while (j.is_array() && j.size() == 1)
      {
        json inner = std::move(j.front());
        j = std::move(inner);
      }
    }

    expect<json> post_json_rpc(std::string method, json params = json::object())
    {
      json request_body = {
        {"jsonrpc", "2.0"},
        {"id", "0"},
        {"method", method}
      };
      if (!params.empty())
        request_body["params"] = std::move(params);

      auto response = cpr::Post(
        cpr::Url{lws::daemon_add},
        cpr::Body{request_body.dump()},
        cpr::Header{{"Content-Type", "application/json"}},
        cpr::Timeout{std::chrono::milliseconds{30000}}
      );

      if (response.status_code != 200)
      {
        // status_code 0 means the HTTP request never completed (connection
        // refused/reset, timeout, or empty reply). response.error carries the
        // libcurl-level reason; log method + reason + url + timing so a code-0
        // failure points at its actual cause instead of being anonymous.
        MERROR("daemon RPC '" << method << "' failed: HTTP status " << response.status_code
               << ", transport error [" << static_cast<int>(response.error.code) << "] "
               << response.error.message << ", url=" << lws::daemon_add
               << ", req_bytes=" << request_body.dump().size()
               << ", elapsed=" << response.elapsed << "s");
        return make_error_code(std::errc::io_error);
      }

      try
      {
        json parsed = json::parse(response.text);
        unwrap_json_rpc(parsed);
        if (!parsed.is_object())
        {
          MERROR("daemon RPC '" << method << "' returned a non-object response: "
                 << response.text.substr(0, 300));
          return make_error_code(std::errc::protocol_error);
        }
        return parsed;
      }
      catch (const std::exception& e)
      {
        MERROR("daemon RPC '" << method << "' JSON parse failed: " << e.what());
        return make_error_code(std::errc::invalid_argument);
      }
    }

    //! `crypto::key_image` has no `std::hash` specialization in this tree.
    struct key_image_hash
    {
      std::size_t operator()(crypto::key_image const& image) const noexcept
      {
        std::size_t out{};
        static_assert(sizeof(out) <= sizeof(image.data), "key_image smaller than size_t");
        std::memcpy(std::addressof(out), image.data, sizeof(out));
        return out;
      }
    };

    struct master_node_cache
    {
      json master_nodes;
      json blacklist;
      // Built once per cache refresh from `blacklist`/`master_nodes` above so
      // request handlers do an O(1) lookup instead of walking every
      // masternode/contributor/contribution per output, per request.
      std::unordered_map<crypto::key_image, std::uint64_t, key_image_hash> blacklist_by_image;
      std::unordered_map<crypto::key_image, std::uint64_t, key_image_hash> locked_by_image;
    };

    expect<master_node_cache> get_master_node_cache()
    {
      static constexpr const auto cache_ttl = std::chrono::seconds{10};
      static std::mutex cache_mutex;
      static master_node_cache cache{};
      static auto last_update = std::chrono::steady_clock::now();
      static bool cache_initialized = false;

      const auto now = std::chrono::steady_clock::now();
      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        if (cache_initialized && now - last_update < cache_ttl)
          return cache;
      }

      auto master_nodes = post_json_rpc("get_master_nodes");
      if (!master_nodes)
        return master_nodes.error();

      auto blacklist = post_json_rpc("get_master_node_blacklisted_key_images");
      if (!blacklist)
        return blacklist.error();

      const std::lock_guard<std::mutex> lock{cache_mutex};
      // Peel any envelope-level array wrapping (single, or doubly nested as
      // get_output_distribution returns), leaving the envelope object.
      cache.master_nodes = std::move(*master_nodes);
      cache.blacklist = std::move(*blacklist);
      unwrap_json_rpc(cache.master_nodes);
      unwrap_json_rpc(cache.blacklist);

      // Some daemon builds also wrap "result" itself in a single-element array
      // (get_fee_estimate does; see deep_unwrap). Peel it in place so the
      // ["result"]["..."] walks below see the object, and guard the whole build
      // so a malformed master-node/blacklist response yields a clean error
      // instead of an uncaught throw out of get_address_info/get_unspent_outs.
      const auto dearray_result = [] (json& env)
      {
        if (!env.is_object())
          return;
        const auto it = env.find("result");
        if (it != env.end() && it->is_array() && it->size() == 1)
        {
          json inner = std::move(it->front());
          *it = std::move(inner);
        }
      };
      dearray_result(cache.blacklist);
      dearray_result(cache.master_nodes);

      cache.blacklist_by_image.clear();
      cache.locked_by_image.clear();
      try
      {
        for (const auto& item : cache.blacklist["result"]["blacklist"])
        {
          crypto::key_image image;
          const std::string image_str = item["key_image"];
          if (epee::string_tools::hex_to_pod(image_str, image))
            cache.blacklist_by_image[image] = item["amount"].get<std::uint64_t>();
        }

        for (const auto& mn_all : cache.master_nodes["result"]["master_node_states"])
        {
          if (!mn_all.contains("contributors"))
            continue;
          for (const auto& mn_contrib : mn_all["contributors"])
          {
            if (!mn_contrib.contains("locked_contributions"))
              continue;
            for (const auto& contribution : mn_contrib["locked_contributions"])
            {
              crypto::key_image image;
              const std::string image_str = contribution["key_image"].get<std::string>();
              if (tools::hex_to_type(image_str, image))
                cache.locked_by_image[image] = contribution["amount"].get<std::uint64_t>();
            }
          }
        }
      }
      catch (const std::exception& e)
      {
        MERROR("get_master_node_cache: unexpected master-node/blacklist response: " << e.what());
        return {lws::error::bad_daemon_response};
      }

      last_update = std::chrono::steady_clock::now();
      cache_initialized = true;
      return cache;
    }

    // Cache slow-changing, request-independent daemon data behind a short TTL,
    // the same pattern as get_master_node_cache above. The fee estimate and the
    // RingCT (amount 0) output distribution both change ~once per block; before
    // this, every get_unspent_outs did a live get_fee_estimate and every
    // get_random_outs did a live get_output_distribution (a large JSON) even
    // though the parameters are constant. The cached response shape is identical
    // (only up to `cache_ttl` stale), so clients are unaffected. A few blocks of
    // staleness in the distribution is harmless: decoy selection deliberately
    // avoids the very newest outputs anyway.
    expect<json> get_fee_estimate_cache()
    {
      static constexpr const auto cache_ttl = std::chrono::seconds{30};
      static std::mutex cache_mutex;
      static json cache{};
      static auto last_update = std::chrono::steady_clock::now();
      static bool cache_initialized = false;

      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        if (cache_initialized && std::chrono::steady_clock::now() - last_update < cache_ttl)
          return cache;
      }

      json params = json::object();
      params["grace_blocks"] = std::uint64_t(10);
      auto fetched = post_json_rpc("get_fee_estimate", std::move(params));
      if (!fetched)
        return fetched.error();

      const std::lock_guard<std::mutex> lock{cache_mutex};
      cache = std::move(*fetched);
      last_update = std::chrono::steady_clock::now();
      cache_initialized = true;
      return cache;
    }

    expect<json> get_output_distribution_cache()
    {
      static constexpr const auto cache_ttl = std::chrono::seconds{30};
      static std::mutex cache_mutex;
      static json cache{};
      static auto last_update = std::chrono::steady_clock::now();
      static bool cache_initialized = false;

      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        if (cache_initialized && std::chrono::steady_clock::now() - last_update < cache_ttl)
          return cache;
      }

      json params = {
        {"amounts", json::array({0})},
        {"from_height", 0},
        {"to_height", 0},
        {"cumulative", true}
      };
      auto fetched = post_json_rpc("get_output_distribution", std::move(params));
      if (!fetched)
        return fetched.error();

      const std::lock_guard<std::mutex> lock{cache_mutex};
      cache = std::move(*fetched);
      last_update = std::chrono::steady_clock::now();
      cache_initialized = true;
      return cache;
    }


    /*! A stream from `get_outputs`/`get_spends(id, min_height)` is positioned past
        the start of the account's records, so its `count()` - which reports every
        record at the key, not the remaining ones - would size a container for the
        whole account and hand back the memory the seek just saved. Reserve a fixed
        amount for incremental requests instead; the vector still grows on its own
        if a client returns after an unusually long absence.

        \return A `reserve()` size for a walk of `stream` bounded by `min_height`
        and/or paginated by `max_count`. */
    template<typename Stream>
    std::size_t reserve_for(const Stream& stream, const std::uint64_t min_height, const std::uint64_t max_count = 0)
    {
      constexpr const std::size_t incremental_reserve = 1024;
      if (max_count) // one page; the vector still grows if a huge block overshoots
        return std::min<std::size_t>(max_count, std::size_t{1} << 16);
      return min_height ? incremental_reserve : stream.count();
    }

    /*! One output's contribution to the `locked_funds` scalar.

        Kept separately from `spend_meta_` because that struct is ordered by output
        id for `find_metadata`, whereas this is only ever summed. */
    struct locked_entry
    {
      std::uint64_t amount;
      std::uint64_t unlock_time;
      crypto::key_image image;
    };

    /*! Cached projection of one account's output table.

        `get_address_info` has to resolve every returned spend against the output it
        consumed (`metas`), and has to report a cumulative `total_received` - which
        together forced a full walk of the account's outputs on EVERY request, even
        an incremental one, and even though nothing below the client's cursor could
        have changed. On a large account that walk dominates the request, and the
        endpoint is polled continuously for the wallet balance.

        Outputs are append-only, so the walk is cached here and extended with only
        the new records once the scanner advances. Holds ~112 bytes/output rather
        than the 264-byte `db::output`.

        `locked_funds` is deliberately NOT cached: it depends on live master-node
        state (10s TTL) and, for timestamp-based unlock times, on wall-clock time.
        It is recomputed per request from `locked`, which is a RAM scan with no LMDB
        I/O. */
    struct account_index
    {
      db::block_id scan_height;                    //!< every output in a block <= this is present
      crypto::hash scan_hash;                      //!< "our" block hash at `scan_height`
      std::uint64_t total_received;
      std::vector<db::output::spend_meta_> metas;  //!< sorted by id, for find_metadata
      std::vector<locked_entry> locked;            //!< output-walk order
    };

    std::size_t index_bytes(const account_index& self) noexcept
    {
      return sizeof(account_index)
        + self.metas.capacity() * sizeof(db::output::spend_meta_)
        + self.locked.capacity() * sizeof(locked_entry);
    }

    /*! \return Cached output projection for `user`, extended or rebuilt as needed.

        Entries are immutable once published, so a caller can hold the returned
        pointer without keeping the cache locked. An advance in `scan_height` builds
        a fresh entry (copy-on-extend) rather than mutating the shared one. */
    expect<std::shared_ptr<const account_index>>
    get_account_index(db::storage_reader& reader, const db::account& user)
    {
      struct index_slot
      {
        std::shared_ptr<const account_index> value;
        std::chrono::steady_clock::time_point last_access;
      };

      static std::mutex index_mutex;
      static std::unordered_map<std::uint32_t, index_slot> cache;
      static std::size_t cache_bytes = 0;
      // Bound total cached bytes so many distinct large accounts cannot grow memory
      // without limit (a single projection larger than this is never cached).
      constexpr const std::size_t cache_max_bytes = 256 * 1024 * 1024;

      const std::uint32_t key = std::uint32_t(user.id);
      const auto now = std::chrono::steady_clock::now();

      /* Scan height alone is not a safe identity for the account's output set. A
         reorg rolls the account back and re-scans forward, and if it lands on the
         same height again with no request in between, the height would look like an
         exact hit while the cached records came from the abandoned branch. The
         block hash at `scan_height` pins the branch too. One point lookup, against
         the full output walk it protects.

         If the hash is unavailable (e.g. a brand-new account whose scan height has
         no stored block) the cache is bypassed for this request rather than risked;
         the endpoint still answers, just without the memoization. */
      const expect<crypto::hash> scan_hash = reader.get_block_hash(user.scan_height);
      const bool cacheable = bool(scan_hash);

      std::shared_ptr<const account_index> base{};
      if (cacheable)
      {
        const std::lock_guard<std::mutex> lock{index_mutex};
        const auto it = cache.find(key);
        if (it != cache.end())
        {
          it->second.last_access = now;
          if (it->second.value->scan_height == user.scan_height &&
              it->second.value->scan_hash == *scan_hash)
            return it->second.value; // exact hit - no DB reads at all
          if (user.scan_height <= it->second.value->scan_height)
          {
            // Scan height moved backwards, or stayed put on a different branch:
            // records cached above the fork may be gone. Rebuild from scratch.
            cache_bytes -= index_bytes(*it->second.value);
            cache.erase(it);
          }
          else
            base = it->second.value; // extend with the delta below
        }
      }

      /* Extending assumes the records at or below the cached height are still the
         ones on the current chain. A reorg could have rewritten history below the
         cached height and re-scanned past it, so re-check that entry's branch
         before building on it. Only runs when the scanner has advanced, not on
         every request. */
      if (base)
      {
        const expect<crypto::hash> base_hash = reader.get_block_hash(base->scan_height);
        if (!base_hash || !(*base_hash == base->scan_hash))
          base.reset(); // history below the cursor changed - rebuild from scratch
      }

      auto fresh = std::make_shared<account_index>();
      fresh->scan_height = user.scan_height;
      fresh->scan_hash = cacheable ? *scan_hash : crypto::hash{};
      fresh->total_received = 0;
      if (base)
      {
        fresh->metas = base->metas;
        fresh->locked = base->locked;
        fresh->total_received = base->total_received;
      }

      /* Seek past what is already held. `base->scan_height` is the last block whose
         outputs are all present - the scanner commits outputs and the account's
         scan height in one transaction - so resume at the block after it. */
      auto outputs = base ?
        reader.get_outputs(user.id, db::block_id(std::uint64_t(base->scan_height) + 1)) :
        reader.get_outputs(user.id);
      if (!outputs)
        return outputs.error();

      if (!base) // count() is only meaningful on a stream that was not seeked
      {
        fresh->metas.reserve(outputs->count());
        fresh->locked.reserve(outputs->count());
      }

      for (auto output = outputs->make_iterator(); !output.is_end(); ++output)
      {
        // HF22: a privacy-token output's amount is denominated in that token,
        // not BDX. Letting one through here reports a wallet holding 1000 DEMO
        // as if it held an extra 1,000,000 BDX, and offers the output up as
        // spendable coin for a native send. Native outputs carry a null
        // token_id; token balances are accounted per-token, not here.
        if (output.get_value<MONERO_FIELD(db::output, token_id)>() != crypto::public_key{})
          continue;

        const db::output::spend_meta_ meta =
          output.get_value<MONERO_FIELD(db::output, spend_meta)>();

        // these outputs will usually be in correct order post ringct
        if (fresh->metas.empty() || fresh->metas.back().id < meta.id)
          fresh->metas.push_back(meta);
        else
          fresh->metas.insert(find_metadata(fresh->metas, meta.id), meta);

        fresh->total_received += meta.amount;
        fresh->locked.push_back(
          locked_entry{
            meta.amount,
            output.get_value<MONERO_FIELD(db::output, unlock_time)>(),
            output.get_value<MONERO_FIELD(db::output, locked_key_image)>()
          }
        );
      }

      std::shared_ptr<const account_index> result = fresh;
      if (cacheable)
      {
        const std::lock_guard<std::mutex> lock{index_mutex};
        const auto it = cache.find(key);
        if (it != cache.end())
        {
          cache_bytes -= index_bytes(*it->second.value);
          cache.erase(it);
        }
        const std::size_t sz = index_bytes(*result);
        // Evict least-recently-used until the new entry fits, rather than clearing
        // everything: a rebuild costs a full output walk, so dropping every account
        // on one overshoot would stampede.
        while (!cache.empty() && cache_max_bytes < cache_bytes + sz)
        {
          auto oldest = cache.begin();
          for (auto i = cache.begin(); i != cache.end(); ++i)
          {
            if (i->second.last_access < oldest->second.last_access)
              oldest = i;
          }
          cache_bytes -= index_bytes(*oldest->second.value);
          cache.erase(oldest);
        }
        if (sz <= cache_max_bytes)
        {
          cache.emplace(key, index_slot{result, now});
          cache_bytes += sz;
        }
      }
      return result;
    }

    //! \return Account info from the DB, iff key matches address AND address is NOT hidden.
    expect<std::pair<db::account, db::storage_reader>> open_account(const rpc::account_credentials& creds, db::storage disk)
    {
      if (!key_check(creds))
        return {lws::error::bad_view_key};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();

      const auto user = reader->get_account(creds.address);
      if (!user)
        return user.error();
      if (is_hidden(user->first))
        return {lws::error::account_not_found};
      return {std::make_pair(user->second, std::move(*reader))};
    }

    struct daemon_status
    {
        using request = rpc::daemon_status_request;
        using response = rpc::daemon_status_response;
    
        static expect<response> handle(const request&, db::storage)
        {
            // Build JSON request
            nlohmann::json request_body = {
                {"jsonrpc", "2.0"},
                {"id", "0"},
                {"method", "get_info"}
            };
    
            // Call the daemon
            auto response_http = cpr::Post(
                cpr::Url{lws::daemon_add},
                cpr::Body{request_body.dump()},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Timeout{std::chrono::milliseconds{30000}}
            );
    
            if (response_http.status_code != 200)
            {
                MERROR("get_info call failed with HTTP code: " << response_http.status_code);
                return make_error_code(std::errc::io_error);
            }
    
            // Parse JSON
            nlohmann::json full_response;
            try
            {
                full_response = nlohmann::json::parse(response_http.text);
            }
            catch (const std::exception& e)
            {
                MERROR("JSON parse failed: " << e.what());
                return make_error_code(std::errc::invalid_argument);
            }

            // The daemon may wrap the envelope (and/or the result) in a
            // single-element array, sometimes doubly; peel both levels so the
            // field reads below work regardless of nesting depth.
            const json& env = deep_unwrap(full_response);
            if (!env.is_object() || !env.contains("result"))
            {
                MERROR("Missing 'result' in get_info response");
                return make_error_code(std::errc::protocol_error);
            }

            const auto& result = deep_unwrap(env.at("result"));
    
            try
            {
                rpc::daemon_status_response resp;
    
                // Extract only required values
                resp.height = result.at("height").get<uint64_t>();
                resp.target_height = result.at("target_height").get<uint64_t>();
                resp.outgoing_connections_count = result.at("outgoing_connections_count").get<uint32_t>();
                resp.incoming_connections_count = result.at("incoming_connections_count").get<uint32_t>();
    
                // Determine network type
                std::string net = result.at("nettype").get<std::string>();
                if (net == "mainnet") resp.network = rpc::network_type::main;
                else if (net == "testnet") resp.network = rpc::network_type::test;
                else {
                    MERROR("Unknown nettype: " << net);
                    return make_error_code(std::errc::invalid_argument);
                }
    
                // Determine daemon state
                if (resp.outgoing_connections_count == 0 && resp.incoming_connections_count == 0)
                    resp.state = rpc::daemon_state::no_connections;
                else if (resp.target_height && (resp.target_height - resp.height) >= 5)
                    resp.state = rpc::daemon_state::synchronizing;
                else
                    resp.state = rpc::daemon_state::ok;
    
                return resp;
            }
            catch (const std::exception& e)
            {
                MERROR("Error parsing fields from get_info: " << e.what());
                return make_error_code(std::errc::invalid_argument);
            }
        }
    };
     
    
    struct get_address_info
    {
      using request = rpc::get_address_info_request;
      using response = rpc::get_address_info_response;

      static expect<response> handle(const request &req, db::storage disk)
      {
        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        std::unordered_set<crypto::key_image, key_image_hash> processed;

        auto master_node_data = get_master_node_cache();
        if (!master_node_data)
          return master_node_data.error();

        response resp{};

        // Only an incremental/paginated caller can use the per-spend `height`
        // field; a legacy caller would just pay for the bytes. See write_bytes for
        // transaction_spend.
        const bool incremental = (req.min_height != 0 || req.max_count != 0);

        /* The output side is served from the cached projection (see account_index)
           rather than re-walked here. It is needed in full regardless of the
           client's cursor - a spend returned below is resolved against `metas` by
           output id, and a spend in a new block can consume an output received
           years earlier, so a seeked (partial) `metas` would trip the "no receive
           for spend" throw - but it is also identical between requests until the
           scanner advances, which is what makes it cacheable. */
        auto index = get_account_index(user->second, user->first);
        if (!index)
          return index.error();
        const account_index& outputs = **index;

        // Incremental fetch: when the client sends a min_height cursor, seek the
        // spends cursor to it so only the new candidate spends are read. This is
        // the array that makes the response reach hundreds of MB on a busy
        // account, and the seek means the earlier spends cost nothing rather than
        // being read and then discarded.
        //
        // The client keeps its own persisted view of older candidate spends and
        // filters them with its key images (which the server, being view-only,
        // cannot do); it just receives new candidates as a small delta. Note that
        // `total_sent` is therefore delta-scoped for an incremental request, while
        // the output-derived scalars below stay cumulative.
        auto spends = req.min_height ?
          user->second.get_spends(user->first.id, db::block_id(req.min_height)) :
          user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);

        const std::vector<db::output::spend_meta_>& metas = outputs.metas;

        resp.total_received = rpc::safe_uint64(outputs.total_received);

        /* locked_funds is recomputed on every request rather than cached with the
           projection: the master-node blacklist and locked contributions come from
           the daemon on a 10s TTL, and a timestamp-based unlock_time is measured
           against wall-clock time, so neither is a pure function of the account's
           scanned state. This loop touches only RAM - no LMDB reads. */
        for (const locked_entry& out : outputs.locked)
        {
          // Skip non-locked outputs up front (the common case), and use O(1)
          // set membership instead of a linear scan of `processed` per output
          // (the latter was O(n^2) for accounts with many locked outputs).
          if (out.image != crypto::key_image{} && !processed.count(out.image))
          {
            // O(1) lookup against the maps built once per master-node cache
            // refresh (10s TTL), instead of walking every masternode /
            // contributor / contribution for this output.
            const auto blacklisted = master_node_data->blacklist_by_image.find(out.image);
            if (blacklisted != master_node_data->blacklist_by_image.end())
            {
              resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + blacklisted->second);
              processed.insert(out.image);
            }
            else
            {
              const auto locked = master_node_data->locked_by_image.find(out.image);
              if (locked != master_node_data->locked_by_image.end())
              {
                resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + locked->second);
                processed.insert(out.image);
              }
            }
          }

          if (is_locked(out.unlock_time, user->first.scan_height))
          {
            resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + out.amount);
          }
        }

        // Pagination: cap spent_outputs at max_count, stopping only at a block
        // boundary (a block is never split across pages). next_min_height carries
        // the first not-returned height back to the client for the next page. The
        // output-derived scalars above stay cumulative regardless.
        std::uint64_t returned = 0;
        std::uint64_t last_returned_height = 0;

        resp.spent_outputs.reserve(reserve_for(*spends, req.min_height, req.max_count));
        for (auto const &spend : spends->make_range())
        {
          const std::uint64_t spend_height = std::uint64_t(spend.link.height);
          if (req.max_count != 0 && returned >= req.max_count && spend_height != last_returned_height)
          {
            resp.next_min_height = spend_height; // resume here next page (inclusive seek)
            break;
          }

          const auto meta = find_metadata(metas, spend.source);
          if (meta == metas.end() || meta->id != spend.source)
          {
            throw std::logic_error{
              "Serious database error, no receive for spend"
            };
          }

          resp.spent_outputs.push_back({*meta, spend, incremental});
          resp.total_sent = rpc::safe_uint64(std::uint64_t(resp.total_sent) + meta->amount);
          ++returned;
          last_returned_height = spend_height;
        }

        return resp;
      }
    };//get_address_info

    struct get_unspent_outs
    {
      using request = rpc::get_unspent_outs_request;
      using response = rpc::get_unspent_outs_response;

      static expect<response> handle(request req, db::storage disk)
      {
        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        auto master_node_data = get_master_node_cache();
        if (!master_node_data)
          return master_node_data.error();

        // Fee estimate is request-independent (constant grace_blocks) and
        // changes slowly; served from a short-TTL cache instead of a live
        // daemon round-trip per request.
        auto fee_data = get_fee_estimate_cache();
        if (!fee_data)
          return fee_data.error();

        json resp = std::move(*fee_data);

        if ((req.use_dust && req.use_dust) || !req.dust_threshold)
          req.dust_threshold = rpc::safe_uint64(0);

        if (!req.mixin)
          req.mixin = 0;

        // Incremental unspent pool: when the client sends a min_height cursor, walk
        // only the outputs received at/after it. The client persists the outputs
        // (and their key images) it has already fetched and applies its own
        // spent-filtering, so a refresh transfers just the new outputs instead of
        // the account's entire receive history (hundreds of MB on a busy account).
        //
        // The bound is a cursor seek rather than a filter, so the earlier outputs
        // are never read - which also skips their per-output get_images sub-query
        // below, the dominant cost of this endpoint on a large account. `received`
        // is then the delta sum, so the full-pool `received < amount` guard is
        // skipped for incremental calls.
        auto outputs = req.min_height ?
          user->second.get_outputs(user->first.id, db::block_id(req.min_height)) :
          user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        std::uint64_t received = 0;
        std::vector<std::pair<db::output, std::vector<crypto::key_image>>> unspent;

        // Pagination: when the client sends max_count, return at most that many
        // outputs, stopping only at a block boundary so a block is never split
        // across pages. next_min_height carries the first not-returned height
        // back to the client, which re-issues with min_height = next_min_height.
        std::uint64_t next_min_height = 0;
        std::uint64_t returned = 0;
        std::uint64_t last_returned_height = 0;

        unspent.reserve(reserve_for(*outputs, req.min_height, req.max_count));
        for (db::output const& out : outputs->make_range())
        {
          const std::uint64_t out_height = std::uint64_t(out.link.height);
          if (req.max_count != 0 && returned >= req.max_count && out_height != last_returned_height)
          {
            next_min_height = out_height; // resume here next page (inclusive seek)
            break;
          }

          // HF22: never offer a privacy-token output as spendable coin. Its
          // amount is denominated in that token, and a wallet that picks one up
          // for a native send builds a transaction the daemon rejects outright
          // ("ringct non-semantics verification failed"). Token spending needs
          // its own selection path; this endpoint is native-only.
          if (out.token_id != crypto::public_key{})
            continue;

          // Nor a still-locked output. An HF22 registration locks its 10,000 BDX
          // collateral for months; offering it as spendable lets a wallet build
          // a transaction the network refuses. The client sees only an amount
          // and a height, not the unlock rule, so the server must not put a
          // locked output on the table in the first place.
          if (is_locked(out.unlock_time, user->first.scan_height))
            continue;

          const std::pair<db::extra, std::uint8_t> unpacked = db::unpack(out.extra);
          const bool coinbase = (unpacked.first & lws::db::coinbase_output);
          if (out.spend_meta.amount < std::uint64_t(*req.dust_threshold) ||  (out.spend_meta.mixin_count < *req.mixin && !(coinbase == 1)))
            continue;

          bool should_skip_output = false;
          const std::uint64_t value_l = out.spend_meta.amount;
          const crypto::key_image locked_key_image = out.locked_key_image;

          if (locked_key_image != crypto::key_image{})
          {
            // O(1) lookup against the maps built once per master-node cache
            // refresh (10s TTL), instead of walking every masternode /
            // contributor / contribution for this output. Amount is still
            // checked to match the prior per-entry comparison.
            const auto blacklisted = master_node_data->blacklist_by_image.find(locked_key_image);
            if (blacklisted != master_node_data->blacklist_by_image.end() && blacklisted->second == value_l)
            {
              should_skip_output = true;
            }
            else
            {
              const auto locked = master_node_data->locked_by_image.find(locked_key_image);
              if (locked != master_node_data->locked_by_image.end() && locked->second == value_l)
                should_skip_output = true;
            }
          }

          if (!should_skip_output)
          {
            received += out.spend_meta.amount;
            unspent.push_back({out, {}});

            auto images = user->second.get_images(out.spend_meta.id);
            if (!images)
              return images.error();

            unspent.back().second.reserve(images->count());
            auto range = images->make_range<MONERO_FIELD(db::key_image, value)>();
            std::copy(range.begin(), range.end(), std::back_inserter(unspent.back().second));

            ++returned;
            last_returned_height = out_height;
          }

        }

        // Only enforce the "enough funds" guard on a full-pool request. For an
        // incremental (min_height) request `received` is just the delta, and the
        // client aggregates coverage across its persisted pool itself.
        if (req.min_height == 0 && received < std::uint64_t(req.amount))
          return {lws::error::account_not_found};

        std::uint64_t fee_per_byte, fee_per_output, flash_fee_per_byte,
                      flash_fee_per_output, flash_fee_fixed, quantization_mask;
        try
        {
          // resp is the get_fee_estimate envelope (post_json_rpc /
          // get_fee_estimate_cache). deep_unwrap peels any single-element array
          // wrapping at the envelope and/or result level; guarded so an
          // unexpected daemon response becomes bad_daemon_response, not a throw.
          const json& env = deep_unwrap(resp);
          if (env.value("status", std::string{}) == "Failed")
            return {lws::error::bad_daemon_response};

          const json& result = deep_unwrap(env.at("result"));
          if (result.value("status", std::string{"OK"}) == "Failed")
            return {lws::error::bad_daemon_response};

          fee_per_byte         = result.at("fee_per_byte").get<std::uint64_t>();
          fee_per_output       = result.at("fee_per_output").get<std::uint64_t>();
          flash_fee_per_byte   = result.at("flash_fee_per_byte").get<std::uint64_t>();
          flash_fee_per_output = result.at("flash_fee_per_output").get<std::uint64_t>();
          flash_fee_fixed      = result.at("flash_fee_fixed").get<std::uint64_t>();
          quantization_mask    = result.at("quantization_mask").get<std::uint64_t>();
        }
        catch (const std::exception& e)
        {
          MERROR("get_unspent_outs: unexpected get_fee_estimate response: " << e.what()
                 << " -- body: " << resp.dump().substr(0, 400));
          return {lws::error::bad_daemon_response};
        }

        // The chain tip. HF22 token registration locks its collateral output to
        // an absolute height, so the client needs to know where the chain is.
        //
        // This is the scanner's tip, which trails the daemon's -- and consensus
        // compares the collateral's unlock height against the daemon's height at
        // validation time, so reporting a stale value here makes the client
        // build registrations the network rejects. The client adds its own
        // margin on top, but do not narrow this further: whatever is reported
        // here is already in the past by the time the transaction is validated.
        std::uint64_t blockchain_height = 0;
        if (const expect<db::block_info> last = user->second.get_last_block())
          blockchain_height = std::uint64_t(last->id);
        // get_last_block() has been observed lagging the scanner by well over a
        // thousand blocks, which is fatal here: a registration's collateral is
        // locked relative to this number, and consensus compares it against the
        // daemon's real height, so an understated tip produces a transaction the
        // network relays and then never mines. The account's own scan height is
        // the fresher of the two, so report whichever is further along.
        blockchain_height = std::max(blockchain_height, std::uint64_t(user->first.scan_height));

        // TODO: report the daemon's real fork version here. This was pinned at
        // 17, which silently disabled every client-side gate above it --
        // including the whole HF22 private-token path, since the client tests
        // fork_version >= HF_VERSION_PRIVATE_TOKENS before it will build a
        // token transaction at all. Pinned to 22 so the feature is reachable;
        // it must become dynamic before this serves a real network, or the
        // client will try to build token transactions on a chain that has not
        // forked yet.
        constexpr std::uint64_t PINNED_FORK_VERSION = 22;

        return response{fee_per_byte, fee_per_output, flash_fee_per_byte, flash_fee_per_output,
                        flash_fee_fixed, quantization_mask, PINNED_FORK_VERSION,
                        rpc::safe_uint64(received), std::move(unspent),
                        std::move(req.creds.key), next_min_height, blockchain_height};
      }
    };//get_unspent_outs

    struct get_address_txs
    {
      using request = rpc::get_address_txs_request;
      using response = rpc::get_address_txs_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        // Only an incremental/paginated caller can use the per-spend `height`
        // field; a legacy caller would just pay for the bytes. See write_bytes
        // for transaction_spend.
        const bool incremental = (req.min_height != 0 || req.max_count != 0);

        // For the cumulative `locked_funds` scalar - the same master-node /
        // unlock-time locked amount get_address_info reports, computed here so a
        // client that only makes the cheap incremental get_address_txs call still
        // gets a balance-relevant locked total without the 100+ MB address_info
        // download.
        auto master_node_data = get_master_node_cache();
        if (!master_node_data)
          return master_node_data.error();
        std::unordered_set<crypto::key_image, key_image_hash> locked_processed;

        // Outputs are walked in full even for an incremental request: they feed
        // the cumulative scalars above, and `metas` must cover the whole account
        // so that a spend in a new block can still resolve the (possibly very old)
        // output it consumes.
        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        // Spends, by contrast, are only ever emitted, never aggregated into a
        // scalar here - so an incremental request seeks straight to its cursor and
        // never reads the earlier ones. Safe because `metas` is complete (above).
        auto spends = req.min_height ?
          user->second.get_spends(user->first.id, db::block_id(req.min_height)) :
          user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        response resp{};
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;

        // merge input and output info into a single set of txes.

        auto output = outputs->make_iterator();
        auto spend = spends->make_iterator();

        std::vector<db::output::spend_meta_> metas{};

        resp.transactions.reserve(outputs->count());
        metas.reserve(resp.transactions.capacity());

        db::transaction_link next_output{};
        db::transaction_link next_spend{};

        if (!output.is_end())
          next_output = output.get_value<MONERO_FIELD(db::output, link)>();
        if (!spend.is_end())
          next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();

        while (!output.is_end() || !spend.is_end())
        {
          if (!resp.transactions.empty())
          {
            db::transaction_link const& last = resp.transactions.back().info.link;

            if ((!output.is_end() && next_output < last) || (!spend.is_end() && next_spend < last))
            {
              throw std::logic_error{"DB has unexpected sort order"};
            }
          }

          if (spend.is_end() || (!output.is_end() && next_output <= next_spend))
          {
            // HF22: a privacy-token output's amount is denominated in that
            // token, not BDX. Folding it into the transaction's BDX amount
            // shows a registration of 1000 DEMO (1e15 atomic at 12 decimals)
            // as "+999999.69 BDX" received in the history. Advance past it so
            // the entry reflects only the native value moved.
            if (output.get_value<MONERO_FIELD(db::output, token_id)>() != crypto::public_key{})
            {
              ++output;
              if (!output.is_end())
                next_output = output.get_value<MONERO_FIELD(db::output, link)>();
              continue;
            }

            std::uint64_t amount = 0;
            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_output.tx_hash)
            {
              resp.transactions.push_back({*output});
              amount = resp.transactions.back().info.spend_meta.amount;
            }
            else
            {
              amount = output.get_value<MONERO_FIELD(db::output, spend_meta.amount)>();
              resp.transactions.back().info.spend_meta.amount += amount;
            }

            const db::output::spend_meta_ meta = output.get_value<MONERO_FIELD(db::output, spend_meta)>();
            if (metas.empty() || metas.back().id < meta.id)
              metas.push_back(meta);
            else
              metas.insert(find_metadata(metas, meta.id), meta);

            resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + amount);

            // Cumulative locked_funds - identical logic to get_address_info, so
            // the two endpoints agree. Master-node locked/blacklisted
            // contributions (matched O(1) against the 10s-TTL cache maps) plus
            // outputs still time-locked by unlock_time. This runs over every
            // output regardless of min_height, so the scalar stays cumulative
            // while the transactions array is filtered to the delta below.
            const crypto::key_image locked_key_image =
                output.get_value<MONERO_FIELD(db::output, locked_key_image)>();
            if (locked_key_image != crypto::key_image{} && !locked_processed.count(locked_key_image))
            {
              const auto blacklisted = master_node_data->blacklist_by_image.find(locked_key_image);
              if (blacklisted != master_node_data->blacklist_by_image.end())
              {
                resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + blacklisted->second);
                locked_processed.insert(locked_key_image);
              }
              else
              {
                const auto locked = master_node_data->locked_by_image.find(locked_key_image);
                if (locked != master_node_data->locked_by_image.end())
                {
                  resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + locked->second);
                  locked_processed.insert(locked_key_image);
                }
              }
            }
            if (is_locked(output.get_value<MONERO_FIELD(db::output, unlock_time)>(), user->first.scan_height))
              resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + meta.amount);

            ++output;
            if (!output.is_end())
              next_output = output.get_value<MONERO_FIELD(db::output, link)>();
          }
          else if (output.is_end() || (next_spend < next_output))
          {
            const db::output_id source_id = spend.get_value<MONERO_FIELD(db::spend, source)>();
            const auto meta = find_metadata(metas, source_id);
            if (meta == metas.end() || meta->id != source_id)
            {
              throw std::logic_error{
                "Serious database error, no receive for spend"
              };
            }

            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_spend.tx_hash)
            {
              resp.transactions.push_back({});
              resp.transactions.back().spends.push_back({*meta, *spend, incremental});
              resp.transactions.back().info.link.height = resp.transactions.back().spends.back().possible_spend.link.height;
              resp.transactions.back().info.link.tx_hash = resp.transactions.back().spends.back().possible_spend.link.tx_hash;
              resp.transactions.back().info.spend_meta.mixin_count =
                  resp.transactions.back().spends.back().possible_spend.mixin_count;
              resp.transactions.back().info.timestamp = resp.transactions.back().spends.back().possible_spend.timestamp;
              resp.transactions.back().info.unlock_time = resp.transactions.back().spends.back().possible_spend.unlock_time;
            }
            else
              resp.transactions.back().spends.push_back({*meta, *spend, incremental});

            resp.transactions.back().spent += meta->amount;

            ++spend;
            if (!spend.is_end())
              next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();
          }
        }

        // Incremental fetch: drop the txs below the client's min_height cursor.
        // Only output-derived entries can still be here - the spends cursor was
        // seeked, so no old spend was merged in. Those are filtered after the
        // merge rather than suppressed during it because the loop groups by
        // comparing against `resp.transactions.back()`, and skipping a push
        // mid-merge would mis-group a tx that has both outputs and spends. The
        // vector is built regardless, since the outputs feed the cumulative
        // total_received and locked_funds scalars.
        if (req.min_height != 0)
        {
          auto& txs = resp.transactions;
          txs.erase(
            std::remove_if(
              txs.begin(), txs.end(),
              [min_height = req.min_height](const response::transaction& t)
              {
                return std::uint64_t(t.info.link.height) < min_height;
              }),
            txs.end());
        }

        // Pagination: cap the transactions returned at max_count, extending the
        // last kept block so a block is never split across pages. transactions
        // are height-ascending (merge order, preserved by the filter above), so
        // next_min_height = the first dropped tx's height resumes cleanly. Unlike
        // the other two endpoints this truncates after the full merge - the output
        // walk is structural (it feeds the cumulative scalars), so only the
        // response is bounded here, matching the existing min_height filter.
        if (req.max_count != 0 && resp.transactions.size() > req.max_count)
        {
          auto& txs = resp.transactions;
          std::size_t cut = req.max_count;
          const std::uint64_t boundary_h = std::uint64_t(txs[cut - 1].info.link.height);
          while (cut < txs.size() && std::uint64_t(txs[cut].info.link.height) == boundary_h)
            ++cut; // keep the whole block that straddles the cap
          if (cut < txs.size())
          {
            resp.next_min_height = std::uint64_t(txs[cut].info.link.height);
            txs.erase(txs.begin() + cut, txs.end()); // shrink only (transaction has no default ctor)
          }
        }

        return resp;
      }
    };

    struct get_random_outs
    {
      using request = rpc::get_random_outs_request;
      using response = rpc::get_random_outs_response;

      static expect<response> handle(request req, const db::storage&)
      {
        using distribution_rpc = cryptonote::rpc::GET_OUTPUT_DISTRIBUTION;
        using histogram_rpc = cryptonote::rpc::GET_OUTPUT_HISTOGRAM;
        
        std::vector<std::uint64_t> amounts = std::move(req.amounts.values);

        if (50 < req.count || 20 < amounts.size())
          return {lws::error::exceeded_rest_request_limit};

        const std::greater<std::uint64_t> rsort{};
        std::sort(amounts.begin(), amounts.end(), rsort);
        const std::size_t ringct_count = amounts.end() - std::lower_bound(amounts.begin(), amounts.end(), 0, rsort);
        std::vector<lws::histogram> histograms{};
        if (ringct_count < amounts.size())
        {
          // reuse allocated vector memory
          amounts.resize(amounts.size() - ringct_count);

          histogram_rpc histogram_req{};
          histogram_req.request.amounts = std::move(amounts);
          histogram_req.request.min_count = 0;
          histogram_req.request.max_count = 0;
          histogram_req.request.unlocked = true;
          histogram_req.request.recent_cutoff = 0;

          // epee::byte_slice msg = rpc::client::make_message("get_output_histogram", histogram_req.request);
          // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json histogram_params = {
            {"amounts", histogram_req.request.amounts},
            {"min_count", histogram_req.request.min_count},
            {"max_count", histogram_req.request.max_count},
            {"unlocked", histogram_req.request.unlocked},
            {"recent_cutoff", histogram_req.request.recent_cutoff}
          };
          auto histogram_data = post_json_rpc("get_output_histogram", std::move(histogram_params));
          if (!histogram_data)
            return histogram_data.error();

          json resp = std::move(*histogram_data);
          try
          {
            for (const auto& raw : deep_unwrap(deep_unwrap(resp).at("result")).at("histogram"))
            {
              const json& it = deep_unwrap(raw);
              lws::histogram histogram_resp{};
              histogram_resp.amount         = it.at("amount");
              histogram_resp.total_count    = it.at("total_instances");
              histogram_resp.unlocked_count = it.at("unlocked_instances");
              histogram_resp.recent_count   = it.at("recent_instances");
              histograms.push_back(histogram_resp);
            }
          }
          catch (const std::exception& e)
          {
            MERROR("get_random_outs: unexpected get_output_histogram response: " << e.what()
                   << " -- body: " << resp.dump().substr(0, 400));
            return {lws::error::bad_daemon_response};
          }

          if (histograms.size() != histogram_req.request.amounts.size())
            return {lws::error::bad_daemon_response};

          // histograms = std::move(histogram_resp->histogram);

          amounts = std::move(histogram_req.request.amounts);
          amounts.insert(amounts.end(), ringct_count, 0);
        }

        std::vector<std::uint64_t> distributions{};
        if (ringct_count)
        {
          // std::cout << "print the function " << ringct_count << "\n";
          distribution_rpc distribution_req{};
          if (ringct_count == amounts.size())
            distribution_req.request.amounts = std::move(amounts);

          distribution_req.request.amounts.resize(1);
          distribution_req.request.from_height = 0;
          distribution_req.request.to_height = 0;
          distribution_req.request.cumulative = true;

          //       // epee::byte_slice msg =
          //       //   rpc::client::make_message("get_output_distribution", distribution_req.request);
          //       // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          // The distribution request is constant (amount 0, full cumulative
          // range); served from a short-TTL cache instead of refetching + parsing
          // this large JSON on every get_random_outs.
          auto distribution_data = get_output_distribution_cache();
          if (!distribution_data)
            return distribution_data.error();

          json resp = std::move(*distribution_data);
          try
          {
            const json& dists = deep_unwrap(deep_unwrap(resp).at("result")).at("distributions");
            if (dists.size() != 1)
              return {lws::error::bad_daemon_response};
            const json& dist0 = deep_unwrap(dists.at(0));
            if (dist0.at("amount") != 0)
              return {lws::error::bad_daemon_response};
            for (const auto& it : dist0.at("distribution"))
              distributions.push_back(it.get<std::uint64_t>());
          }
          catch (const std::exception& e)
          {
            MERROR("get_random_outs: unexpected get_output_distribution response: " << e.what()
                   << " -- body: " << resp.dump().substr(0, 400));
            return {lws::error::bad_daemon_response};
          }

          // distributions = std::move(distribution_resp->distributions[0].data.distribution);

          if (amounts.empty())
          {
            amounts = std::move(distribution_req.request.amounts);
            amounts.insert(amounts.end(), ringct_count - 1, 0);
          }
        }

        class zmq_fetch_keys
        {
          /* `std::function` needs a copyable functor. The functor was made
             const and copied in the function instead of using a reference to
             make the callback in `std::function` thread-safe. This shouldn't
             be a problem now, but this is just-in-case of a future refactor. */
          // rpc::client gclient;
        public:
          zmq_fetch_keys() noexcept
          // : gclient(std::move(src))
          {}

          zmq_fetch_keys(zmq_fetch_keys&&) = default;
          zmq_fetch_keys(zmq_fetch_keys const& rhs)
          {}
          //     : gclient(MONERO_UNWRAP(rhs.gclient.clone()))
          //   {}

          expect<std::vector<output_keys>> operator()(std::vector<lws::output_ref> ids) const
          {
            // std::cout <<"operator overload" << std::endl;

            // using get_keys_rpc = cryptonote::rpc::GET_OUTPUTS;

            // get_keys_rpc::request keys_req{};
            // keys_req.outputs = std::move(ids);
            json output_indices;
            int i =0;
            for(auto it :ids)
            {
              output_indices.push_back(it.index);
              i++;
            }
            json out_params = {
              {"output_indices", std::move(output_indices)},
              {"get_txid", false}
            };
            auto out_keys_data = post_json_rpc("get_outs", std::move(out_params));
            if (!out_keys_data)
              return out_keys_data.error();

            json resp = std::move(*out_keys_data);
            using get_keys_rpc = cryptonote::rpc::output_key_mask_unlocked;
            std::vector <get_keys_rpc> keys{};
            try
            {
              for (const auto& raw : deep_unwrap(deep_unwrap(resp).at("result")).at("outs"))
              {
                const json& it = deep_unwrap(raw);
                get_keys_rpc key;
                std::string key_p = it.at("key");
                tools::hex_to_type(key_p, key.key);
                tools::hex_to_type(it.at("mask").get<std::string>(), key.mask);
                key.unlocked = it.at("unlocked");
                // HF22: optional so an older daemon that does not send it still
                // works -- the decoy is then simply treated as native, which is
                // what a null blinded token id means.
                key.blinded_token_id = crypto::null_tid;
                if (const auto btid = it.find("blinded_token_id"); btid != it.end() && btid->is_string())
                  tools::hex_to_type(btid->get<std::string>(), key.blinded_token_id);
                keys.push_back(key);
              }
            }
            catch (const std::exception& e)
            {
              MERROR("get_random_outs: unexpected get_outs response: " << e.what()
                     << " -- body: " << resp.dump().substr(0, 400));
              return {lws::error::bad_daemon_response};
            }
            return {std::move(keys)};
          }
        };

        lws::gamma_picker pick_rct{std::move(distributions)};
        auto rings = pick_random_outputs(
            req.count,
            epee::to_span(amounts),
            pick_rct,
            epee::to_mut_span(histograms),
          zmq_fetch_keys{/*std::move(*client)*/}
        );
        if (!rings)
          return rings.error();

        return response{std::move(*rings)};
      }
    };

    struct import_request
    {
      using request = rpc::account_credentials;
      using response = rpc::import_response;

      static expect<response> handle(request req, db::storage disk)
      {
        bool new_request = false;
        bool fulfilled = false;
        {
          auto user = open_account(req, disk.clone());
          if (!user)
            return user.error();

          if (user->first.start_height == db::block_id(0))
            fulfilled = true;
          else
          {
            const expect<db::request_info> info =
                user->second.get_request(db::request::import_scan, req.address);

            if (!info)
            {
              if (info != lmdb::error(MDB_NOTFOUND))
                return info.error();

              new_request = true;
            }
          }
        } // close reader

        if (new_request)
          MONERO_CHECK(disk.import_request(req.address, db::block_id(0)));

        const char* status = new_request ?
          "Accepted, waiting for approval" : (fulfilled ? "Approved" : "Waiting for Approval");
        return response{rpc::safe_uint64(0), status, new_request, fulfilled};
      }
    };

    struct login
    {
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, db::storage disk)
      {
        // std::cout <<"inside the login\n";
        if (!key_check(req.creds))
          return {lws::error::bad_view_key};

        {
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();

          const auto account = reader->get_account(req.creds.address);
          reader->finish_read();

          if (account)
          {
            if (is_hidden(account->first))
              return {lws::error::account_not_found};

            // Do not count a request for account creation as login
            return response{false, bool(account->second.flags & db::account_generated_locally)};
          }
          else if (!req.create_account || account != lws::error::account_not_found)
            return account.error();
        }

        const auto flags = req.generated_locally ? db::account_generated_locally : db::default_account;
        // MONERO_CHECK(disk.creation_request(req.creds.address, req.creds.key, flags));
        MONERO_UNWRAP(disk.add_account(req.creds.address, req.creds.key));
        // std::cout <<"add_account called\n";
        return response{true, req.generated_locally};
      }
    };//login

    struct submit_raw_tx
    {
      using request = rpc::submit_raw_tx_request;
      using response = rpc::submit_raw_tx_response;

      static expect<response> handle(request req, const db::storage &disk)
      {
        using transaction_rpc = cryptonote::rpc::SUBMIT_TRANSACTION;

        // expect<rpc::client> client = gclient.clone();
        // if (!client)
        //   return client.error();

        transaction_rpc daemon_req{};
        daemon_req.request.tx = std::move(req.tx);
        if(req.fee == "5")
        {
          daemon_req.request.flash = true;
        }else{
          daemon_req.request.flash =false;
        }// Handles Flash Method from Client

        json send_params = {
          {"tx", daemon_req.request.tx},
          {"flash", daemon_req.request.flash}
        };
        auto daemon_data = post_json_rpc("send_raw_transaction", std::move(send_params));
        if (!daemon_data)
          return daemon_data.error();

        json daemon_resp = std::move(*daemon_data);
        try
        {
          const json& result = deep_unwrap(deep_unwrap(daemon_resp).at("result"));
          // A rejected transaction reaches the client as a bare 500 with no
          // body, so the daemon's reason is the only explanation that exists
          // anywhere. Log it before discarding it -- without this a rejection
          // is indistinguishable from a success that never confirms, which is
          // exactly how a failed token registration presents: the wallet shows
          // the transaction optimistically, then it vanishes on refresh.
          const auto log_rejection = [&result, &daemon_resp](const char* what) {
            MERROR("submit_raw_tx " << what
                   << " -- reason: " << result.value("reason", std::string{"(none given)"})
                   << " -- reason_codes: " << result.value("reason_codes", json::array()).dump()
                   << " -- full result: " << result.dump().substr(0, 600));
          };
          if (result.value("not_relayed", false))
          {
            log_rejection("not relayed");
            return {lws::error::tx_relay_failed};
          }
          if (result.value("status", std::string{"OK"}) == "Failed")
          {
            log_rejection("rejected by daemon");
            return {lws::error::status_failed};
          }
        }
        catch (const std::exception& e)
        {
          MERROR("submit_raw_tx: unexpected send_raw_transaction response: " << e.what()
                 << " -- body: " << daemon_resp.dump().substr(0, 400));
          return {lws::error::bad_daemon_response};
        }

        return response{"OK"};
      }
    }; //submit_raw_tx

    template<typename E>
    expect<epee::byte_slice> call(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      using response = typename E::response;

      expect<request> req = wire::json::from_bytes<request>(std::move(root));
      if (!req)
        return req.error();

      expect<response> resp = E::handle(std::move(*req), std::move(disk));
      if (!resp)
        return resp.error();
      return wire::json::to_bytes<response>(*resp);
    }

    // Per-account cache of the fully-serialized get_address_txs response.
    //
    // A light-wallet client re-requests its ENTIRE transaction history on every
    // refresh; get_address_txs takes only credentials (no paging), so for an
    // account with tens of thousands of txs each poll rebuilds and re-serializes
    // the whole history from LMDB - which is what makes large accounts hang.
    //
    // Its response is a pure function of the account's scanned state, the chain
    // tip, and the request's min_height cursor (it reads no master-node cache),
    // so it stays byte-identical until the account scans a new block or the
    // client moves its cursor. Key the cache on (scan_height, last_block,
    // min_height); a hit hands back a clone of the stored byte_slice (an O(1)
    // refcount bump) with no DB reads and no serialization. Invalidation is
    // automatic - the scanner advancing either height, or the client advancing
    // its cursor, changes the key.
    struct address_txs_cache_entry
    {
      db::block_id scan_height;
      db::block_id last_block;
      std::uint64_t min_height;
      std::uint64_t max_count;
      epee::byte_slice bytes;
    };

    expect<epee::byte_slice> call_get_address_txs(std::string&& root, db::storage disk)
    {
      using E = get_address_txs;
      static std::mutex cache_mutex;
      static std::unordered_map<std::uint32_t, address_txs_cache_entry> cache;
      static std::size_t cache_bytes = 0;
      // Bound total cached bytes so many distinct large accounts can't grow
      // memory without limit (a single response larger than this is not cached).
      constexpr const std::size_t cache_max_bytes = 256 * 1024 * 1024;

      expect<E::request> req = wire::json::from_bytes<E::request>(std::move(root));
      if (!req)
        return req.error();

      // Authenticate and read the heights that key the cache. A cache hit is
      // only served after a successful view-key check (open_account).
      auto user = open_account(req->creds, disk.clone());
      if (!user)
        return user.error();

      const std::uint32_t key = static_cast<std::uint32_t>(user->first.id);
      const db::block_id scan_height = user->first.scan_height;
      const std::uint64_t min_height = req->min_height;
      const std::uint64_t max_count = req->max_count;
      const auto last = user->second.get_last_block();
      if (!last)
        return last.error();
      const db::block_id last_block = last->id;
      user->second.finish_read();

      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        const auto it = cache.find(key);
        if (it != cache.end() && it->second.scan_height == scan_height &&
            it->second.last_block == last_block && it->second.min_height == min_height &&
            it->second.max_count == max_count)
          return it->second.bytes.clone();
      }

      expect<E::response> resp = E::handle(*req, std::move(disk));
      if (!resp)
        return resp.error();

      expect<epee::byte_slice> bytes = wire::json::to_bytes<E::response>(*resp);
      if (!bytes)
        return bytes.error();

      const std::size_t sz = bytes->size();
      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        const auto it = cache.find(key);
        if (it != cache.end())
        {
          cache_bytes -= it->second.bytes.size();
          cache.erase(it);
        }
        if (cache_bytes + sz > cache_max_bytes)
        {
          cache.clear();
          cache_bytes = 0;
        }
        if (sz <= cache_max_bytes)
        {
          cache.emplace(key, address_txs_cache_entry{scan_height, last_block, min_height, max_count, bytes->clone()});
          cache_bytes += sz;
        }
      }
      return bytes;
    }

    template<typename T>
    struct admin
    {
      T params;
      crypto::secret_key auth;
    };

    template<typename T>
    void read_bytes(wire::json_reader& source, admin<T>& self)
    {
      wire::object(
        source, wire::field("auth", std::ref(unwrap(unwrap(self.auth)))), WIRE_FIELD(params)
      );
    }
    void read_bytes(wire::json_reader& source, admin<expect<void>>& self)
    {
      // params optional
      wire::object(source, wire::field("auth", std::ref(unwrap(unwrap(self.auth)))));
    }

    template<typename E>
    expect<epee::byte_slice> call_admin(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      const expect<admin<request>> req = wire::json::from_bytes<admin<request>>(std::move(root));
      if (!req)
        return req.error();

      {
        db::account_address address{};
        if (!crypto::secret_key_to_public_key(req->auth, address.view_public))
          return {error::crypto_failure};

        auto reader = disk.start_read();
        if (!reader)
          return reader.error();
        const auto account = reader->get_account(address);
        if (!account)
          return account.error();
        if (account->first == db::account_status::inactive)
          return {error::account_not_found};
        if (!(account->second.flags & db::account_flags::admin_account))
          return {error::account_not_found};
      }

      wire::json_slice_writer dest{};
      MONERO_CHECK(E{}(dest, std::move(disk), req->params));
      return dest.take_bytes();
    }

    struct endpoint
    {
      char const* const name;
      expect<epee::byte_slice> (*const run)(std::string&&, db::storage);
      const unsigned max_size;
    };

    constexpr const endpoint endpoints[] =
        {
      {"/daemon_status",         call<daemon_status>,          1024},
      {"/get_address_info",      call<get_address_info>, 2 * 1024},
      {"/get_address_txs",       call_get_address_txs,   2 * 1024},
      {"/get_random_outs",       call<get_random_outs>,  2 * 1024},
            // {"/get_txt_records",       nullptr,                0       },
      {"/get_unspent_outs",      call<get_unspent_outs>, 2 * 1024},
      {"/import_request",        call<import_request>,   2 * 1024},
      {"/login",                 call<login>,            2 * 1024},
      {"/submit_raw_tx",         call<submit_raw_tx>,   50 * 1024}
    };
    constexpr const endpoint admin_endpoints[] =
    {
      {"/accept_requests",       call_admin<rpc::accept_requests_>, 50 * 1024},
      {"/add_account",           call_admin<rpc::add_account_>,     50 * 1024},
      {"/list_accounts",         call_admin<rpc::list_accounts_>,   100},
      {"/list_requests",         call_admin<rpc::list_requests_>,   100},
      {"/modify_account_status", call_admin<rpc::modify_account_>,  50 * 1024},
      {"/reject_requests",       call_admin<rpc::reject_requests_>, 50 * 1024},
      {"/rescan",                call_admin<rpc::rescan_>,          50 * 1024},
      {"/validate",              call_admin<rpc::validate_>,        50 * 1024}
    };

    struct by_name_
    {
      bool operator()(endpoint const& left, endpoint const& right) const noexcept
      {
        if (left.name && right.name)
          return std::strcmp(left.name, right.name) < 0;
        return false;
      }
      bool operator()(const boost::string_ref left, endpoint const& right) const noexcept
      {
        if (right.name)
          return left < right.name;
        return false;
      }
      bool operator()(endpoint const& left, const boost::string_ref right) const noexcept
      {
        if (left.name)
          return left.name < right;
        return false;
      }
    };
    constexpr const by_name_ by_name{};

  } //anonymous
  struct rest_server::internal final : public lws::http_server_impl_base<rest_server::internal, context>
  {
    db::storage disk;
    boost::optional<std::string> prefix;
    boost::optional<std::string> admin_prefix;


    explicit internal(boost::asio::io_service& io_service, lws::db::storage disk)
      : lws::http_server_impl_base<rest_server::internal, context>(io_service)
      , disk(std::move(disk))
      , prefix()
      , admin_prefix()
    {
      assert(std::is_sorted(std::begin(endpoints), std::end(endpoints), by_name));
    }

    const endpoint* get_endpoint(boost::string_ref uri) const
    {
      using span = epee::span<const endpoint>;
      span handlers = nullptr;

      if (admin_prefix && uri.starts_with(*admin_prefix))
      {
        uri.remove_prefix(admin_prefix->size());
        handlers = span{admin_endpoints};
      }
      else if (prefix && uri.starts_with(*prefix))
      {
        uri.remove_prefix(prefix->size());
        handlers = span{endpoints};
      }
      else
        return nullptr;

      const auto handler = std::lower_bound(
        std::begin(handlers), std::end(handlers), uri, by_name
      );
      if (handler == std::end(handlers) || handler->name != uri)
        return nullptr;
      return handler;
    }

    virtual bool
      handle_http_request(const http::http_request_info& query, http::http_response_info& response, context& ctx)
        override final
    {
     endpoint const* const handler = get_endpoint(query.m_URI);
      if (!handler)
      {
        response.m_response_code = 404;
        response.m_response_comment = "Not Found";
        return true;
      }

      if (handler->run == nullptr)
      {
        response.m_response_code = 501;
        response.m_response_comment = "Not Implemented";
        return true;
      }

      if (handler->max_size < query.m_body.size())
      {
        MINFO("Client exceeded maximum body size (" << handler->max_size << " bytes)");
        response.m_response_code = 400;
        response.m_response_comment = "Bad Request";
        return true;
      }

      if (query.m_http_method != http::http_method_post)
      {
        response.m_response_code = 405;
        response.m_response_comment = "Method Not Allowed";
        return true;
      }

      // \TODO remove copy of json string here :/
      auto body = handler->run(std::string{query.m_body}, disk.clone());
      if (!body)
      {
        MINFO(body.error().message() << " from " << ctx.m_remote_address.str() << " on " << handler->name);

        if (body.error().category() == wire::error::rapidjson_category())
        {
          response.m_response_code = 400;
          response.m_response_comment = "Bad Request";
        }
        else if (body == lws::error::account_not_found || body == lws::error::duplicate_request)
        {
          response.m_response_code = 403;
          response.m_response_comment = "Forbidden";
        }
        else if (body.matches(std::errc::timed_out) || body.matches(std::errc::no_lock_available))
        {
          response.m_response_code = 503;
          response.m_response_comment = "Service Unavailable";
        }
        else
        {
          response.m_response_code = 500;
          response.m_response_comment = "Internal Server Error";
        }
        return true;
      }

      response.m_response_code = 200;
      response.m_response_comment = "OK";
      response.m_mime_tipe = "application/json";
      response.m_header_info.m_content_type = "application/json";

      // Compress large responses when the client advertises gzip. get_address_txs
      // for a big account is hundreds of MB of hex + repetitive JSON that gzips
      // well; this is a pure transfer win and a no-op for clients that do not
      // send Accept-Encoding: gzip.
      //
      // Compress before materializing the plain body: zlib reads straight from the
      // serialized slice, so a compressible response is copied into `m_body` once
      // (compressed) instead of twice (plain, then compressed). Only the
      // uncompressible/non-gzip path pays the plain copy.
      bool body_set = false;
      if (body->size() >= 1024 && client_accepts_gzip(query))
      {
        std::string compressed = gzip_compress(body->data(), body->size());
        if (!compressed.empty() && compressed.size() < body->size())
        {
          response.m_body = std::move(compressed);
          response.m_additional_fields.emplace_back("Content-Encoding", "gzip");
          response.m_additional_fields.emplace_back("Vary", "Accept-Encoding");
          body_set = true;
        }
      }
      if (!body_set)
        response.m_body.assign(reinterpret_cast<const char*>(body->data()), body->size());
      return true;
    }
  };
  rest_server::rest_server(epee::span<const std::string> addresses, std::vector<std::string> admin, db::storage disk, configuration config)
      : io_service_(), ports_()
  {
    if (addresses.empty())
      MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

    std::sort(admin.begin(), admin.end());
    const auto init_port = [&admin] (internal& port, const std::string& address, configuration config, const bool is_admin) -> bool
  
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(address, url))
      MONERO_THROW(lws::error::configuration, "REST server URL/address is invalid");

      const bool https = url.schema == "https";
      if (!https && url.schema != "http")
        MONERO_THROW(lws::error::configuration, "Unsupported scheme, only http or https supported");

      if (std::numeric_limits<std::uint16_t>::max() < url.port)
      MONERO_THROW(lws::error::configuration, "Specified port for REST server is out of range");

      if (!url.uri.empty() && url.uri.front() != '/')
        MONERO_THROW(lws::error::configuration, "First path prefix character must be '/'");


      if (!https)
      {
        boost::system::error_code error{};
        const auto ip_host = boost::asio::ip::make_address(url.host, error);
        if (error)
          MONERO_THROW(lws::error::configuration, "Invalid IP address for REST server");
        if (!ip_host.is_loopback() && !config.allow_external)
          MONERO_THROW(lws::error::configuration, "Binding to external interface with http - consider using https or secure tunnel (ssh, etc). Use --confirm-external-bind to override");
      }

      if (url.port == 0)
        url.port = https ? 8443 : 8080;

      if (!is_admin)
        {
          epee::net_utils::http::url_content admin_url{};
          const boost::string_ref start{address.c_str(), address.rfind(url.uri)};
          while (true) // try to merge 1+ admin prefixes
          {
            const auto mergeable = std::lower_bound(admin.begin(), admin.end(), start);
            if (mergeable == admin.end())
              break;
  
            if (!epee::net_utils::parse_url(*mergeable, admin_url))
              MONERO_THROW(lws::error::configuration, "Admin REST URL/address is invalid");
            if (admin_url.port == 0)
              admin_url.port = https ? 8443 : 8080;
            if (url.host != admin_url.host || url.port != admin_url.port)
              break; // nothing is mergeable
  
            if (port.admin_prefix)
              MONERO_THROW(lws::error::configuration, "Two admin REST servers cannot be merged onto one REST server");
  
            if (url.uri.size() < 2 || admin_url.uri.size() < 2)
              MONERO_THROW(lws::error::configuration, "Cannot merge REST server and admin REST server - a prefix must be specified for both");
            if (admin_url.uri.front() != '/')
              MONERO_THROW(lws::error::configuration, "Admin REST first path prefix character must be '/'");
            if (admin_url.uri != admin_url.m_uri_content.m_path)
              MONERO_THROW(lws::error::configuration, "Admin REST server must have path only prefix");
  
            MINFO("Merging admin and non-admin REST servers: " << address << " + " << *mergeable);
            port.admin_prefix = admin_url.m_uri_content.m_path;
            admin.erase(mergeable);
          } // while multiple mergable admins
        }
  
        if (url.uri != url.m_uri_content.m_path)
          MONERO_THROW(lws::error::configuration, "REST server must have path only prefix");
  
        if (url.uri.size() < 2)
          url.m_uri_content.m_path.clear();
        if (is_admin)
          port.admin_prefix = url.m_uri_content.m_path;
        else
          port.prefix = url.m_uri_content.m_path;
     

      epee::net_utils::ssl_options_t ssl_options = https ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;
      ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
      ssl_options.auth = std::move(config.auth);

      if (!port.init(std::to_string(url.port), std::move(url.host), std::move(config.access_controls), std::move(ssl_options)))
        MONERO_THROW(lws::error::http_server, "REST server failed to initialize");
      return https;
    };

    bool any_ssl = false;

    for (const std::string& address : addresses)
    {
      ports_.emplace_back(io_service_, disk.clone());
      any_ssl |= init_port(ports_.back(), address, config, false);
    }

    for (const std::string& address : admin)
    {
      ports_.emplace_back(io_service_, disk.clone());
      any_ssl |= init_port(ports_.back(), address, config, true);
    }

    const bool expect_ssl = !config.auth.private_key_path.empty();
    const std::size_t threads = config.threads;
    if (!any_ssl && expect_ssl)
      MONERO_THROW(lws::error::configuration, "Specified SSL key/cert without specifying https capable REST server");

    if (!ports_.front().run(threads, false))
      MONERO_THROW(lws::error::http_server, "REST server failed to run");
  }

  rest_server::~rest_server() noexcept
  {
  }
} // lws
