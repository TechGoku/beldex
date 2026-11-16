#pragma once

#include <boost/asio/io_service.hpp>
#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <vector>

#include "db/storage.h"
#include "rpc/client.h"
#include "epee/span.h"

#include "epee/net/http_base.h"             // beldex/contrib/epee/include
#include "epee/net/net_parse_helpers.h"     // beldex/contrib/epee/include
#include "epee/net/net_ssl.h"               // beldex/contrib/epee/include

namespace lws
{
    /*! Primary daemon JSON-RPC endpoint. Kept as the first entry of
        `daemon_pool` and still read directly where a single URL is wanted for
        logging. */
    inline std::string daemon_add;

    /*! Every daemon JSON-RPC endpoint this server may talk to, primary first.

        A single hardcoded endpoint made beldexd a single point of failure for
        the whole wallet backend: one daemon restart, and every balance query
        for every user failed until it came back. Populated from `--daemon` plus
        `--daemon-backup`; with no backups configured this holds exactly one
        entry and behaves as before. */
    inline std::vector<std::string> daemon_pool;

    /*! Ceiling for EACH of the two per-account response caches, in bytes.

        Was a hardcoded 256 MB total across all accounts, which is a sensible
        figure for a few thousand accounts and a rounding error for a few
        hundred thousand - past that the hit rate collapses to zero and every
        request rebuilds its response from LMDB. Operators sizing a box for a
        large population need this to be a knob (`--rest-cache-bytes`). */
    inline std::size_t rest_cache_max_bytes = 256 * 1024 * 1024;

    /*! Ceiling on the number of accounts `/login` may create (`--max-accounts`).
        `0`, the default, means no ceiling.

        `/login` with `create_account` registers an address immediately and
        the request costs the caller nothing, while every account is scanned
        against every transaction from then on. Without a ceiling, anyone who
        can reach the port can grow that cost, and the database, without
        bound. Accounts added by an admin are not subject to it. */
    inline std::uint64_t max_accounts = 0;

    /*! Accounts one client address may create per hour through `/login`
        (`--signup-rate-limit`). `0`, the default, means unlimited.

        Counted per connecting address (per /64 for IPv6). Behind a reverse
        proxy every client arrives from the proxy's address and would share
        one allowance, so limit signups at the proxy there instead. */
    inline unsigned signup_rate_limit = 0;

    /*! Most REST threads that may be waiting on the daemon at once for
        endpoints anyone can call without a view key (`/daemon_status`,
        `/get_token_info`, `/get_token_list`). `0` means unlimited.

        Each of those makes a live daemon call with a 30-second timeout on a
        REST worker thread, and there are only a handful of threads. Without
        a ceiling a few clients looping on them could hold every thread and
        stall every wallet. `beldex-lws-daemon` sets this to one less than
        `--rest-threads` unless `--public-lookup-threads` says otherwise, so
        at least one thread is always left for everything else. */
    inline std::size_t public_lookup_slots = 0;
    class rest_server
    {
        struct internal;
        boost::asio::io_service io_service_;
        std::list<internal> ports_;
    public:
        struct configuration
        {
            epee::net_utils::ssl_authentication_t auth;
            std::vector<std::string> access_controls;
            std::size_t threads;
            bool allow_external;
            /*! Refuse responses larger than this, in bytes. `0` (the default)
                means unlimited, which is the historical behaviour.

                Opt-in on purpose: existing clients - including the shipped WASM
                wallet - never send `max_count`, so they always request an
                account's FULL history. A cap enabled by default would silently
                truncate them. Operators who need the memory ceiling can set it. */
            std::size_t max_response_bytes;
            /*! Directory of the database this server starts on.

                Needed because a `db::storage` handle does not remember where it
                came from, and `/switch_db` has to know what it is switching
                *away* from - both to back it up first and to report it. */
            std::string db_path;
            /*! How the database was opened, so `/switch_db` can open the
                incoming one the same way.

                Opening the new database with defaults instead would silently
                change the server's behaviour at the moment of the switch - most
                sharply `create_queue_max`, where a default of 0 rejects every
                `/login` that would register a new account. */
            unsigned create_queue_max;
            std::uint64_t db_map_size;
            unsigned db_max_readers;
        }; //configre

        explicit rest_server(epee::span<const std::string> addresses, std::vector<std::string> admin, db::storage disk, configuration config);

        rest_server(epee::span<const std::string> addresses, db::storage disk, configuration config);

        rest_server(rest_server&&) = delete;
        rest_server(rest_server const&) = delete;

        ~rest_server() noexcept;

        rest_server& operator=(rest_server&&) = delete;
        rest_server& operator=(rest_server const&) = delete;
    }; //rest_server


} //lws