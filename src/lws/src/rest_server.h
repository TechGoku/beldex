#pragma once

#include <boost/asio/io_service.hpp>
#include <cstddef>
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