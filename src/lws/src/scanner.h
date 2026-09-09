#pragma once

#include <atomic>
#include <chrono>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include "db/storage.h"
#include "db/data.h"
#include "rpc/client.h"

namespace lws
{
    class scanner
    {
        static std::atomic<bool> running;
        scanner() = delete;

    public:

        /*! Use `client` to sync blockchain data.
            \return False if the sync failed (daemon unreachable or a bad
            response), so a caller with several endpoints can fail over. */
        static bool sync(db::storage disk,std::string daemon_rpc);

        //! Poll daemon until `stop()` is called, using `thread_count` threads.
        static void run(db::storage disk, std::string daemon_rpc,std::size_t thread_count);

        /*! As above, but rotates through `daemon_rpcs` (primary first) whenever a
            scan pass aborts immediately - i.e. when the daemon it was talking to
            is unreachable. A single-entry list behaves exactly like the overload
            above.

            \param spread Fan the scan threads out across every endpoint instead
              of pointing them all at the current one. Only worth enabling when
              accounts sit at genuinely different heights - see the note in
              scanner.cpp. */
        static void run(db::storage disk, std::vector<std::string> daemon_rpcs, std::size_t thread_count, bool spread = false);

        /*! Hand the scanner a different database to scan, without stopping it.

            Used by the admin `/switch_db` endpoint to move a running server
            onto a database rebuilt by `beldex-lws-rebuild`. The swap is picked
            up between scan passes: `check_loop` returns as soon as one is
            pending (the same path an account-set change already uses), the
            thread group is joined, and the next pass loads its accounts from
            the new database. Nothing is dropped - the outgoing threads finish
            and commit their current batch to the old database first.

            The handle passed here is owned by the scanner once it is picked up.

            \note Not a rollback of in-flight work: the caller is responsible
              for having verified the incoming database is complete. */
        static void swap_storage(db::storage disk);

        /*! Set how long account-set changes are coalesced before the scan
            threads restart to pick them up.

            Raise it for bulk work. A restart reloads every account whose
            `scan_height` moved since the last pass, and during a rebuild that
            is all of them - so on a server that auto-accepts signups, the
            default 30s window means restarting (and reloading) continuously.
            Lowering it only makes new accounts start scanning sooner. */
        static void set_change_coalesce(std::chrono::seconds window) noexcept;

        //! \return True if a `swap_storage` handle is waiting to be picked up.
        static bool swap_pending() noexcept;

        //! \return True if `stop()` has never been called.
        static bool is_running() noexcept { return running; }

        //! Stops all scanner instances globally.
        static void stop() noexcept { std::cout << "STOP_ACTION called" << std::endl;running = false; }
    };

} //lws