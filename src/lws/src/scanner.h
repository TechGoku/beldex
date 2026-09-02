#pragma once

#include <atomic>
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
            above. */
        static void run(db::storage disk, std::vector<std::string> daemon_rpcs, std::size_t thread_count);

        //! \return True if `stop()` has never been called.
        static bool is_running() noexcept { return running; }

        //! Stops all scanner instances globally.
        static void stop() noexcept { std::cout << "STOP_ACTION called" << std::endl;running = false; }
    };

} //lws