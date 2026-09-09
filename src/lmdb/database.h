// Copyright (c) 2018, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <cstddef>
#include <lmdb.h>
#include <memory>
#include <type_traits>

#include "common/expect.h"
#include "lmdb/error.h"
#include "lmdb/transaction.h"

namespace lmdb
{
    //! Closes LMDB environment handle.
    struct close_env
    {
        void operator()(MDB_env* ptr) const noexcept
        {
            if (ptr)
                mdb_env_close(ptr);
        }
    };

    using environment = std::unique_ptr<MDB_env, close_env>;

    //! \return LMDB environment at `path` with a max of `max_dbs` tables.
    //! \param map_size Initial memory-map size in bytes; `0` keeps the LMDB
    //!   default (1 MiB). On 64-bit the map is sparse virtual address space, so
    //!   a large value does not preallocate disk - the file grows on demand.
    //! \param max_readers Maximum concurrent reader slots (LMDB default 126).
    /*! \param read_only Open with `MDB_RDONLY`.

        A read-only environment never takes the single writer lock and can never
        modify the source, which is what makes it safe to point at a database a
        live LWS daemon is actively writing to (the backup tool does exactly
        that). Opening normally would block on the writer lock and could trigger
        a schema migration against someone else's database. */
    expect<environment> open_environment(const char* path, MDB_dbi max_dbs, mdb_size_t map_size = 0, unsigned max_readers = 1024, bool read_only = false) noexcept;

    /*! Context given to LMDB.

        Guards map resizing against in-flight transactions: a resize may only run
        when no transaction is active in this process.

        This used to be a raw `std::atomic_flag` spun on with no pause or yield,
        taken on EVERY read and write transaction, with `resize()` holding it
        while busy-waiting for `active` to drain. Under REST concurrency that
        burned CPU on a process-wide serialisation point, and a single long read
        (a large `get_address_txs`) made every other thread spin hot until it
        finished. A mutex + condition variable blocks instead of burning, and
        wakes precisely. */
    struct context
    {
        std::mutex lock;
        std::condition_variable drained;   //!< signalled when `active` hits zero
        std::size_t active = 0;            //!< in-flight transactions
        bool resizing = false;             //!< a resize is pending or running
    };

    //! Manages a LMDB environment for safe memory-map resizing. Thread-safe.
    class database
    {
        environment env;
        context ctx;

        expect<write_txn> do_create_txn(unsigned int flags) noexcept;

    protected:
        /*! \return The LMDB environment associated with the object.

            Protected rather than private so a derived class can run one-shot
            setup that the RAII transaction handles cannot express - notably
            opening table handles inside a read-only transaction that must be
            *committed* rather than aborted, since aborting discards every DBI
            opened in it. */
        MDB_env* handle() const noexcept { return env.get(); }

    public: 
        database(environment env);

        database(database&&) = delete;
        database(database const&) = delete;

        virtual ~database() noexcept;

        database& operator=(database&&) = delete;
        database& operator=(database const&) = delete;

        /*!
            Resize the memory map for the LMDB environment. Will block until
            all reads/writes on the environment complete.
        */
        expect<void> resize() noexcept;

        //! Memory-map and reader-table utilisation, for monitoring.
        struct usage
        {
            mdb_size_t map_size;   //!< Current memory-map size in bytes.
            mdb_size_t used_bytes; //!< Bytes of the map actually in use.
            /*! High-water mark of reader slots used, NOT a live count. LMDB's
                `me_numreaders` only ever increases (see `mti_numreaders`), and
                `check_readers` empties a stale slot without decrementing it, so
                this does not drop when readers finish or are swept. Useful for
                spotting pressure against `max_readers`; use the return value of
                `check_readers` to see stale slots actually reclaimed. */
            unsigned readers_high_water;
            unsigned max_readers;  //!< Reader slot capacity.
        };

        /*!
            Clear reader-table slots whose owning process is no longer alive.

            A read txn that is never aborted - because its process was killed
            (SIGKILL, or SIGTERM with no handler installed, or a crash) - leaves
            its slot in `lock.mdb` holding an old transaction id. LMDB then
            refuses to reuse ANY page freed after that snapshot, for as long as
            the slot survives, so the map grows without bound and eventually
            returns MDB_MAP_FULL even though most of it is reclaimable garbage.
            LMDB only sweeps stale slots itself once the reader table fills
            completely (`max_readers` of them), which is far too late to help.

            Safe to call on a live environment and from any thread: a slot owned
            by a process that is still running - including this one - is never
            touched.

            \return Number of stale slots cleared.
        */
        expect<int> check_readers() noexcept;

        //! \return Current map/reader utilisation, for logging and alerting.
        expect<usage> get_usage() const noexcept;

        //! \return A read only LMDB transaction, reusing `txn` if provided.
        expect<read_txn> create_read_txn(suspended_txn txn = nullptr) noexcept;

        //! \return `txn` after releasing context.
        expect<suspended_txn> reset_txn(read_txn txn) noexcept;

        //! \return A read-write LMDB transaction.
        expect<write_txn> create_write_txn() noexcept;

        //! Commit the read-write transaction.
        expect<void> commit(write_txn txn) noexcept;

        /*!
            Copy this environment, compacting free space out, to `dest_path`.
            Safe to run against a live environment - LMDB takes an internal
            read-txn snapshot for the duration of the copy, so it does not
            block concurrent readers/writers. The result is a separate,
            equivalent DB at `dest_path` for the operator to swap in during a
            maintenance window; this call never touches the live mapped file.
        */
        expect<void> compact(const char* dest_path) const noexcept;

        /*!
            Create a write transaction, pass it to `f`, then try to commit
            the write if `f` succeeds.

            \tparam F must be callable with signature `expect<T>(MDB_txn&)`.
            \param f must be re-startable if `lmdb::error(MDB_MAP_FULL)`.

            \return The result of calling `f`.
        */
        template<typename F>
        typename std::result_of<F(MDB_txn&)>::type try_write(F f, unsigned attempts = 16)
        {
            for (unsigned i = 0; i < attempts; ++i)
            {
                expect<write_txn> txn = create_write_txn();
                if (!txn)
                    return txn.error();

                MONERO_PRECOND(*txn != nullptr);
                auto wrote = f(*(*txn));
                if (wrote)
                {
                    // MDB_MAP_FULL can surface at commit as well as during the
                    // write; grow the map and retry the whole transaction rather
                    // than failing (which would stop the scanner / lose the write).
                    const expect<void> committed = commit(std::move(*txn));
                    if (committed)
                        return wrote;
                    if (committed != lmdb::error(MDB_MAP_FULL))
                        return committed.error();
                    MONERO_CHECK(this->resize());
                    continue;
                }
                if (wrote != lmdb::error(MDB_MAP_FULL))
                    return wrote;

                txn->reset();
                MONERO_CHECK(this->resize());
            }
            return {lmdb::error(MDB_MAP_FULL)};
        }
    };
} // lmdb

