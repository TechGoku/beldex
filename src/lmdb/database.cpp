// Copyright (c) 2014-2018, The Monero Project
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
#include "database.h"
#include "lmdb/error.h"
#include "lmdb/util.h"

#ifdef _WIN32
namespace
{
    constexpr const mdb_mode_t open_flags = 0;
}
#else
#include <sys/stat.h>

namespace
{
    constexpr const mdb_mode_t open_flags = (S_IRUSR | S_IWUSR);
}
#endif

namespace lmdb
{
    namespace
    {
        constexpr const mdb_size_t max_resize = 1 * 1024 * 1024 * 1024; // 1 GB
        //! Register an in-flight transaction, waiting out any pending resize.
        void acquire_context(context& ctx) noexcept
        {
            std::unique_lock<std::mutex> guard{ctx.lock};
            ctx.drained.wait(guard, [&ctx] { return !ctx.resizing; });
            ++ctx.active;
        }

        //! Retire a transaction; wakes a waiting resize once the last one goes.
        void release_context(context& ctx) noexcept
        {
            std::unique_lock<std::mutex> guard{ctx.lock};
            if (ctx.active)
                --ctx.active;
            if (ctx.active == 0)
            {
                guard.unlock();
                ctx.drained.notify_all();
            }
        }
    }

    void release_read_txn::operator()(MDB_txn* ptr) const noexcept
    {
        if (ptr)
        {
            MDB_env* const env = mdb_txn_env(ptr);
            abort_txn{}(ptr);
            if (env)
            {
                context* ctx = reinterpret_cast<context*>(mdb_env_get_userctx(env));
                if (ctx)
                    release_context(*ctx);
            }
        }
    }

    expect<environment> open_environment(const char* path, MDB_dbi max_dbs, mdb_size_t map_size, unsigned max_readers, bool read_only) noexcept
    {
        MONERO_PRECOND(path != nullptr);

        MDB_env* obj = nullptr;
        MONERO_LMDB_CHECK(mdb_env_create(std::addressof(obj)));
        environment out{obj};

        MONERO_LMDB_CHECK(mdb_env_set_maxdbs(out.get(), max_dbs));
        // Raise the reader-slot table above LMDB's default of 126. Concurrent
        // read txns come from every REST worker and scan thread plus reused
        // suspended txns; the default can hit MDB_READERS_FULL under load. Must
        // be set before mdb_env_open. Reader slots are cheap (a few KiB total).
        MONERO_LMDB_CHECK(mdb_env_set_maxreaders(out.get(), max_readers));
        // Set an initial map size *before* opening so the first writes have room.
        // Without this the map starts at the 1 MiB LMDB default and a single large
        // write can exhaust the bounded resize-retries in `try_write`, surfacing as
        // MDB_MAP_FULL. The map is sparse on 64-bit; the file only grows on demand.
        if (map_size)
            MONERO_LMDB_CHECK(mdb_env_set_mapsize(out.get(), map_size));
        MONERO_LMDB_CHECK(mdb_env_open(out.get(), path, read_only ? MDB_RDONLY : 0, open_flags));
        return {std::move(out)};
    }

    expect<write_txn> database::do_create_txn(unsigned int flags) noexcept
    {
        MONERO_PRECOND(handle() != nullptr);

        for (unsigned attempts = 0; attempts < 3; ++attempts)
        {
            acquire_context(ctx);

            MDB_txn* txn = nullptr;
            const int err =
                mdb_txn_begin(handle(), nullptr, flags, &txn);
            if (!err && txn != nullptr)
                return write_txn{txn};

            release_context(ctx);
            if (err != MDB_MAP_RESIZED)
                return {lmdb::error(err)};
            MONERO_CHECK(this->resize());
        }
        return {lmdb::error(MDB_MAP_RESIZED)};
    }

    database::database(environment env)
      : env(std::move(env)), ctx{}
    {
        if (handle())
        {
            const int err = mdb_env_set_userctx(handle(), std::addressof(ctx));
            if (err)
                MONERO_THROW(lmdb::error(err), "Failed to set user context");
        }
    }

    database::~database() noexcept
    {
        // Wait for in-flight transactions without spinning.
        std::unique_lock<std::mutex> guard{ctx.lock};
        ctx.drained.wait(guard, [this] { return ctx.active == 0; });
    }

    expect<void> database::resize() noexcept
    {
        MONERO_PRECOND(handle() != nullptr);

        /* Block new transactions, then wait for the in-flight ones to finish.
           LMDB requires no active transactions in this process during
           `mdb_env_set_mapsize`. Both waits are condition-variable based, so
           threads sleep rather than spin. */
        {
            std::unique_lock<std::mutex> guard{ctx.lock};
            ctx.drained.wait(guard, [this] { return !ctx.resizing; });
            ctx.resizing = true;                                  // gate new txns
            ctx.drained.wait(guard, [this] { return ctx.active == 0; });
        }

        MDB_envinfo info{};
        int err = mdb_env_info(handle(), &info);
        if (!err)
        {
            const mdb_size_t resize = std::min(info.me_mapsize, max_resize);
            err = mdb_env_set_mapsize(handle(), info.me_mapsize + resize);
        }

        {
            const std::lock_guard<std::mutex> guard{ctx.lock};
            ctx.resizing = false;
        }
        ctx.drained.notify_all();

        if (err)
            return {lmdb::error(err)};
        return success();
    }

    expect<int> database::check_readers() noexcept
    {
        MONERO_PRECOND(handle() != nullptr);

        // Only clears slots whose owning PID is gone; slots held by live
        // processes (this one included) are left alone, so this is safe to run
        // against a busy environment.
        int dead = 0;
        MONERO_LMDB_CHECK(mdb_reader_check(handle(), &dead));
        return dead;
    }

    expect<database::usage> database::get_usage() const noexcept
    {
        MONERO_PRECOND(handle() != nullptr);

        MDB_envinfo info{};
        MDB_stat stat{};
        MONERO_LMDB_CHECK(mdb_env_info(handle(), &info));
        MONERO_LMDB_CHECK(mdb_env_stat(handle(), &stat));

        usage out{};
        out.map_size = info.me_mapsize;
        // `me_last_pgno` is the highest allocated page number and is 0-based,
        // so the used byte count is (last + 1) pages.
        out.used_bytes = mdb_size_t(info.me_last_pgno + 1) * mdb_size_t(stat.ms_psize);
        out.readers_high_water = info.me_numreaders;
        out.max_readers = info.me_maxreaders;
        return out;
    }

    expect<read_txn> database::create_read_txn(suspended_txn txn) noexcept
    {
        if (txn)
        {
            acquire_context(ctx);
            const int err = mdb_txn_renew(txn.get());
            if (err)
            {
                release_context(ctx);
                return {lmdb::error(err)};
            }
            return read_txn{txn.release()};
        }
        auto new_txn = do_create_txn(MDB_RDONLY);
        if (new_txn)
            return read_txn{new_txn->release()};
        return new_txn.error();
    }

    expect<suspended_txn> database::reset_txn(read_txn txn) noexcept
    {
        MONERO_PRECOND(txn != nullptr);
        mdb_txn_reset(txn.get());
        release_context(ctx);
        return suspended_txn{txn.release()};
    }

    expect<write_txn> database::create_write_txn() noexcept
    {
        return do_create_txn(0);
    }

    expect<void> database::commit(write_txn txn) noexcept
    {
        MONERO_PRECOND(txn != nullptr);
        // `mdb_txn_commit` frees the txn handle on *both* success and failure, so
        // release ownership first to avoid a double-free via `abort_write_txn`
        // (the previous code aborted an already-freed handle when commit failed,
        // e.g. on MDB_MAP_FULL). The context is always released.
        const int err = mdb_txn_commit(txn.release());
        release_context(ctx);
        if (err)
            return {lmdb::error(err)};
        return success();
    }

    expect<void> database::compact(const char* dest_path) const noexcept
    {
        MONERO_PRECOND(handle() != nullptr);
        MONERO_PRECOND(dest_path != nullptr);
        MONERO_LMDB_CHECK(mdb_env_copy2(handle(), dest_path, MDB_CP_COMPACT));
        return success();
    }
} // lmdb
