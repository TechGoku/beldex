// Reproduction + regression test for the recurring MDB_MAP_FULL.
//
// Claim under test: a reader slot orphaned by a process that died without
// aborting its read transaction stops LMDB reclaiming ANY page freed after that
// snapshot. Write churn then grows the map without bound instead of reusing
// free pages, and the environment eventually returns MDB_MAP_FULL even though
// most of the map is reclaimable garbage. `mdb_reader_check` (exposed here as
// `lmdb::database::check_readers`) sweeps such slots and restores reuse.
//
// The test runs the same insert-then-delete churn three times and compares how
// far `used_bytes` moves:
//
//   Phase A  no orphaned reader                  -> plateaus (pages reused)
//   Phase B  orphaned reader from a SIGKILLed child -> grows (reuse blocked)
//   Phase C  after check_readers()               -> plateaus again
//
// Failing Phase B would mean the diagnosis is wrong. Failing Phase C would mean
// the fix does not work. Both are worth knowing.
//
// Deliberately uses the raw LMDB API for the churn workload rather than the LWS
// schema, so it measures page reclamation itself and cannot be perturbed by
// storage-layer semantics.
//
// Built as `lws-stale-reader-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <lmdb.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lmdb/database.h"
#include "lmdb/error.h"
#include "lmdb/util.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  constexpr const char table_name[] = "churn";
  //! Records per churn cycle. Enough page traffic that blocked reuse is obvious.
  constexpr const unsigned records_per_cycle = 20000;
  //! Bytes per record value; keeps each cycle in the hundreds of KiB.
  constexpr const unsigned value_size = 64;
  constexpr const unsigned cycles_per_phase = 12;
  //! 512 MiB is ample for the churn even with reuse fully blocked.
  constexpr const mdb_size_t map_size = mdb_size_t(512) * 1024 * 1024;

  [[noreturn]] void fail_hard(const std::string& what, int err)
  {
    std::cerr << "fatal: " << what << ": " << mdb_strerror(err) << '\n';
    std::_Exit(2);
  }

  //! One insert-all-then-delete-all cycle. Frees every page it allocated, so a
  //! healthy environment reuses them on the next cycle instead of growing.
  void churn_once(lmdb::database& db, std::uint64_t salt)
  {
    std::vector<char> payload(value_size, char(salt & 0xff));

    // Insert.
    {
      auto txn = db.create_write_txn();
      if (!txn)
        fail_hard("create_write_txn (insert)", 0);

      MDB_dbi dbi{};
      const int rc = mdb_dbi_open(txn->get(), table_name, MDB_CREATE | MDB_INTEGERKEY, &dbi);
      if (rc)
        fail_hard("mdb_dbi_open", rc);

      for (std::uint64_t i = 0; i < records_per_cycle; ++i)
      {
        std::uint64_t key = i;
        MDB_val k{sizeof(key), &key};
        MDB_val v{payload.size(), payload.data()};
        const int put = mdb_put(txn->get(), dbi, &k, &v, 0);
        if (put)
          fail_hard("mdb_put", put);
      }

      const auto committed = db.commit(std::move(*txn));
      if (!committed)
        fail_hard("commit (insert)", 0);
    }

    // Delete, returning every one of those pages to the free list.
    {
      auto txn = db.create_write_txn();
      if (!txn)
        fail_hard("create_write_txn (delete)", 0);

      MDB_dbi dbi{};
      const int rc = mdb_dbi_open(txn->get(), table_name, MDB_INTEGERKEY, &dbi);
      if (rc)
        fail_hard("mdb_dbi_open (delete)", rc);

      for (std::uint64_t i = 0; i < records_per_cycle; ++i)
      {
        std::uint64_t key = i;
        MDB_val k{sizeof(key), &key};
        const int del = mdb_del(txn->get(), dbi, &k, nullptr);
        if (del && del != MDB_NOTFOUND)
          fail_hard("mdb_del", del);
      }

      const auto committed = db.commit(std::move(*txn));
      if (!committed)
        fail_hard("commit (delete)", 0);
    }
  }

  std::uint64_t used_bytes(lmdb::database& db)
  {
    const auto usage = db.get_usage();
    if (!usage)
      fail_hard("get_usage", 0);
    return std::uint64_t(usage->used_bytes);
  }

  //! Run `cycles_per_phase` churn cycles. \return bytes the map grew by.
  std::uint64_t measure_growth(lmdb::database& db, std::uint64_t salt_base)
  {
    const std::uint64_t before = used_bytes(db);
    for (unsigned i = 0; i < cycles_per_phase; ++i)
      churn_once(db, salt_base + i);
    const std::uint64_t after = used_bytes(db);
    return after > before ? after - before : 0;
  }

  /*! Fork a child that opens the same environment, begins a read transaction
      (which claims a reader slot), reports readiness, and then blocks forever.
      The parent SIGKILLs it, so the slot is never released - exactly what a
      crash or an unhandled SIGTERM does to a live LWS. */
  pid_t orphan_a_reader(const std::string& path)
  {
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0)
    {
      std::cerr << "fatal: pipe() failed\n";
      std::_Exit(2);
    }

    const pid_t pid = fork();
    if (pid < 0)
    {
      std::cerr << "fatal: fork() failed\n";
      std::_Exit(2);
    }

    if (pid == 0)
    {
      // Child. Must open its own environment handle - an MDB_env cannot be
      // shared across fork.
      close(fds[0]);

      MDB_env* env = nullptr;
      if (mdb_env_create(&env))
        std::_Exit(3);
      mdb_env_set_maxdbs(env, 20);
      mdb_env_set_mapsize(env, map_size);
      mdb_env_set_maxreaders(env, 64);
      if (mdb_env_open(env, path.c_str(), 0, S_IRUSR | S_IWUSR))
        std::_Exit(3);

      MDB_txn* txn = nullptr;
      if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn)) // claims the slot
        std::_Exit(3);

      // Touch the table so the snapshot is genuinely established.
      MDB_dbi dbi{};
      mdb_dbi_open(txn, table_name, MDB_INTEGERKEY, &dbi);

      const char ready = 'r';
      ssize_t ignored = write(fds[1], &ready, 1);
      (void)ignored;

      for (;;)
        pause(); // hold the read txn open until killed
    }

    // Parent: wait for the child to actually hold the read transaction.
    close(fds[1]);
    char ready = 0;
    const ssize_t got = read(fds[0], &ready, 1);
    close(fds[0]);
    if (got != 1 || ready != 'r')
    {
      std::cerr << "fatal: child failed to open a read transaction\n";
      kill(pid, SIGKILL);
      waitpid(pid, nullptr, 0);
      std::_Exit(2);
    }
    return pid;
  }
}

int main()
{
  const boost::filesystem::path dir =
    boost::filesystem::temp_directory_path() /
    boost::filesystem::unique_path("lws-stale-reader-%%%%%%%%");
  boost::filesystem::create_directories(dir);

  int status = 1;
  try
  {
    auto env = lmdb::open_environment(dir.string().c_str(), 20, map_size, 64);
    if (!env)
      throw std::runtime_error{"open_environment failed"};
    lmdb::database db{std::move(*env)};

    // Warm up so the first phase measures steady-state reuse, not one-off
    // allocation of the table's own structure.
    churn_once(db, 0);
    churn_once(db, 1);

    // ---- Phase A: control, no orphaned reader -------------------------------
    const std::uint64_t growth_clean = measure_growth(db, 100);
    std::cout << "  ..     phase A (no orphaned reader): grew "
              << growth_clean / 1024 << " KiB over " << cycles_per_phase << " cycles\n";

    // ---- Phase B: orphan a reader, then churn -------------------------------
    const pid_t orphan = orphan_a_reader(dir.string());
    kill(orphan, SIGKILL);
    waitpid(orphan, nullptr, 0); // reap, so the PID is unambiguously gone

    {
      const auto usage = db.get_usage();
      check(bool(usage) && 1 <= usage->readers_high_water,
            "a reader slot was claimed by the child before it died");
    }

    const std::uint64_t growth_orphaned = measure_growth(db, 200);
    std::cout << "  ..     phase B (orphaned reader):    grew "
              << growth_orphaned / 1024 << " KiB over " << cycles_per_phase << " cycles\n";

    check(growth_clean * 4 < growth_orphaned,
          "an orphaned reader blocks page reuse (phase B grows far faster than A)");

    // ---- Phase C: sweep the slot, then churn again --------------------------
    const auto cleared = db.check_readers();
    check(bool(cleared) && 1 <= *cleared,
          "check_readers() clears the orphaned slot");
    if (cleared)
      std::cout << "  ..     check_readers() cleared " << *cleared << " slot(s)\n";

    {
      /* NOT a liveness check: `me_numreaders` is a high-water mark that only
         ever increases, so it stays at 1 after the sweep even though the slot
         is now free. Asserting it dropped to 0 would be asserting a bug. That
         the slot really was reclaimed is what phase C below demonstrates. */
      const auto usage = db.get_usage();
      check(bool(usage) && 1 <= usage->readers_high_water,
            "reader high-water mark persists across a sweep (LMDB semantics)");
    }

    const std::uint64_t growth_swept = measure_growth(db, 300);
    std::cout << "  ..     phase C (after sweep):        grew "
              << growth_swept / 1024 << " KiB over " << cycles_per_phase << " cycles\n";

    check(growth_swept * 4 < growth_orphaned,
          "page reuse resumes once the stale slot is cleared");

    // get_usage() should describe a sane environment throughout.
    {
      const auto usage = db.get_usage();
      check(bool(usage) && usage->map_size == map_size, "get_usage reports the map size");
      check(bool(usage) && usage->max_readers == 64, "get_usage reports the reader capacity");
      check(bool(usage) && usage->readers_high_water <= usage->max_readers,
            "reader high-water mark stays within capacity");
      check(bool(usage) && 0 < usage->used_bytes && usage->used_bytes <= usage->map_size,
            "get_usage reports a used size within the map");
    }

    // A sweep with nothing to clear must be harmless.
    const auto none = db.check_readers();
    check(bool(none) && *none == 0, "check_readers() on a clean table is a no-op");

    std::cout << (failures ? "FAILED" : "PASSED") << " (" << failures << " failure(s))\n";
    status = failures ? 1 : 0;
  }
  catch (const std::exception& e)
  {
    std::cerr << "fatal: " << e.what() << '\n';
    status = 2;
  }

  boost::system::error_code ignored;
  boost::filesystem::remove_all(dir, ignored);
  return status;
}
