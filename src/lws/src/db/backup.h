#pragma once

/*! \file backup.h

    Verified hot backups of an LWS database.

    Shared deliberately. `beldex-lws-backup` takes these on a timer, and the
    admin `/switch_db` endpoint takes one immediately before it swaps the live
    database - and those two must be the *same* copy-and-verify code. A backup
    path that is only exercised by the scheduled tool is a backup path nobody
    finds out is broken until the day it matters.
*/

#include <chrono>
#include <cstdint>
#include <string>

#include "common/expect.h" // beldex/src

namespace lws
{
namespace db
{
  //! Prefix of every directory the backup code creates; also the retention filter.
  constexpr const char* backup_prefix = "lws-backup-";

  //! Suffix of an in-progress copy, which is never counted as a backup.
  constexpr const char* backup_partial_suffix = ".partial";

  struct backup_result
  {
    std::string path;            //!< Final directory, once verified and renamed.
    std::uint64_t height;        //!< Chain tip read back out of the copy.
    std::size_t accounts;        //!< Active accounts read back out of the copy.
    std::uint64_t bytes;         //!< Size on disk of the finished backup.
    std::chrono::seconds elapsed;
  };

  /*! Take one verified hot backup of the database at `source_path` into `root`.

      The source is opened `MDB_RDONLY` and copied with `mdb_env_copy2` +
      `MDB_CP_COMPACT`, so this never takes the single writer lock and cannot
      block, slow or modify a live server. The copy is written to a `.partial`
      directory, opened and read back exactly as the daemon would open it, and
      renamed only once that succeeds - an interrupted or corrupt run therefore
      cannot leave behind something that looks like a good backup.

      Nothing is deleted here, including on failure beyond the tool's own
      `.partial` debris. Retention is a separate, explicit call.

      \return The finished backup, or the reason it could not be produced. */
  expect<backup_result> take_backup(const std::string& source_path, const std::string& root);

  /*! Delete backups in `root` beyond the newest `keep`.

      \param keep `0` keeps every backup and deletes nothing. `.partial`
        directories are never counted and never removed - counting one could
        push a genuinely good backup out of the retention window. */
  void apply_retention(const std::string& root, unsigned keep);

  //! \return Total size in bytes of the regular files directly under `dir`.
  std::uint64_t dir_size(const std::string& dir) noexcept;

  //! \return `bytes` rendered as e.g. "12.3 MiB".
  std::string as_mib(std::uint64_t bytes);
} // db
} // lws
