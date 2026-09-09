/*! \file backup.cpp

    Implementation of the verified hot backup; see backup.h for why this is
    shared between `beldex-lws-backup` and the admin `/switch_db` endpoint.
*/

#include "db/backup.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <vector>

#include "common/fs.h"        // beldex/src
#include "epee/misc_log_ex.h" // beldex/contrib/epee/include/epee

#include "db/storage.h"
#include "error.h"
#include "lmdb/database.h"

namespace lws
{
namespace db
{
  namespace
  {
    //! UTC timestamp, sortable lexicographically so retention can sort by name.
    std::string timestamp_now()
    {
      const std::time_t now = std::time(nullptr);
      std::tm tm{};
#ifdef _WIN32
      gmtime_s(&tm, &now);
#else
      gmtime_r(&now, &tm);
#endif
      std::ostringstream out;
      out << std::put_time(&tm, "%Y%m%d-%H%M%S");
      return out.str();
    }

    /*! Open `path` exactly as the daemon would and read it back.

        This is the check that makes a backup trustworthy rather than merely
        present: a file that exists proves nothing, whereas opening the copy
        through the same `storage::open` the daemon uses - and reading the chain
        tip and the account table out of it - proves the daemon can actually
        recover from it. */
    expect<std::pair<std::uint64_t, std::size_t>> verify_backup(const std::string& path)
    {
      try
      {
        lws::db::storage disk = lws::db::storage::open(path.c_str(), 0);

        auto reader = disk.start_read();
        if (!reader)
          return reader.error();

        std::uint64_t height = 0;
        const auto last = reader->get_last_block();
        if (last)
          height = std::uint64_t(last->id);

        std::size_t accounts = 0;
        auto active = reader->get_accounts(lws::db::account_status::active);
        if (!active)
          return active.error();
        for (auto user = active->make_iterator(); !user.is_end(); ++user)
          ++accounts;

        reader->finish_read();
        return {std::make_pair(height, accounts)};
      }
      catch (const std::exception& e)
      {
        MERROR("backup verification threw: " << e.what());
        return {lws::error::bad_blockchain};
      }
    }
  } // anonymous

  std::uint64_t dir_size(const std::string& dir) noexcept
  {
    std::uint64_t total = 0;
    try
    {
      for (fs::directory_iterator i{fs::path{dir}}; i != fs::directory_iterator{}; ++i)
        if (fs::is_regular_file(i->path()))
          total += std::uint64_t(fs::file_size(i->path()));
    }
    catch (...) {}
    return total;
  }

  std::string as_mib(std::uint64_t bytes)
  {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1)
        << (double(bytes) / (1024.0 * 1024.0)) << " MiB";
    return out.str();
  }

  expect<backup_result> take_backup(const std::string& source_path, const std::string& root_path)
  {
    const fs::path root{root_path};
    std::error_code ec{};
    fs::create_directories(root, ec);
    if (ec)
    {
      MERROR("cannot create backup directory " << root_path << ": " << ec.message());
      return {lws::error::configuration};
    }

    const std::string stamp = timestamp_now();
    const fs::path final_dir = root / (std::string{backup_prefix} + stamp);
    const fs::path partial_dir =
      root / (std::string{backup_prefix} + stamp + backup_partial_suffix);

    if (fs::exists(final_dir))
    {
      MWARNING("backup " << final_dir.filename().string() << " already exists, skipping");
      return {lws::error::configuration};
    }

    fs::remove_all(partial_dir, ec); // clear any debris from a previous crash
    fs::create_directories(partial_dir, ec);
    if (ec)
    {
      MERROR("cannot create " << partial_dir.string() << ": " << ec.message());
      return {lws::error::configuration};
    }

    const auto started = std::chrono::steady_clock::now();
    MGINFO("starting hot backup of " << source_path << " -> " << final_dir.string());

    {
      /* Read-only open: no writer lock, no migration, cannot modify the source.
         `map_size` is passed as 0 so LMDB adopts the existing file's size rather
         than trying to set one on a database another process owns. */
      auto env = lmdb::open_environment(source_path.c_str(), 20, 0, 1024, true);
      if (!env)
      {
        MERROR("cannot open source database read-only: " << env.error().message());
        fs::remove_all(partial_dir, ec);
        return env.error();
      }

      lmdb::database source{std::move(*env)};
      const expect<void> copied = source.compact(partial_dir.string().c_str());
      if (!copied)
      {
        MERROR("backup copy failed: " << copied.error().message());
        fs::remove_all(partial_dir, ec);
        return copied.error();
      }
    } // source environment closed before verification

    const auto verified = verify_backup(partial_dir.string());
    if (!verified)
    {
      MERROR("backup failed verification (" << verified.error().message()
             << "); discarding " << partial_dir.string());
      fs::remove_all(partial_dir, ec);
      return verified.error();
    }

    fs::rename(partial_dir, final_dir, ec);
    if (ec)
    {
      MERROR("cannot finalise backup: " << ec.message());
      fs::remove_all(partial_dir, ec);
      return {lws::error::configuration};
    }

    backup_result result{};
    result.path = final_dir.string();
    result.height = verified->first;
    result.accounts = verified->second;
    result.bytes = dir_size(result.path);
    result.elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - started);

    MGINFO("backup complete: " << final_dir.filename().string()
           << " (" << as_mib(result.bytes)
           << ", height " << result.height
           << ", " << result.accounts << " account(s)"
           << ", took " << result.elapsed.count() << "s)");

    return result;
  }

  void apply_retention(const std::string& root_path, unsigned keep)
  {
    if (keep == 0)
      return; // 0 = keep everything

    const fs::path root{root_path};
    std::vector<fs::path> backups;
    try
    {
      for (fs::directory_iterator i{root}; i != fs::directory_iterator{}; ++i)
      {
        const std::string name = i->path().filename().string();
        if (name.rfind(backup_prefix, 0) != 0)
          continue;
        // A partial is not a backup and must never be counted as one, or a
        // crashed run could push a good backup out of the retention window.
        const std::size_t suffix_len = std::strlen(backup_partial_suffix);
        if (name.size() >= suffix_len &&
            name.compare(name.size() - suffix_len, suffix_len, backup_partial_suffix) == 0)
          continue;
        if (fs::is_directory(i->path()))
          backups.push_back(i->path());
      }
    }
    catch (const std::exception& e)
    {
      MWARNING("retention scan failed: " << e.what());
      return;
    }

    // Names are UTC timestamps, so lexicographic order is chronological.
    std::sort(backups.begin(), backups.end(),
              [](const fs::path& l, const fs::path& r)
              { return l.filename().string() < r.filename().string(); });

    if (backups.size() <= keep)
    {
      MINFO("retention: " << backups.size() << "/" << keep << " backup(s) kept");
      return;
    }

    const std::size_t remove_count = backups.size() - keep;
    for (std::size_t i = 0; i < remove_count; ++i)
    {
      std::error_code ec{};
      const std::uint64_t freed = dir_size(backups[i].string());
      fs::remove_all(backups[i], ec);
      if (ec)
        MWARNING("retention: failed to delete " << backups[i].string() << ": " << ec.message());
      else
        MGINFO("retention: deleted " << backups[i].filename().string()
               << " (freed " << as_mib(freed) << ")");
    }
  }
} // db
} // lws
