/*! \file backup_main.cpp

    Scheduled hot backups of the LWS database.

    The LWS database had no backup story: the only way to copy it safely was to
    stop the daemon, which contradicts the uptime requirement, and a plain `cp`
    of a live LMDB file can capture a torn page mid-write and produce a copy that
    opens but is subtly corrupt.

    This binary takes a *hot* backup - LMDB's `mdb_env_copy2` with
    `MDB_CP_COMPACT`, which snapshots the database under an internal read
    transaction while the scanner keeps writing. The LWS daemon is never stopped,
    paused or slowed by more than the disk bandwidth the copy consumes.

    Three properties matter and all three are enforced here:

      1. **No downtime.** The source is opened `MDB_RDONLY`, so this process
         never takes the single LMDB writer lock and cannot block the scanner.
         Opening normally would contend for that lock *and* could trigger a
         schema migration against a database owned by another process.

      2. **Directly usable.** The output is a real LMDB environment with the
         same tables, so recovery is `--db-path <backup dir>` with no import,
         replay or conversion step. Every backup is verified by opening it the
         way the daemon would and reading back its contents; a copy that fails
         that check is deleted rather than kept and counted.

      3. **Never a half-backup.** The copy is written to a `.partial` directory
         and renamed only once it has been verified, so an interrupted run
         cannot leave something that looks like a good backup - and cannot cause
         retention to delete a genuinely good one in its favour.

    Because `MDB_CP_COMPACT` writes only live pages, a backup is typically far
    smaller than the source file, which is also why it doubles as the answer to
    a bloated map.
*/

#include <algorithm>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <system_error>
#include <thread>
#include <vector>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "common/fs.h"           // beldex/src
#include "epee/misc_log_ex.h"    // beldex/contrib/epee/include/epee

#include "config.h"
#include "db/storage.h"
#include "error.h"
#include "lmdb/database.h"
#include "options.h"

namespace
{
  //! Prefix for every directory this tool creates; also the retention filter.
  constexpr const char* backup_prefix = "lws-backup-";
  constexpr const char* partial_suffix = ".partial";

  std::atomic<bool> running{true};

  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> backup_path;
    const command_line::arg_descriptor<unsigned> interval_hours;
    const command_line::arg_descriptor<unsigned> keep;
    const command_line::arg_descriptor<bool> once;

    options()
      : lws::options()
      , backup_path{"backup-path", "Directory to write backups into (required)", ""}
      , interval_hours{"interval-hours", "Hours between backups", 24}
      , keep{"keep", "Number of backups to retain; 0 keeps every backup", 7}
      , once{"once", "Take a single backup and exit (for cron/systemd timers)", false}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, backup_path);
      command_line::add_arg(description, interval_hours);
      command_line::add_arg(description, keep);
      command_line::add_arg(description, once);
    }
  };

  struct program
  {
    std::string db_path;
    std::string backup_path;
    std::chrono::seconds interval;
    unsigned keep;
    bool once;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << std::endl;
    out << "Takes consistent backups of a live LWS database without stopping it."
        << std::endl;
    out << "The output is a normal LWS database: recover with --db-path <backup dir>."
        << std::endl;
    out << description;
  }

  program get_program(int argc, char** argv)
  {
    const options opts{};
    boost::program_options::variables_map args{};
    {
      boost::program_options::options_description description{"Options"};
      opts.prepare(description);

      boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv)
          .options(description).run(),
        args
      );
      boost::program_options::notify(args);

      if (command_line::get_arg(args, command_line::arg_help))
      {
        print_help(std::cout);
        throw std::runtime_error{""};
      }
    }

    opts.set_network(args);

    program prog{
      command_line::get_arg(args, opts.db_path),
      command_line::get_arg(args, opts.backup_path),
      std::chrono::seconds{
        std::uint64_t(command_line::get_arg(args, opts.interval_hours)) * 3600},
      command_line::get_arg(args, opts.keep),
      command_line::get_arg(args, opts.once)
    };

    if (prog.backup_path.empty())
      throw std::runtime_error{"--backup-path is required"};
    if (!prog.once && prog.interval.count() == 0)
      throw std::runtime_error{"--interval-hours must be non-zero (or pass --once)"};

    return prog;
  }

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

  std::string as_mib(std::uint64_t bytes)
  {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1)
        << (double(bytes) / (1024.0 * 1024.0)) << " MiB";
    return out.str();
  }

  std::uint64_t dir_size(const fs::path& dir) noexcept
  {
    std::uint64_t total = 0;
    try
    {
      for (fs::directory_iterator i{dir}; i != fs::directory_iterator{}; ++i)
        if (fs::is_regular_file(i->path()))
          total += std::uint64_t(fs::file_size(i->path()));
    }
    catch (...) {}
    return total;
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

  //! Delete oldest backups beyond `keep`. Never touches `.partial` directories.
  void apply_retention(const fs::path& root, unsigned keep)
  {
    if (keep == 0)
      return; // 0 = keep everything

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
        if (name.size() >= std::strlen(partial_suffix) &&
            name.compare(name.size() - std::strlen(partial_suffix),
                         std::strlen(partial_suffix), partial_suffix) == 0)
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
      const std::uint64_t freed = dir_size(backups[i]);
      fs::remove_all(backups[i], ec);
      if (ec)
        MWARNING("retention: failed to delete " << backups[i].string() << ": " << ec.message());
      else
        MGINFO("retention: deleted " << backups[i].filename().string()
               << " (freed " << as_mib(freed) << ")");
    }
  }

  //! \return True if a verified backup was produced.
  bool take_backup(const program& prog)
  {
    const fs::path root{prog.backup_path};
    std::error_code ec{};
    fs::create_directories(root, ec);
    if (ec)
    {
      MERROR("cannot create backup directory " << root.string() << ": " << ec.message());
      return false;
    }

    const std::string stamp = timestamp_now();
    const fs::path final_dir = root / (std::string{backup_prefix} + stamp);
    const fs::path partial_dir = root / (std::string{backup_prefix} + stamp + partial_suffix);

    if (fs::exists(final_dir))
    {
      MWARNING("backup " << final_dir.filename().string() << " already exists, skipping");
      return false;
    }

    fs::remove_all(partial_dir, ec); // clear any debris from a previous crash
    fs::create_directories(partial_dir, ec);
    if (ec)
    {
      MERROR("cannot create " << partial_dir.string() << ": " << ec.message());
      return false;
    }

    const auto started = std::chrono::steady_clock::now();
    MGINFO("starting hot backup of " << prog.db_path << " -> " << final_dir.string());

    {
      /* Read-only open: no writer lock, no migration, cannot modify the source.
         `map_size` is passed as 0 so LMDB adopts the existing file's size rather
         than trying to set one on a database another process owns. */
      auto env = lmdb::open_environment(prog.db_path.c_str(), 20, 0, 1024, true);
      if (!env)
      {
        MERROR("cannot open source database read-only: " << env.error().message());
        fs::remove_all(partial_dir, ec);
        return false;
      }

      lmdb::database source{std::move(*env)};
      const expect<void> copied = source.compact(partial_dir.string().c_str());
      if (!copied)
      {
        MERROR("backup copy failed: " << copied.error().message());
        fs::remove_all(partial_dir, ec);
        return false;
      }
    } // source environment closed before verification

    const auto verified = verify_backup(partial_dir.string());
    if (!verified)
    {
      MERROR("backup failed verification (" << verified.error().message()
             << "); discarding " << partial_dir.string());
      fs::remove_all(partial_dir, ec);
      return false;
    }

    fs::rename(partial_dir, final_dir, ec);
    if (ec)
    {
      MERROR("cannot finalise backup: " << ec.message());
      fs::remove_all(partial_dir, ec);
      return false;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - started);

    MGINFO("backup complete: " << final_dir.filename().string()
           << " (" << as_mib(dir_size(final_dir))
           << ", height " << verified->first
           << ", " << verified->second << " account(s)"
           << ", took " << elapsed.count() << "s)");

    apply_retention(root, prog.keep);
    return true;
  }

  //! Sleep in short slices so a stop signal is honoured promptly.
  void interruptible_wait(std::chrono::seconds total)
  {
    const auto deadline = std::chrono::steady_clock::now() + total;
    while (running && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::seconds{1});
  }

  int run(const program& prog)
  {
    std::signal(SIGINT,  [](int) { running = false; });
    std::signal(SIGTERM, [](int) { running = false; });

    if (prog.once)
      return take_backup(prog) ? 0 : 1;

    MGINFO("backup daemon started: every "
           << (prog.interval.count() / 3600) << "h, keeping "
           << (prog.keep ? std::to_string(prog.keep) : std::string{"all"})
           << " backup(s) in " << prog.backup_path);

    bool any_failed = false;
    while (running)
    {
      if (!take_backup(prog))
        any_failed = true;
      if (!running)
        break;
      interruptible_wait(prog.interval);
    }

    MGINFO("backup daemon stopped");
    return any_failed ? 1 : 0;
  }
} // anonymous

int main(int argc, char** argv)
{
  try
  {
    mlog_configure("", true);
    return run(get_program(argc, argv));
  }
  catch (const std::exception& e)
  {
    if (std::strlen(e.what()) != 0)
    {
      std::cerr << e.what() << std::endl;
      return 1;
    }
    return 0; // --help
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return 1;
  }
}
