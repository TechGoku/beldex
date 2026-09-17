/*! \file backup_main.cpp

    Scheduled hot backups of the LWS database.

    The LWS database had no backup story: the only way to copy it safely was to
    stop the daemon, which contradicts the uptime requirement, and a plain `cp`
    of a live LMDB file can capture a torn page mid-write and produce a copy that
    opens but is subtly corrupt.

    This binary takes a *hot* backup on a timer. The copy, the verification and
    the retention rules all live in `db/backup.cpp`, because the admin
    `/switch_db` endpoint takes exactly the same kind of backup immediately
    before it swaps the live database - and a backup path exercised by only one
    of its two callers is one nobody finds out is broken until it matters.

    See `db/backup.h` for the guarantees: no downtime, directly usable output,
    and never a half-backup.
*/

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "common/fs.h"           // beldex/src
#include "epee/misc_log_ex.h"    // beldex/contrib/epee/include/epee

#include "config.h"
#include "db/backup.h"
#include "options.h"

namespace
{
  std::atomic<bool> running{true};

  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> backup_path;
    const command_line::arg_descriptor<unsigned> interval_hours;
    const command_line::arg_descriptor<unsigned> keep;
    const command_line::arg_descriptor<bool> once;

    options()
      : lws::options()
      , backup_path{"backup-path", "Where to write backups (required)", ""}
      , interval_hours{"interval-hours", "Hours between backups", 24}
      , keep{"keep", "How many to keep; 0 deletes nothing", 7}
      , once{"once", "Take one backup and exit", false}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);

      boost::program_options::options_description backup{"Backup"};
      command_line::add_arg(backup, backup_path);
      command_line::add_arg(backup, once);
      command_line::add_arg(backup, interval_hours);
      command_line::add_arg(backup, keep);
      description.add(backup);
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
    boost::program_options::options_description description{};
    options{}.prepare(description);

    out <<
      "beldex-lws-backup - hot backups of a live light wallet server database\n"
      "\n"
      "Usage:\n"
      "  beldex-lws-backup --db-path <live db> --backup-path <dir> [options]\n"
      "\n"
      "Copies the database while the server keeps running. The source is opened\n"
      "read-only, so it never takes the writer lock. Each copy is verified\n"
      "before it counts as a backup.\n"
      << description <<
      "\n"
      "The result is an ordinary LWS database: recover with --db-path <backup>.\n"
      "--keep only deletes once a NEW backup has been verified.\n"
      "\n"
      "Setup, examples and procedures: src/lws/lightwallet_server.md\n";
  }

  program get_program(int argc, char** argv)
  {
    const options opts{};
    boost::program_options::variables_map args{};
    {
      boost::program_options::options_description description{};
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

  //! \return True if a verified backup was produced.
  bool take_one(const program& prog)
  {
    const expect<lws::db::backup_result> result =
      lws::db::take_backup(prog.db_path, prog.backup_path);
    if (!result)
      return false;

    // Retention runs only after a good backup exists, so a failing run can
    // never be the reason an older, good backup is deleted.
    lws::db::apply_retention(prog.backup_path, prog.keep);
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
      return take_one(prog) ? 0 : 1;

    MGINFO("backup daemon started: every "
           << (prog.interval.count() / 3600) << "h, keeping "
           << (prog.keep ? std::to_string(prog.keep) : std::string{"all"})
           << " backup(s) in " << prog.backup_path);

    bool any_failed = false;
    while (running)
    {
      if (!take_one(prog))
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
