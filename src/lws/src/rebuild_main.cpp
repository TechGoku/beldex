/*! \file rebuild_main.cpp

    Rebuild the LWS database from chain, in parallel, while the live server
    keeps running.

    A rescan or a rollback used to mean an outage. `rescan` only lowers an
    account's `scan_height`, so the running scanner picks it up - and because
    scan threads are grouped by height and a group is driven from its LOWEST
    member, one rescanning account dragged every account grouped with it back
    down with it. `rollback` is worse: it deletes every block above the target
    plus every affected account's outputs and spends inside a single write
    transaction, holding the one LMDB writer lock for as long as that takes.
    With 50k accounts neither is something you can do on a live server.

    This binary sidesteps both by never touching the live database. It builds a
    *second* database - the shadow - in its own LMDB environment:

      * Its own environment means its own writer lock. Nothing it does can
        block, slow or stall the live scanner.
      * Its own `--daemon` endpoints mean it need not compete with the live
        server for beldexd either.
      * The live database is opened `MDB_RDONLY` and is never written.

    The shadow starts with no outputs, spends or images at all, so every row in
    it is rebuilt from the chain. That is what makes this a true rescan rather
    than a top-up: a wrong row cannot survive, because nothing is carried over
    except the account list itself.

    Accounts registered on the live server while the rebuild runs are picked up
    by the sync loop and seeded into the shadow at their own start height, so a
    rebuild that takes hours does not miss the people who signed up during it.

    When the shadow has caught up, the live daemon is pointed at it with the
    admin `/switch_db` endpoint, which swaps the database under the running
    process without closing a socket.

    Nothing here ever deletes anything. Re-running against an existing shadow
    resumes it; it refuses to touch a directory it did not create.
*/

#include <algorithm>
#include <atomic>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/thread/thread.hpp>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "common/fs.h"           // beldex/src
#include "epee/misc_log_ex.h"    // beldex/contrib/epee/include/epee

#include "config.h"
#include "db/account.h"
#include "db/data.h"
#include "db/storage.h"
#include "db/string.h"
#include "error.h"
#include "options.h"
#include "scanner.h"

namespace
{
  //! Written into the shadow directory so a resume can prove the DB is ours.
  constexpr const char* marker_name = "lws-rebuild.json";
  constexpr const unsigned marker_version = 1;

  std::atomic<bool> running{true};

  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> shadow_path;
    const command_line::arg_descriptor<std::uint64_t> rescan_height;
    const command_line::arg_descriptor<std::string> daemon_rpc;
    const command_line::arg_descriptor<std::string> daemon_backup;
    const command_line::arg_descriptor<bool> daemon_spread;
    const command_line::arg_descriptor<std::size_t> scan_threads;
    const command_line::arg_descriptor<unsigned> sync_interval;
    const command_line::arg_descriptor<unsigned> restart_coalesce;
    const command_line::arg_descriptor<bool> status;

    options()
      : lws::options()
      , shadow_path{"shadow-path", "Directory for the rebuilt database (required)", ""}
      , rescan_height{"rescan-height", "Height every account is rebuilt from; 0 rebuilds from the start of each account", 0}
      , daemon_rpc{"daemon", "[(https|http)://<address>:]<port> of the beldexd this rebuild scans against", ""}
      , daemon_backup{"daemon-backup", "Comma-separated additional beldexd endpoints to fail over to", ""}
      , daemon_spread{"daemon-spread", "Fan scan threads across every endpoint. Worth enabling here: during a rebuild accounts genuinely sit at different heights", false}
      , scan_threads{"scan-threads", "Threads for the rebuild scan; independent of the live server's", boost::thread::hardware_concurrency()}
      , sync_interval{"sync-interval", "Seconds between polls of the live DB for newly registered accounts", 30}
      /* Deliberately far higher than the daemon's 30s. Adding an account
         restarts the scan threads, and a restart reloads every account whose
         scan height moved - during a rebuild, all of them. A server that
         auto-accepts signups always has a change pending, so a short window
         here means restarting and reloading continuously instead of scanning.
         New accounts still arrive well before the switch, which is the only
         deadline that matters: `/switch_db` refuses if any is missing. */
      , restart_coalesce{"restart-coalesce", "Seconds to batch newly seeded accounts before restarting the rebuild scan threads", 900}
      , status{"status", "Print rebuild progress and exit", false}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, shadow_path);
      command_line::add_arg(description, rescan_height);
      command_line::add_arg(description, daemon_rpc);
      command_line::add_arg(description, daemon_backup);
      command_line::add_arg(description, daemon_spread);
      command_line::add_arg(description, scan_threads);
      command_line::add_arg(description, sync_interval);
      command_line::add_arg(description, restart_coalesce);
      command_line::add_arg(description, status);
    }
  };

  struct program
  {
    std::string db_path;
    std::string shadow_path;
    std::uint64_t rescan_height;
    std::vector<std::string> daemon_rpcs;
    std::size_t scan_threads;
    std::chrono::seconds sync_interval;
    std::chrono::seconds restart_coalesce;
    bool daemon_spread;
    bool status_only;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << std::endl;
    out << "Rebuilds the LWS database from chain into --shadow-path while the live" << std::endl;
    out << "server at --db-path keeps running and serving. The live database is" << std::endl;
    out << "opened read-only and is never modified." << std::endl;
    out << std::endl;
    out << "When the shadow has caught up, switch the running daemon onto it with" << std::endl;
    out << "the admin /switch_db endpoint. Nothing is ever deleted by this tool." << std::endl;
    out << description;
  }

  //! Split a comma separated endpoint list, dropping blanks and duplicates.
  void append_endpoints(std::vector<std::string>& out, const std::string& list)
  {
    std::size_t pos = 0;
    while (pos <= list.size() && !list.empty())
    {
      const std::size_t comma = list.find(',', pos);
      std::string entry =
        list.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);

      while (!entry.empty() && std::isspace(static_cast<unsigned char>(entry.front())))
        entry.erase(entry.begin());
      while (!entry.empty() && std::isspace(static_cast<unsigned char>(entry.back())))
        entry.pop_back();

      if (!entry.empty() && std::find(out.begin(), out.end(), entry) == out.end())
        out.push_back(std::move(entry));

      if (comma == std::string::npos)
        break;
      pos = comma + 1;
    }
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

    program prog{};
    prog.db_path = command_line::get_arg(args, opts.db_path);
    prog.shadow_path = command_line::get_arg(args, opts.shadow_path);
    prog.rescan_height = command_line::get_arg(args, opts.rescan_height);
    prog.scan_threads = std::max(std::size_t(1), command_line::get_arg(args, opts.scan_threads));
    prog.sync_interval = std::chrono::seconds{command_line::get_arg(args, opts.sync_interval)};
    prog.restart_coalesce =
      std::chrono::seconds{command_line::get_arg(args, opts.restart_coalesce)};
    prog.daemon_spread = command_line::get_arg(args, opts.daemon_spread);
    prog.status_only = command_line::get_arg(args, opts.status);

    if (prog.shadow_path.empty())
      throw std::runtime_error{"--shadow-path is required"};

    /* Rebuilding into the live directory would defeat the entire point: the
       two environments must be independent for the writer locks to be
       independent. Compare canonical paths so `db/` and `db/.` cannot slip
       through. */
    {
      std::error_code ec{};
      const fs::path live = fs::weakly_canonical(fs::path{prog.db_path}, ec);
      const fs::path shadow = fs::weakly_canonical(fs::path{prog.shadow_path}, ec);
      if (!ec && live == shadow)
        throw std::runtime_error{"--shadow-path must differ from --db-path"};
    }

    append_endpoints(prog.daemon_rpcs, command_line::get_arg(args, opts.daemon_rpc));
    append_endpoints(prog.daemon_rpcs, command_line::get_arg(args, opts.daemon_backup));

    if (!prog.status_only && prog.daemon_rpcs.empty())
      throw std::runtime_error{"--daemon is required (point it at a beldexd this rebuild can use)"};

    if (!prog.status_only && prog.sync_interval.count() == 0)
      throw std::runtime_error{"--sync-interval must be non-zero"};

    return prog;
  }

  //! One account carried from the live database into the shadow.
  struct seed_account
  {
    lws::db::account_address address;
    crypto::secret_key key;
    lws::db::block_id start_height;
    lws::db::account_status status;
    lws::db::account_flags flags;
  };

  /*! One pending entry from the `requests` table.

      Kept alongside the accounts because it is state a user is waiting on. A
      wallet that calls `/import_request` during a rebuild is told "Accepted,
      waiting for approval"; if the switch dropped that row the request would
      silently never exist, and the user would sit on "Waiting for Approval"
      forever with nothing for an operator to approve. */
  struct seed_request
  {
    lws::db::request type;
    lws::db::account_address address;
    crypto::secret_key key;
    lws::db::block_id start_height;
    lws::db::account_flags flags;
  };

  struct account_set
  {
    std::vector<seed_account> accounts;
    std::vector<seed_request> requests;
    std::uint64_t height; //!< Chain tip recorded in that database.
  };

  //! Read every account, in every status, out of `disk`.
  account_set read_accounts(lws::db::storage& disk)
  {
    account_set out{};

    auto reader = MONERO_UNWRAP(disk.start_read());

    const auto last = reader.get_last_block();
    out.height = last ? std::uint64_t(last->id) : 0;

    /* Every status, not just active. Seeding only the active accounts would
       silently drop the inactive and hidden ones, and the rebuild would look
       like it had succeeded right up until someone reactivated one. */
    const lws::db::account_status all[] = {
      lws::db::account_status::active,
      lws::db::account_status::inactive,
      lws::db::account_status::hidden
    };

    for (const lws::db::account_status status : all)
    {
      auto users = MONERO_UNWRAP(reader.get_accounts(status));
      for (auto user = users.make_iterator(); !user.is_end(); ++user)
      {
        const lws::db::account acct = *user;
        seed_account entry{};
        entry.address = acct.address;
        std::memcpy(std::addressof(entry.key), std::addressof(acct.key), sizeof(entry.key));
        entry.start_height = acct.start_height;
        entry.status = status;
        entry.flags = acct.flags;
        out.accounts.push_back(entry);
      }
    }

    // Pending create/import requests are user-visible state too; see seed_request.
    {
      auto requests = MONERO_UNWRAP(reader.get_requests());
      for (auto entry = requests.make_iterator(); !entry.is_end(); ++entry)
      {
        const lws::db::request type = entry.get_key();
        for (const lws::db::request_info& info : entry.make_value_range())
        {
          seed_request pending{};
          pending.type = type;
          pending.address = info.address;
          std::memcpy(std::addressof(pending.key), std::addressof(info.key), sizeof(pending.key));
          pending.start_height = info.start_height;
          pending.flags = info.creation_flags;
          out.requests.push_back(pending);
        }
      }
    }

    reader.finish_read();
    return out;
  }

  //! Comparator giving accounts a stable order so two sets can be diffed.
  struct by_address
  {
    bool operator()(const lws::db::account_address& l, const lws::db::account_address& r) const noexcept
    {
      const int spend = std::memcmp(
        std::addressof(l.spend_public), std::addressof(r.spend_public), sizeof(l.spend_public));
      if (spend != 0)
        return spend < 0;
      return std::memcmp(
        std::addressof(l.view_public), std::addressof(r.view_public), sizeof(l.view_public)) < 0;
    }
  };

  std::string marker_path(const std::string& shadow_path)
  {
    return (fs::path{shadow_path} / marker_name).string();
  }

  /*! Refuse to write into a directory holding a database this tool did not
      create.

      An operator typo here would otherwise point a rebuild at a real database
      and start adding accounts to it. An empty (or absent) directory is fine -
      that is a fresh rebuild. A directory with our marker is fine - that is a
      resume. Anything else stops the run. */
  void check_shadow_dir(const program& prog)
  {
    const fs::path dir{prog.shadow_path};
    std::error_code ec{};

    if (!fs::exists(dir, ec))
      return; // fresh

    if (!fs::is_directory(dir, ec))
      throw std::runtime_error{prog.shadow_path + " exists and is not a directory"};

    const bool empty = fs::is_empty(dir, ec);
    if (!ec && empty)
      return; // fresh

    std::ifstream marker{marker_path(prog.shadow_path)};
    if (!marker)
    {
      throw std::runtime_error{
        prog.shadow_path + " already contains files but no " + marker_name +
        ", so it was not created by beldex-lws-rebuild. Refusing to write to it - "
        "point --shadow-path at a new directory."};
    }

    nlohmann::json doc;
    try
    {
      marker >> doc;
    }
    catch (const std::exception& e)
    {
      throw std::runtime_error{
        std::string{"cannot read "} + marker_name + ": " + e.what()};
    }

    const auto source = doc.value("source_db", std::string{});
    if (!source.empty() && source != prog.db_path)
    {
      MWARNING("shadow was seeded from " << source << " but --db-path is now "
               << prog.db_path << "; continuing, but check this is intended");
    }

    const auto height = doc.value("rescan_height", std::uint64_t(0));
    if (height != prog.rescan_height)
    {
      throw std::runtime_error{
        "shadow was started with --rescan-height " + std::to_string(height) +
        " but this run says " + std::to_string(prog.rescan_height) +
        ". Resuming with a different height would leave a database rebuilt from "
        "two different points; use a new --shadow-path."};
    }
  }

  void write_marker(const program& prog)
  {
    nlohmann::json doc;
    doc["version"] = marker_version;
    doc["source_db"] = prog.db_path;
    doc["rescan_height"] = prog.rescan_height;
    doc["created_at"] = std::uint64_t(std::time(nullptr));
    doc["network"] =
      lws::config::network == cryptonote::MAINNET ? "main" :
      lws::config::network == cryptonote::TESTNET ? "test" :
      lws::config::network == cryptonote::DEVNET  ? "dev"  : "main";

    std::ofstream file{marker_path(prog.shadow_path), std::ios::binary | std::ios::trunc};
    if (!file)
      throw std::runtime_error{"cannot write " + marker_path(prog.shadow_path)};
    file << doc.dump(2) << std::endl;
  }

  /*! Add to `shadow` every account in `live` that is not there yet.

      `add_account` stamps the account at the shadow's current chain tip, so
      each new account is then lowered to where it actually needs to start:
      `--rescan-height` for the original population, and the account's own
      `start_height` for one that appeared later. A late signup must not be
      dragged back to the rebuild height - it has no history down there, and
      scanning it from there would cost hours for nothing.

      \return Number of accounts added. */
  std::size_t seed_accounts(
    lws::db::storage& shadow,
    const std::vector<seed_account>& live,
    const std::vector<seed_account>& existing,
    std::uint64_t shadow_height,
    std::uint64_t rescan_height,
    bool initial)
  {
    std::vector<lws::db::account_address> present;
    present.reserve(existing.size());
    for (const seed_account& acct : existing)
      present.push_back(acct.address);
    std::sort(present.begin(), present.end(), by_address{});

    std::size_t added = 0;
    std::map<std::uint64_t, std::vector<lws::db::account_address>> by_height;
    std::map<lws::db::account_status, std::vector<lws::db::account_address>> by_status;

    for (const seed_account& acct : live)
    {
      if (std::binary_search(present.begin(), present.end(), acct.address, by_address{}))
        continue;

      const expect<void> result = shadow.add_account(acct.address, acct.key, acct.flags);
      if (!result && result != lws::error::account_exists)
      {
        /* One bad account must not abort a multi-hour rebuild. Report it and
           keep going; the summary line carries the count. */
        MERROR("could not seed " << lws::db::address_string(acct.address)
               << ": " << result.error().message());
        continue;
      }

      /* Where this account should begin.

         `add_account` has just stamped it at the shadow's current tip, and
         `rescan` only ever lowers a height, so the target is clamped to that
         tip: asking to start ABOVE it is rejected outright by `rescan`
         (`bad_height`), which is a real case here - a wallet that registers on
         the live server at the chain tip while the shadow is still hours
         behind. Clamping leaves it at the shadow tip, from which it will be
         scanned forward normally, instead of logging an error every sync. */
      const std::uint64_t wanted =
        initial ? rescan_height
                : std::max(rescan_height, std::uint64_t(acct.start_height));
      const std::uint64_t target = std::min(wanted, shadow_height);

      by_height[target].push_back(acct.address);
      if (acct.status != lws::db::account_status::active)
        by_status[acct.status].push_back(acct.address);
      ++added;
    }

    for (const auto& group : by_height)
    {
      const expect<std::vector<lws::db::account_address>> result =
        shadow.rescan(lws::db::block_id(group.first), epee::to_span(group.second));
      if (!result)
        MERROR("could not set start height " << group.first << " on "
               << group.second.size() << " account(s): " << result.error().message());
    }

    /* Status is mirrored after the height is set: `change_status` moves the
       account between status keys, and doing it first would make the rescan
       above miss it. */
    for (const auto& group : by_status)
    {
      const expect<std::vector<lws::db::account_address>> result =
        shadow.change_status(group.first, epee::to_span(group.second));
      if (!result)
        MERROR("could not mirror status on " << group.second.size()
               << " account(s): " << result.error().message());
    }

    return added;
  }

  /*! Mirror pending create/import requests that the shadow does not have yet.

      Separate from `seed_accounts` because a request is not an account: it has
      no id, it lives in its own table, and an import request can exist for an
      account that is already present. Both are keyed by (type, address), so
      "already there" is decided on that pair, not on the address alone.

      \return Number of requests mirrored. */
  std::size_t seed_requests(
    lws::db::storage& shadow,
    const std::vector<seed_request>& live,
    const std::vector<seed_request>& existing)
  {
    const auto already_present = [&existing] (const seed_request& want)
    {
      for (const seed_request& have : existing)
      {
        if (have.type == want.type &&
            std::memcmp(std::addressof(have.address), std::addressof(want.address),
                        sizeof(want.address)) == 0)
        {
          return true;
        }
      }
      return false;
    };

    std::size_t added = 0;
    for (const seed_request& pending : live)
    {
      if (already_present(pending))
        continue;

      expect<void> result = success();
      switch (pending.type)
      {
      case lws::db::request::create:
        result = shadow.creation_request(pending.address, pending.key, pending.flags);
        break;
      case lws::db::request::import_scan:
        result = shadow.import_request(pending.address, pending.start_height);
        break;
      default:
        MWARNING("unknown request type for " << lws::db::address_string(pending.address)
                 << "; not mirrored");
        continue;
      }

      if (result || result == lws::error::duplicate_request)
        ++added;
      else
      {
        MERROR("could not mirror pending request for "
               << lws::db::address_string(pending.address) << ": "
               << result.error().message());
      }
    }
    return added;
  }

  //! Print how far the rebuild has got, then return.
  int report_status(const program& prog)
  {
    lws::db::storage live = lws::db::storage::open_readonly(prog.db_path.c_str());
    const account_set live_set = read_accounts(live);

    std::error_code ec{};
    if (!fs::exists(fs::path{prog.shadow_path}, ec))
    {
      std::cout << "shadow:  not created yet (" << prog.shadow_path << ")\n"
                << "live:    " << live_set.accounts.size() << " account(s), height "
                << live_set.height << std::endl;
      return 1;
    }

    lws::db::storage shadow = lws::db::storage::open_readonly(prog.shadow_path.c_str());
    const account_set shadow_set = read_accounts(shadow);

    const std::uint64_t lag =
      live_set.height > shadow_set.height ? live_set.height - shadow_set.height : 0;

    std::cout
      << "live:    " << live_set.accounts.size() << " account(s), height " << live_set.height << "\n"
      << "shadow:  " << shadow_set.accounts.size() << " account(s), height " << shadow_set.height << "\n"
      << "lag:     " << lag << " block(s)\n"
      << "missing: " << (live_set.accounts.size() > shadow_set.accounts.size()
                          ? live_set.accounts.size() - shadow_set.accounts.size() : 0)
      << " account(s) not yet seeded\n"
      << "pending: " << shadow_set.requests.size() << "/" << live_set.requests.size()
      << " request(s) mirrored" << std::endl;

    // Caught up enough to switch? Deliberately strict: the operator can decide
    // to force it, this only reports the safe case.
    const bool ready = lag == 0 &&
      shadow_set.accounts.size() >= live_set.accounts.size() &&
      shadow_set.requests.size() >= live_set.requests.size();
    std::cout << "ready:   " << (ready ? "yes" : "no") << std::endl;
    return ready ? 0 : 1;
  }

  int run(program prog)
  {
    std::signal(SIGINT,  [](int) { running = false; lws::scanner::stop(); });
    std::signal(SIGTERM, [](int) { running = false; lws::scanner::stop(); });

    if (prog.status_only)
      return report_status(prog);

    check_shadow_dir(prog);

    // Read the live account list first, and only read-only. Nothing below this
    // point writes to the live database.
    account_set live_set{};
    {
      lws::db::storage live = lws::db::storage::open_readonly(prog.db_path.c_str());
      live_set = read_accounts(live);
    }
    MGINFO("live database: " << live_set.accounts.size() << " account(s), height " << live_set.height);

    if (live_set.height <= prog.rescan_height)
    {
      throw std::runtime_error{
        "--rescan-height " + std::to_string(prog.rescan_height) +
        " is at or above the live chain height " + std::to_string(live_set.height)};
    }

    fs::create_directories(prog.shadow_path);
    /* `create_queue_max` must not be 0 here: `creation_request` rejects every
       call when it is, so pending create requests could not be mirrored into
       the shadow. Sized generously because this is a mirror of a queue the live
       server already accepted, not a fresh queue taking new arrivals. */
    constexpr const unsigned shadow_create_queue_max = 1000000;
    lws::db::storage shadow =
      lws::db::storage::open(prog.shadow_path.c_str(), shadow_create_queue_max);
    write_marker(prog);

    /* The shadow needs a chain before accounts can be added to it -
       `add_account` stamps the account at the current tip and fails on an
       empty blocks table. This is the same call the daemon makes at startup. */
    MGINFO("seeding shadow chain from " << prog.daemon_rpcs.front());
    if (!lws::scanner::sync(shadow.clone(), prog.daemon_rpcs.front()))
      throw std::runtime_error{"could not sync the shadow chain from " + prog.daemon_rpcs.front()};

    {
      const account_set existing = read_accounts(shadow);
      const std::size_t added = seed_accounts(
        shadow, live_set.accounts, existing.accounts,
        existing.height, prog.rescan_height, /*initial=*/true);
      const std::size_t mirrored =
        seed_requests(shadow, live_set.requests, existing.requests);
      MGINFO("seeded " << added << " account(s) at height " << prog.rescan_height
             << " (" << existing.accounts.size() << " already present), "
             << mirrored << " pending request(s) mirrored");
    }

    /* Batch the restarts caused by newly seeded accounts; see
       `--restart-coalesce` and `scanner::set_change_coalesce`. */
    lws::scanner::set_change_coalesce(prog.restart_coalesce);

    /* Scan on its own thread so the sync loop below can keep adding accounts
       that appear on the live server while this runs. `scanner::run` returns
       only when `scanner::stop()` is called. */
    boost::thread scan_thread{
      [&prog, &shadow] ()
      {
        try
        {
          lws::scanner::run(
            shadow.clone(), prog.daemon_rpcs, prog.scan_threads, prog.daemon_spread);
        }
        catch (const std::exception& e)
        {
          MERROR("rebuild scan loop stopped: " << e.what());
          running = false;
        }
      }
    };

    MGINFO("rebuild running; polling " << prog.db_path << " for new accounts every "
           << prog.sync_interval.count() << "s");

    while (running && lws::scanner::is_running())
    {
      const auto deadline = std::chrono::steady_clock::now() + prog.sync_interval;
      while (running && lws::scanner::is_running() &&
             std::chrono::steady_clock::now() < deadline)
      {
        std::this_thread::sleep_for(std::chrono::seconds{1});
      }
      if (!running || !lws::scanner::is_running())
        break;

      try
      {
        lws::db::storage live = lws::db::storage::open_readonly(prog.db_path.c_str());
        const account_set current = read_accounts(live);
        const account_set existing = read_accounts(shadow);

        const std::size_t added = seed_accounts(
          shadow, current.accounts, existing.accounts,
          existing.height, prog.rescan_height, /*initial=*/false);
        if (added)
          MGINFO("sync: added " << added << " newly registered account(s) to the shadow");

        const std::size_t mirrored =
          seed_requests(shadow, current.requests, existing.requests);
        if (mirrored)
          MGINFO("sync: mirrored " << mirrored << " pending request(s) to the shadow");

        const std::uint64_t lag =
          current.height > existing.height ? current.height - existing.height : 0;
        MINFO("sync: shadow height " << existing.height << ", live height "
              << current.height << ", lag " << lag << " block(s), "
              << existing.accounts.size() << "/" << current.accounts.size() << " account(s)");
      }
      catch (const std::exception& e)
      {
        // A transient failure to read the live DB must not end the rebuild.
        MWARNING("sync pass failed, will retry: " << e.what());
      }
    }

    lws::scanner::stop();
    scan_thread.join();
    MGINFO("rebuild stopped; shadow left intact at " << prog.shadow_path);
    return 0;
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
