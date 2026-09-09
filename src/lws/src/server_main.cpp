// #include <boost/filesystem/operations.hpp>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/thread/thread.hpp>
#include <boost/filesystem.hpp>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/command_line.h"      //beldex/common
#include "common/util.h"              //beldex/common
#include "config.h"
#include "cryptonote_config.h"        //beldex/src/
#include "db/storage.h"
#include "error.h"
//#include "rpc/client.h"
#include "options.h"
#include "rest_server.h"
#include "scanner.h"

namespace
{
  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> daemon_rpc;
    const command_line::arg_descriptor<std::string> daemon_sub;
    const command_line::arg_descriptor<std::string> daemon_backup;
    const command_line::arg_descriptor<std::uint64_t> rest_cache_bytes;
    const command_line::arg_descriptor<bool> daemon_spread;
    const command_line::arg_descriptor<std::vector<std::string>> rest_servers;
    const command_line::arg_descriptor<std::vector<std::string>> admin_rest_servers;
    const command_line::arg_descriptor<std::string> rest_ssl_key;
    const command_line::arg_descriptor<std::string> rest_ssl_cert;
    const command_line::arg_descriptor<std::size_t> rest_threads;
    const command_line::arg_descriptor<std::size_t> scan_threads;
    const command_line::arg_descriptor<std::vector<std::string>> access_controls;
    const command_line::arg_descriptor<bool> external_bind;
    const command_line::arg_descriptor<unsigned> create_queue_max;
    const command_line::arg_descriptor<std::chrono::minutes::rep> rates_interval;
    const command_line::arg_descriptor<unsigned short> log_level;
    const command_line::arg_descriptor<std::string> config_file;
    const command_line::arg_descriptor<std::uint64_t> db_map_size;
    const command_line::arg_descriptor<unsigned> db_max_readers;
    const command_line::arg_descriptor<std::uint64_t> max_response_bytes;

    static std::string get_default_zmq()
    {
      static constexpr const char base[] = "http://127.0.0.1:";
      switch (lws::config::network)
      {
      case cryptonote::network_type::TESTNET:
        return base + std::to_string(cryptonote::config::testnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::DEVNET:
        return base + std::to_string(cryptonote::config::devnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::MAINNET:
      default:
        break;
      }
      return base + std::to_string(cryptonote::config::RPC_DEFAULT_PORT);
    }

    options()
      : lws::options()
      , daemon_rpc{"daemon", "[(https|http)://<address>:]<port> for daemon connections", get_default_zmq()}
      , daemon_sub{"sub", "tcp://address:port or ipc://path of a beldexd OMQ Pub", ""}
      , daemon_backup{"daemon-backup", "Comma-separated additional beldexd HTTP endpoints to fail over to, e.g. http://host2:19091,http://host3:19091", ""}
      , rest_cache_bytes{"rest-cache-bytes", "Memory ceiling for EACH per-account REST response cache, in bytes", 256 * 1024 * 1024}
      , daemon_spread{"daemon-spread", "Fan scan threads across every --daemon/--daemon-backup endpoint instead of using one at a time. Helps only when accounts sit at different heights (bulk rescan, staggered catch-up); in steady state the threads request the same blocks and the shared fetch cache already dedupes them", false}
      , rest_servers{"rest-server", "[(https|http)://<address>:]<port>[/<prefix>] for incoming connections, multiple declarations allowed"}
      , admin_rest_servers{"admin-rest-server", "[(https|http])://<address>:]<port>[/<prefix>] for incoming admin connections, multiple declarations allowed"}      , rest_ssl_key{"rest-ssl-key", "<path> to PEM formatted SSL key for https REST server", ""}
      , rest_ssl_cert{"rest-ssl-certificate", "<path> to PEM formatted SSL certificate (chains supported) for https REST server", ""}
      /* Was 1. With a single REST thread every request is serialised behind
         whichever one is running, so one large get_address_txs stalls every
         other wallet on the server - the opposite of the "thousands of
         concurrent users" target. Capped rather than set to the full core count
         because the intended deployment runs several of these processes on one
         host, and each would otherwise size itself as if it owned the box. */
      , rest_threads{"rest-threads", "Number of threads to process REST connections",
                     std::min<unsigned>(8, std::max<unsigned>(2, boost::thread::hardware_concurrency()))}
      , scan_threads{"scan-threads", "Maximum number of threads for account scanning", boost::thread::hardware_concurrency()}
      , access_controls{"access-control-origin", "Specify a whitelisted HTTP control origin domain"}
      , external_bind{"confirm-external-bind", "Allow listening for external connections", false}
      , create_queue_max{"create-queue-max", "Set pending create account requests maximum", 10000}
      , rates_interval{"exchange-rate-interval", "Retrieve exchange rates in minute intervals from cryptocompare.com if greater than 0", 0}
      , log_level{"log-level", "Log level [0-4]", 1}
      , config_file{"config-file", "Specify any option in a config file; <name>=<value> on separate lines"}
      , db_map_size{"db-map-size", "Initial LMDB memory-map size in bytes; 0 keeps the built-in default sizing", 0}
      , db_max_readers{"db-max-readers", "Maximum concurrent LMDB reader slots", 1024}
      , max_response_bytes{"rest-max-response-bytes", "Refuse REST responses larger than this many bytes; 0 (default) is unlimited", 0}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      static constexpr const char rest_default[] = "https://0.0.0.0:8443";

      lws::options::prepare(description);
      command_line::add_arg(description, daemon_rpc);
      command_line::add_arg(description, daemon_sub);
      command_line::add_arg(description, daemon_backup);
      command_line::add_arg(description, rest_cache_bytes);
      command_line::add_arg(description, daemon_spread);
      description.add_options()(rest_servers.name, boost::program_options::value<std::vector<std::string>>()->default_value({rest_default}, rest_default), rest_servers.description);
      command_line::add_arg(description, admin_rest_servers);
      command_line::add_arg(description, rest_ssl_key);
      command_line::add_arg(description, rest_ssl_cert);
      command_line::add_arg(description, rest_threads);
      command_line::add_arg(description, scan_threads);
      command_line::add_arg(description, access_controls);
      command_line::add_arg(description, external_bind);
      command_line::add_arg(description, create_queue_max);
      command_line::add_arg(description, rates_interval);
      command_line::add_arg(description, log_level);
      command_line::add_arg(description, config_file);
      command_line::add_arg(description, db_map_size);
      command_line::add_arg(description, db_max_readers);
      command_line::add_arg(description, max_response_bytes);
    }
  };
 struct program
  {
    std::string db_path;
    std::vector<std::string> rest_servers;
    std::vector<std::string> admin_rest_servers;
    lws::rest_server::configuration rest_config;
    std::string daemon_rpc;
    std::string daemon_sub;
    std::string daemon_backup;
    std::chrono::minutes rates_interval;
    std::size_t scan_threads;
    unsigned create_queue_max;
    std::uint64_t db_map_size;
    unsigned db_max_readers;
    /*! Parsed + normalised `--daemon-backup`. Last member on purpose: `program`
        is aggregate-initialised from the option list, so inserting a field
        anywhere earlier shifts every following initialiser into the wrong
        member. Filled in after that initialisation. */
    std::vector<std::string> daemon_backups;
    bool daemon_spread;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << description;
  }

 boost::optional<program> get_program(int argc, char **argv)
 {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
        po::options_description description{"Options"};
        opts.prepare(description);

        po::store(
            po::command_line_parser(argc, argv).options(description).run(), args);
        po::notify(args);
      if (!command_line::is_arg_defaulted(args, opts.config_file))
      {
        boost::filesystem::path config_path{command_line::get_arg(args, opts.config_file)};
        if (!boost::filesystem::exists(config_path))
          MONERO_THROW(lws::error::configuration, "Config file does not exist");

        po::store(
          po::parse_config_file<char>(config_path.string<std::string>().c_str(), description), args
        );
        po::notify(args);
      }
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
        print_help(std::cout);
        return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/
    mlog_set_log_level(command_line::get_arg(args, opts.log_level));

    program prog{
        command_line::get_arg(args, opts.db_path),
        command_line::get_arg(args, opts.rest_servers),
        command_line::get_arg(args, opts.admin_rest_servers),
        lws::rest_server::configuration{
            {command_line::get_arg(args, opts.rest_ssl_key), command_line::get_arg(args, opts.rest_ssl_cert)},
            command_line::get_arg(args, opts.access_controls),
            command_line::get_arg(args, opts.rest_threads),
            command_line::get_arg(args, opts.external_bind),
            std::size_t(command_line::get_arg(args, opts.max_response_bytes))},
        command_line::get_arg(args, opts.daemon_rpc),
        command_line::get_arg(args, opts.daemon_sub),
        command_line::get_arg(args, opts.daemon_backup),
        std::chrono::minutes{command_line::get_arg(args, opts.rates_interval)},
        command_line::get_arg(args, opts.scan_threads),
        command_line::get_arg(args, opts.create_queue_max),
        command_line::get_arg(args, opts.db_map_size),
        command_line::get_arg(args, opts.db_max_readers),
    };

    prog.rest_config.threads = std::max(std::size_t(1), prog.rest_config.threads);
    /* The REST tier needs to know where its database lives so `/switch_db` can
       back it up before switching away from it, and name it in the response. */
    prog.rest_config.db_path = prog.db_path;
    prog.rest_config.create_queue_max = prog.create_queue_max;
    prog.rest_config.db_map_size = prog.db_map_size;
    prog.rest_config.db_max_readers = prog.db_max_readers;
    prog.scan_threads = std::max(std::size_t(1), prog.scan_threads);

    // Detect IPC mode
  const bool ipc_mode = prog.daemon_rpc.rfind("ipc://", 0) == 0;

  if (command_line::is_arg_defaulted(args, opts.daemon_rpc))
    prog.daemon_rpc = options::get_default_zmq();

  /* Append "/json_rpc" for HTTP endpoints, but only when it is not already
     there. This used to be unconditional, so passing the full URL - which is
     what the endpoint actually is, and the obvious thing to hand it - produced
     ".../json_rpc/json_rpc". beldexd answers that with "Not found", and since
     the reply is not JSON every chain sync died on a parse error ("last read:
     'N'") with nothing in the message pointing at the URL as the cause.
     `--daemon-backup` already guarded against this in `normalise` below; the
     primary did not.

     Trailing slashes are stripped first so ".../:29391/" does not become
     "...//json_rpc". */
  if (!ipc_mode)
  {
    while (!prog.daemon_rpc.empty() && prog.daemon_rpc.back() == '/')
      prog.daemon_rpc.pop_back();
    if (prog.daemon_rpc.find("/json_rpc") == std::string::npos)
      prog.daemon_rpc += "/json_rpc";
  }

    // For cpr::Post HTTP calls in rest_server.cpp, always use HTTP endpoint
    if (prog.daemon_rpc.rfind("ipc://", 0) == 0)
      lws::daemon_add = options::get_default_zmq() + "/json_rpc";
    else
      lws::daemon_add = prog.daemon_rpc;

    lws::rest_cache_max_bytes = std::size_t(command_line::get_arg(args, opts.rest_cache_bytes));
    prog.daemon_spread = command_line::get_arg(args, opts.daemon_spread);

    /* Build the failover endpoint list: primary first, then --daemon-backup.

       The two tiers cannot use the same set. The REST tier reaches beldexd over
       HTTP with cpr, so it can only use http(s) endpoints. The scanner picks
       its transport per endpoint (`is_ipc_uri`), so it can use an ipc:// socket
       AND http:// endpoints in the same list - which is the useful arrangement:
       a local socket for the fast path, remote hosts as the fallback.

       Only http endpoints get "/json_rpc" appended. Doing that unconditionally
       turned `ipc:///var/run/beldexd.sock` into
       `ipc:///var/run/beldexd.sock/json_rpc`, a socket path that cannot exist. */
    const auto is_ipc = [](const std::string& uri)
    { return uri.rfind("ipc://", 0) == 0; };

    const auto normalise = [&is_ipc](std::string entry) -> std::string
    {
      const auto first = entry.find_first_not_of(" \t");
      const auto last  = entry.find_last_not_of(" \t");
      entry = (first == std::string::npos) ? std::string{} : entry.substr(first, last - first + 1);
      if (entry.empty())
        return entry;

      if (is_ipc(entry))
        return entry; // a socket path - leave exactly as given

      while (!entry.empty() && entry.back() == '/')
        entry.pop_back();
      if (entry.find("/json_rpc") == std::string::npos)
        entry += "/json_rpc";
      return entry;
    };

    prog.daemon_backups.clear();
    {
      const std::string& backups = prog.daemon_backup;
      std::size_t pos = 0;
      while (!backups.empty() && pos <= backups.size())
      {
        const std::size_t comma = backups.find(',', pos);
        std::string entry = normalise(
          backups.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos));

        // Duplicates are dropped so one dead daemon cannot be retried twice per
        // request; the primary counts as already present.
        if (!entry.empty() && entry != prog.daemon_rpc && entry != lws::daemon_add &&
            std::find(prog.daemon_backups.begin(), prog.daemon_backups.end(), entry) == prog.daemon_backups.end())
        {
          prog.daemon_backups.push_back(std::move(entry));
        }

        if (comma == std::string::npos)
          break;
        pos = comma + 1;
      }
    }

    // REST tier: http only. `lws::daemon_add` is already forced to an http
    // endpoint above even when the primary is ipc://, so this is never empty.
    lws::daemon_pool.clear();
    lws::daemon_pool.push_back(lws::daemon_add);
    for (const std::string& entry : prog.daemon_backups)
    {
      if (is_ipc(entry))
        continue; // cannot be dialled with cpr; scanner still uses it
      if (std::find(lws::daemon_pool.begin(), lws::daemon_pool.end(), entry) == lws::daemon_pool.end())
        lws::daemon_pool.push_back(entry);
    }

    if (!prog.daemon_backups.empty())
    {
      MINFO("Daemon failover configured:");
      MINFO("  scanner endpoints (" << (1 + prog.daemon_backups.size()) << "):");
      MINFO("    1. " << prog.daemon_rpc << (is_ipc(prog.daemon_rpc) ? "   [ipc]" : "   [http]"));
      unsigned n = 1;
      for (const std::string& entry : prog.daemon_backups)
        MINFO("    " << ++n << ". " << entry << (is_ipc(entry) ? "   [ipc]" : "   [http]"));

      MINFO("  REST endpoints (" << lws::daemon_pool.size() << ", http only):");
      unsigned m = 0;
      for (const std::string& url : lws::daemon_pool)
        MINFO("    " << ++m << ". " << url);

      const std::size_t skipped = (1 + prog.daemon_backups.size()) - lws::daemon_pool.size();
      if (skipped)
      {
        MINFO("  (" << skipped << " ipc endpoint(s) are scanner-only - the REST tier "
              "talks to beldexd over HTTP)");
      }
    }
    return prog;
  }
  void run(program prog)
  {
    /* SIGTERM is what systemd, docker and most supervisors send to stop a
       service. With no handler installed the default action terminates the
       process immediately, so every in-flight LMDB read transaction dies
       without releasing its reader slot in `lock.mdb`. An orphaned slot pins
       an old snapshot, which stops LMDB reclaiming any page freed since - the
       map then grows without bound until MDB_MAP_FULL, even though most of it
       is reclaimable. Handling SIGTERM the same way as SIGINT lets the scanner
       and REST server unwind and drop their transactions cleanly. */
    std::signal(SIGINT,  [] (int) { lws::scanner::stop(); });
    std::signal(SIGTERM, [] (int) { lws::scanner::stop(); });
    // A client disconnecting mid-write must not take the daemon down.
    std::signal(SIGPIPE, SIG_IGN);

    fs::create_directories(prog.db_path);
    auto disk = lws::db::storage::open(prog.db_path.c_str(), prog.create_queue_max, prog.db_map_size, prog.db_max_readers);

    /* Sweep reader slots orphaned by any previous unclean shutdown before
       scanning starts, so the first writes can reuse freed pages instead of
       growing the map. */
    lws::db::run_maintenance(disk, "startup");

    MINFO("Using beldexd RPC at " << prog.daemon_rpc);

    lws::scanner::sync(disk.clone(),prog.daemon_rpc);

    lws::rest_server server{
      epee::to_span(prog.rest_servers), prog.admin_rest_servers, disk.clone(), std::move(prog.rest_config)
    };
    for (const std::string& address : prog.rest_servers)
      MINFO("Listening for REST clients at " << address);
    for (const std::string& address : prog.admin_rest_servers)
      MINFO("Listening for REST admin clients at " << address);

    /* Scanner endpoint list: its own primary (which may be an ipc:// URI, so it
       is not necessarily `lws::daemon_add`) followed by every backup - ipc and
       http alike, since the scanner selects its transport per endpoint. It
       falls over only after a pass aborts early or a chain sync fails, so a
       single-daemon deployment is unaffected. */
    std::vector<std::string> scan_endpoints{prog.daemon_rpc};
    for (const std::string& entry : prog.daemon_backups)
      if (entry != prog.daemon_rpc)
        scan_endpoints.push_back(entry);

        // blocks until SIGINT
    if (prog.daemon_spread && 1 < scan_endpoints.size())
      MINFO("Scan threads will be spread across " << scan_endpoints.size() << " daemon endpoint(s)");

   lws::scanner::run(std::move(disk), std::move(scan_endpoints), prog.scan_threads, prog.daemon_spread);
    
  }
} // anonymous

int main(int argc, char **argv)
{
    tools::on_startup(); // if it throws, don't use MERROR just print default msg

    try
    {
        boost::optional<program> prog;

        try
        {
            prog = get_program(argc, argv);
        }
        catch (std::exception const &e)
        {
            std::cerr << e.what() << std::endl
                      << std::endl;
            print_help(std::cerr);
            return EXIT_FAILURE;
        }

        if (prog)
            run(std::move(*prog));
    }
    catch (std::exception const &e)
    {
        MERROR(e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        MERROR("Unknown exception");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
