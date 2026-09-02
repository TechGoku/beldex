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
    prog.scan_threads = std::max(std::size_t(1), prog.scan_threads);

    // Detect IPC mode
  const bool ipc_mode = prog.daemon_rpc.rfind("ipc://", 0) == 0;

  if (command_line::is_arg_defaulted(args, opts.daemon_rpc))
  {
      prog.daemon_rpc = options::get_default_zmq();

      // Append only for HTTP mode
      if (!ipc_mode)
          prog.daemon_rpc += "/json_rpc";
  }
  else
  {
      // Append only for HTTP mode
      if (!ipc_mode)
          prog.daemon_rpc += "/json_rpc";
  }

    // For cpr::Post HTTP calls in rest_server.cpp, always use HTTP endpoint
    if (prog.daemon_rpc.rfind("ipc://", 0) == 0)
      lws::daemon_add = options::get_default_zmq() + "/json_rpc";
    else
      lws::daemon_add = prog.daemon_rpc;

    /* Build the failover pool: primary first, then --daemon-backup in order.

       Each backup is normalised the same way the primary is - a bare endpoint
       gets "/json_rpc" appended - so operators can pass the same form of URL
       they pass to --daemon. Duplicates and blanks are dropped so a repeated
       entry cannot make one dead daemon get retried twice per request. */
    lws::rest_cache_max_bytes = std::size_t(command_line::get_arg(args, opts.rest_cache_bytes));

    lws::daemon_pool.clear();
    lws::daemon_pool.push_back(lws::daemon_add);
    {
      const std::string& backups = prog.daemon_backup;
      std::size_t pos = 0;
      while (pos <= backups.size() && !backups.empty())
      {
        const std::size_t comma = backups.find(',', pos);
        std::string entry = backups.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);

        // trim surrounding whitespace
        const auto first = entry.find_first_not_of(" \t");
        const auto last  = entry.find_last_not_of(" \t");
        entry = (first == std::string::npos) ? std::string{} : entry.substr(first, last - first + 1);

        if (!entry.empty())
        {
          while (!entry.empty() && entry.back() == '/')
            entry.pop_back();
          if (entry.find("/json_rpc") == std::string::npos)
            entry += "/json_rpc";
          if (std::find(lws::daemon_pool.begin(), lws::daemon_pool.end(), entry) == lws::daemon_pool.end())
            lws::daemon_pool.push_back(std::move(entry));
        }

        if (comma == std::string::npos)
          break;
        pos = comma + 1;
      }
    }
    if (1 < lws::daemon_pool.size())
    {
      MINFO("Daemon failover pool has " << lws::daemon_pool.size() << " endpoint(s):");
      for (const std::string& url : lws::daemon_pool)
        MINFO("  - " << url);
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
       is not necessarily `lws::daemon_add`) followed by the HTTP backups. The
       scanner falls over to the next entry only after a pass aborts early, so a
       single-daemon deployment is unaffected. */
    std::vector<std::string> scan_endpoints{prog.daemon_rpc};
    for (std::size_t i = 1; i < lws::daemon_pool.size(); ++i)
      if (lws::daemon_pool[i] != prog.daemon_rpc)
        scan_endpoints.push_back(lws::daemon_pool[i]);

        // blocks until SIGINT
   lws::scanner::run(std::move(disk), std::move(scan_endpoints), prog.scan_threads);
    
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
