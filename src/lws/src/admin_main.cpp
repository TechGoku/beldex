#include <algorithm>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "epee/misc_log_ex.h"         // beldex/contrib/epee/include/epee
#include "epee/span.h"                // beldex/contrib/epee/include
#include "epee/string_tools.h"        // beldex/contrib/epee/include
#include "options.h"
#include "config.h"
#include "rpc/admin.h"
#include "error.h"
#include "db/storage.h"
#include "db/string.h"
#include "db/data.h"
#include "wire/crypto.h"
#include "wire/filters.h"
#include "wire/json/write.h"

#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <sys/stat.h>

namespace
{
  // wrapper for custom output for admin accounts
  template<typename T>
  struct admin_display
  {
    T value;
  };

  void write_bytes(wire::json_writer& dest, const admin_display<lws::db::account>& source)
  {
    wire::object(dest,
      wire::field("address", lws::db::address_string(source.value.address)),
      wire::field("key", std::cref(source.value.key))  
    );
  
  }

  void write_bytes(wire::json_writer& dest, admin_display<boost::iterator_range<lmdb::value_iterator<lws::db::account>>> source)
  {
    const auto filter = [](const lws::db::account& src)
    { return bool(src.flags & lws::db::account_flags::admin_account); };
    const auto transform = [] (lws::db::account src)
    { return admin_display<lws::db::account>{std::move(src)}; };


    wire::array(dest, (source.value | boost::adaptors::filtered(filter)), transform);


  }


  template<typename F, typename... T>
  void run_command(F f, std::ostream& dest, T&&... args)
  {

    wire::json_stream_writer stream{dest};
    MONERO_UNWRAP(f(stream, std::forward<T>(args)...));
    stream.finish();
  }

  struct options : lws::options
  {
    const command_line::arg_descriptor<bool> show_sensitive;
    const command_line::arg_descriptor<std::string> command;
    const command_line::arg_descriptor<std::vector<std::string>> arguments;

    options()
      : lws::options()
      , show_sensitive{"show-sensitive", "Show view keys", false}
      , command{"command", "Admin command to execute", ""}
      , arguments{"arguments", "Arguments to command"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, show_sensitive);
      command_line::add_arg(description, command);
      command_line::add_arg(description, arguments);
    }
  };

  struct program
  {
    lws::db::storage disk;
    std::vector<std::string> arguments;
    bool show_sensitive;
  };

  crypto::secret_key get_key(std::string const& hex)
  {
    crypto::secret_key out{};
    if (!epee::string_tools::hex_to_pod(hex, out))
      MONERO_THROW(lws::error::bad_view_key, "View key has invalid hex");
    return out;
  }

  std::vector<lws::db::account_address> get_addresses(epee::span<const std::string> arguments)
  {
    // first entry is currently always some other option
    assert(!arguments.empty());
    arguments.remove_prefix(1);

    std::vector<lws::db::account_address> addresses{};
    addresses.reserve(arguments.size());
    for (std::string const& address : arguments)
      addresses.push_back(lws::db::address_string(address).value());
    return addresses;
  }

  void accept_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2){
    throw std::runtime_error{"accept_requests requires 2 or more arguments"};
    }  

      lws::rpc::address_requests req{
        get_addresses(epee::to_span(prog.arguments)),
        MONERO_UNWRAP(lws::db::request_from_string(prog.arguments[0]))
      };
      run_command(lws::rpc::accept_requests, out, std::move(prog.disk), std::move(req));
  }

  void add_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 2){
    throw std::runtime_error{"add_account needs exactly two arguments"};
    }
      

      lws::rpc::add_account_req req{
        lws::db::address_string(prog.arguments[0]).value(),
        get_key(prog.arguments[1])
    };
    run_command(lws::rpc::add_account, out, std::move(prog.disk), std::move(req));
  }

  void create_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty()){
    throw std::runtime_error{"create_admin takes zero arguments"};
    }
      

      admin_display<lws::db::account> account{};
      {
        crypto::secret_key auth{};
        crypto::generate_keys(account.value.address.view_public, auth);
        MONERO_UNWRAP(prog.disk.add_account(account.value.address, auth, lws::db::account_flags::admin_account));
  
        static_assert(sizeof(auth) == sizeof(account.value.key), "bad memcpy");
        std::memcpy(std::addressof(account.value.key), std::addressof(auth), sizeof(auth));
      }
  
      wire::json_stream_writer json{out};
      write_bytes(json, account);
      json.finish();
  }

  void debug_database(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"debug_database takes zero arguments"};

    auto reader = prog.disk.start_read().value();
    reader.json_debug(out, prog.show_sensitive);
  }

  /* ---------------------------------------------------------------------
     Account export / import (server migration)

     Moving an LWS to another host previously meant copying the whole LMDB
     file, which carries the entire scanned history and ties the destination to
     the source's schema and chain state. All that is actually needed to
     reconstitute a server is the *account set* - address, view key and where
     each account had scanned to. These two commands move exactly that, and
     nothing else.

     The exported file contains VIEW KEYS. That is unavoidable - a view key is
     what lets the server scan for an account - so the file is written 0600 and
     the command says so. Treat it as secret material.
     --------------------------------------------------------------------- */

  //! Format version of the export file; import refuses anything it cannot read.
  constexpr const unsigned account_export_version = 1;

  const char* status_name(lws::db::account_status status)
  {
    switch (status)
    {
      case lws::db::account_status::active:   return "active";
      case lws::db::account_status::inactive: return "inactive";
      case lws::db::account_status::hidden:   return "hidden";
    }
    return "active";
  }

  void export_accounts(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"export_accounts needs exactly one argument: <output file>"};

    const std::string& path = prog.arguments[0];

    nlohmann::json doc;
    doc["version"] = account_export_version;
    doc["exported_at"] = std::uint64_t(std::time(nullptr));
    doc["network"] =
      lws::config::network == cryptonote::MAINNET ? "main" :
      lws::config::network == cryptonote::TESTNET ? "test" :
      lws::config::network == cryptonote::DEVNET  ? "dev"  : "main";

    auto reader = MONERO_UNWRAP(prog.disk.start_read());

    {
      const auto last = reader.get_last_block();
      doc["source_height"] = last ? std::uint64_t(last->id) : 0;
    }

    nlohmann::json accounts = nlohmann::json::array();
    std::size_t counts[3] = {0, 0, 0};

    // Every status, not just active: a migration that silently dropped the
    // inactive and hidden accounts would look successful and lose data.
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
        nlohmann::json entry;
        entry["address"]      = lws::db::address_string(acct.address);
        entry["view_key"]     = epee::string_tools::pod_to_hex(acct.key);
        entry["scan_height"]  = std::uint64_t(acct.scan_height);
        entry["start_height"] = std::uint64_t(acct.start_height);
        entry["status"]       = status_name(status);
        entry["generated_locally"] =
          bool(acct.flags & lws::db::account_flags::account_generated_locally);
        entry["admin"] = bool(acct.flags & lws::db::account_flags::admin_account);
        accounts.push_back(std::move(entry));
        ++counts[unsigned(status)];
      }
    }
    reader.finish_read();

    doc["accounts"] = std::move(accounts);

    {
      std::ofstream file{path, std::ios::binary | std::ios::trunc};
      if (!file)
        throw std::runtime_error{"cannot open " + path + " for writing"};
      file << doc.dump(2) << std::endl;
      if (!file)
        throw std::runtime_error{"failed writing " + path};
    }

    // View keys inside: keep it off other users' eyes.
    if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0)
      MWARNING("could not set 0600 permissions on " << path << " - it contains view keys");

    wire::json_stream_writer json{out};
    wire::object(json,
      wire::field("file", std::cref(path)),
      wire::field("exported", std::uint64_t(doc["accounts"].size())),
      wire::field("active", std::uint64_t(counts[0])),
      wire::field("inactive", std::uint64_t(counts[1])),
      wire::field("hidden", std::uint64_t(counts[2])),
      wire::field("source_height", doc["source_height"].get<std::uint64_t>()),
      wire::field("warning", std::string{"file contains view keys - written 0600, keep it secret"})
    );
    json.finish();
  }

  //! One parsed line/record of an import file.
  struct import_entry
  {
    std::string address;
    std::string view_key;
    std::uint64_t scan_height;
    bool generated_locally;
  };

  /*! Accept either the JSON produced by `export_accounts` or a plain
      line-oriented list.

      The line form exists because the realistic migration source is often not
      another LWS - it is a spreadsheet, a psql `COPY ... TO`, or a one-line
      awk over some other system's table. Requiring those to be reshaped into
      JSON first would make the feature annoying enough to route around.
      Accepted separators are comma, semicolon, tab or whitespace; `#` starts a
      comment and blank lines are skipped:

          <address> <view_key_hex> [scan_height]
  */
  std::vector<import_entry> parse_import_file(const std::string& path)
  {
    std::ifstream file{path, std::ios::binary};
    if (!file)
      throw std::runtime_error{"cannot open " + path};

    std::string body{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
    const auto first = body.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
      throw std::runtime_error{path + " is empty"};

    std::vector<import_entry> out;

    if (body[first] == '{')
    {
      nlohmann::json doc = nlohmann::json::parse(body);
      const unsigned version = doc.value("version", 0u);
      if (version == 0 || account_export_version < version)
      {
        throw std::runtime_error{
          "unsupported export version " + std::to_string(version) +
          " (this build reads up to " + std::to_string(account_export_version) + ")"};
      }
      if (!doc.contains("accounts") || !doc["accounts"].is_array())
        throw std::runtime_error{path + " has no \"accounts\" array"};

      /* A mainnet key set imported into a testnet database (or vice versa)
         produces accounts that can never match anything, and the mistake is
         invisible until someone reports a permanently zero balance. */
      const std::string file_net = doc.value("network", std::string{});
      const char* expected =
        lws::config::network == cryptonote::MAINNET ? "main" :
        lws::config::network == cryptonote::TESTNET ? "test" :
        lws::config::network == cryptonote::DEVNET  ? "dev"  : nullptr;
      if (!file_net.empty() && expected && file_net != expected)
      {
        throw std::runtime_error{
          "file was exported from '" + file_net + "' but --network is '" +
          std::string{expected} + "'"};
      }

      for (const auto& entry : doc["accounts"])
      {
        import_entry parsed{};
        parsed.address = entry.value("address", std::string{});
        parsed.view_key = entry.value("view_key", std::string{});
        parsed.scan_height = entry.value("scan_height", std::uint64_t(0));
        parsed.generated_locally = entry.value("generated_locally", false);
        if (parsed.address.empty() || parsed.view_key.empty())
          throw std::runtime_error{"entry missing address or view_key"};
        out.push_back(std::move(parsed));
      }
      return out;
    }

    // Line-oriented form.
    std::istringstream lines{body};
    std::string line;
    unsigned line_no = 0;
    while (std::getline(lines, line))
    {
      ++line_no;
      const auto hash = line.find('#');
      if (hash != std::string::npos)
        line.erase(hash);
      for (char& c : line)
        if (c == ',' || c == ';' || c == '\t')
          c = ' ';

      std::istringstream fields{line};
      import_entry parsed{};
      if (!(fields >> parsed.address >> parsed.view_key))
      {
        if (line.find_first_not_of(" \r") == std::string::npos)
          continue; // blank
        throw std::runtime_error{
          path + ":" + std::to_string(line_no) + ": expected <address> <view_key> [scan_height]"};
      }
      fields >> parsed.scan_height; // optional; 0 if absent
      out.push_back(std::move(parsed));
    }
    return out;
  }

  void import_accounts(program prog, std::ostream& out)
  {
    if (prog.arguments.empty() || 2 < prog.arguments.size())
    {
      throw std::runtime_error{
        "import_accounts needs <input file> [rescan height]"};
    }

    const std::string& path = prog.arguments[0];
    const bool do_rescan = (prog.arguments.size() == 2);
    const std::uint64_t rescan_height = do_rescan ? std::stoull(prog.arguments[1]) : 0;

    const std::vector<import_entry> entries = parse_import_file(path);

    /* `add_account` derives a new account's start height from the newest row of
       the `blocks` table, so it fails with a bare MDB_NOTFOUND against a
       database that has never been synced - once per account, which is a wall
       of identical errors that says nothing about the actual cause. Check once
       and explain the ordering instead. */
    {
      auto reader = MONERO_UNWRAP(prog.disk.start_read());
      const auto last = reader.get_last_block();
      const bool empty = !last;
      reader.finish_read();
      if (empty)
      {
        throw std::runtime_error{
          "destination database has no chain data yet, so accounts cannot be "
          "added to it. Start beldex-lws-daemon against this --db-path once and "
          "let it sync the chain (a few seconds), stop it, then re-run "
          "import_accounts."};
      }
    }

    std::size_t added = 0, existed = 0, failed = 0;
    std::vector<lws::db::account_address> imported;
    imported.reserve(entries.size());
    std::vector<std::string> errors;   // first few only; joined for the report

    for (const import_entry& entry : entries)
    {
      const auto address = lws::db::address_string(entry.address);
      if (!address)
      {
        ++failed;
        if (errors.size() < 10)
          errors.push_back(entry.address + ": bad address");
        continue;
      }

      crypto::secret_key key{};
      if (!epee::string_tools::hex_to_pod(entry.view_key, key))
      {
        ++failed;
        if (errors.size() < 10)
          errors.push_back(entry.address + ": bad view key hex");
        continue;
      }

      const auto flags = entry.generated_locally ?
        lws::db::account_flags::account_generated_locally : lws::db::account_flags::default_account;

      /* One failure must not abort the run. On a migration of thousands of
         accounts, stopping at the first duplicate would leave the destination
         half-populated with no clear resume point; a per-account tally is far
         more useful than a partial import plus an exception. */
      const expect<void> result = prog.disk.add_account(*address, key, flags);
      if (result)
      {
        ++added;
        imported.push_back(*address);
      }
      else if (result == lws::error::account_exists)
      {
        ++existed;
        imported.push_back(*address); // still eligible for the rescan below
      }
      else
      {
        ++failed;
        if (errors.size() < 10)
          errors.push_back(entry.address + ": " + result.error().message());
      }
    }

    /* Rescan in one call rather than asking the operator to paste thousands of
       addresses onto a command line, which is what makes the migration path
       actually usable end to end. */
    std::size_t rescanned = 0;
    if (do_rescan && !imported.empty())
    {
      lws::rpc::rescan_req req{imported, lws::db::block_id(rescan_height)};
      std::ostringstream sink; // the per-command JSON is summarised below instead
      wire::json_stream_writer discard{sink};
      const expect<void> result = lws::rpc::rescan(discard, prog.disk.clone(), req);
      if (!result)
        errors.push_back(std::string{"rescan failed: "} + result.error().message());
      else
        rescanned = imported.size();
    }

    std::string error_text;
    for (const std::string& e : errors)
    {
      if (!error_text.empty())
        error_text += "; ";
      error_text += e;
    }

    wire::json_stream_writer json{out};
    wire::object(json,
      wire::field("file", std::cref(path)),
      wire::field("in_file", std::uint64_t(entries.size())),
      wire::field("added", std::uint64_t(added)),
      wire::field("already_present", std::uint64_t(existed)),
      wire::field("failed", std::uint64_t(failed)),
      wire::field("rescan_height", rescan_height),
      wire::field("rescanned", std::uint64_t(rescanned)),
      wire::field("errors", std::cref(error_text))
    );
    json.finish();
  }

  void list_accounts(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_accounts takes zero arguments"};

    run_command(lws::rpc::list_accounts, out, std::move(prog.disk));
  }  

  void list_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_admin takes zero arguments"};

    using value_range = boost::iterator_range<lmdb::value_iterator<lws::db::account>>;
    const auto transform = [] (value_range user)
    { return admin_display<value_range>{std::move(user)}; };

    auto reader = MONERO_UNWRAP(prog.disk.start_read());
    wire::json_stream_writer json{out};
    wire::dynamic_object(
      json, reader.get_accounts().value().make_range(), wire::enum_as_string, transform
    );
    json.finish();
  }

  void list_requests(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_requests takes zero arguments"};

    run_command(lws::rpc::list_requests, out, std::move(prog.disk));
  }

  void modify_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2){
    throw std::runtime_error{"modify_account_status requires 2 or more arguments"};
    }
      

      lws::rpc::modify_account_req req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::account_status_from_string(prog.arguments[0]).value()
      };
      run_command(lws::rpc::modify_account, out, std::move(prog.disk), std::move(req));
  }

  void reject_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      MONERO_THROW(common_error::kInvalidArgument, "reject_requests requires 2 or more arguments");
     
    lws::rpc::address_requests req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::request_from_string(prog.arguments[0]).value()
      };
      run_command(lws::rpc::reject_requests, out, std::move(prog.disk), std::move(req));
  
  }

  void rescan(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      throw std::runtime_error{"rescan requires 2 or more arguments"};

    lws::rpc::rescan_req req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::block_id(std::stoull(prog.arguments[0]))
      };
      run_command(lws::rpc::rescan, out, std::move(prog.disk), std::move(req));
  
  
  
  }

  void rollback(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"rollback requires 1 argument"};

    const auto height = lws::db::block_id(std::stoull(prog.arguments[0]));
    MONERO_UNWRAP(prog.disk.rollback(height));

    wire::json_stream_writer json{out};
    wire::object(json, wire::field("new_height", height));
    json.finish();
  }

  void compact(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"compact requires 1 argument"};

    // Safe to run against a live, running beldex-lws-daemon: LMDB snapshots
    // the environment for the copy and does not block it. Writes a
    // compacted copy to the given path; swapping it into place is a manual,
    // separate step for the operator.
    const std::string& dest_path = prog.arguments[0];
    MONERO_UNWRAP(prog.disk.compact(dest_path.c_str()));

    wire::json_stream_writer json{out};
    wire::object(json, wire::field("compacted_to", dest_path));
    json.finish();
  }

  struct command
  {
    char const* const name;
    void (*const handler)(program, std::ostream&);
    char const* const parameters;
    };

  static constexpr const command commands[] =
  {
    {"accept_requests",       &accept_requests, "\t<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"add_account",           &add_account,     "\t\t<base58 address> <view key hex>"},
    {"compact",               &compact,         "\t\t<destination path>"},
    {"create_admin",          &create_admin,    ""},
    {"debug_database",        &debug_database,  ""},
    {"export_accounts",       &export_accounts, "\t<output file>  (address+view key+heights; file contains SECRETS)"},
    {"import_accounts",       &import_accounts, "\t<input file> [rescan height]"},
    {"list_accounts",         &list_accounts,   ""},
    {"list_admin",            &list_admin,      ""},
    {"list_requests",         &list_requests,   ""},
    {"modify_account_status", &modify_account,  "\t<\"active\"|\"inactive\"|\"hidden\"> <base58 address> [base 58 address]..."},
    {"reject_requests",       &reject_requests, "\t<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"rescan",                &rescan,          "\t\t<height> <base58 address> [base 58 address]..."},
    {"rollback",              &rollback,        "\t\t<height>"}
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options] [command] [arguments]" << std::endl;
    out << description << std::endl;
    out << "Commands:" << std::endl;
    for (command cmd : commands)
    {
      out << "  " << cmd.name << "\t\t" << cmd.parameters << std::endl;
    }
  }

  boost::optional<std::pair<std::string, program>> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::positional_options_description positional{};
      positional.add(opts.command.name, 1);
      positional.add(opts.arguments.name, -1);

      po::store(
        po::command_line_parser(argc, argv)
        .options(description).positional(positional).run()
        , args
      );
      po::notify(args);
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/

    program prog{
      lws::db::storage::open(command_line::get_arg(args, opts.db_path).c_str(), 0)
    };

    prog.show_sensitive = command_line::get_arg(args, opts.show_sensitive);
    auto cmd = args[opts.command.name];
    if (cmd.empty())
      throw std::runtime_error{"No command given"};

    prog.arguments = command_line::get_arg(args, opts.arguments);
    return {{cmd.as<std::string>(), std::move(prog)}};
  }

  void run(boost::string_ref name, program prog, std::ostream& out)
  {
    struct by_name
    {
      bool operator()(command const& left, command const& right) const noexcept
      {
        assert(left.name && right.name);
        return std::strcmp(left.name, right.name) < 0;
      }
      bool operator()(boost::string_ref left, command const& right) const noexcept
      {
        assert(right.name);
        return left < right.name;
      }
      bool operator()(command const& left, boost::string_ref right) const noexcept
      {
        assert(left.name);
        return left.name < right;
      }
    };

    assert(std::is_sorted(std::begin(commands), std::end(commands), by_name{}));
    const auto found = std::lower_bound(
      std::begin(commands), std::end(commands), name, by_name{}
    );
    if (found == std::end(commands) || found->name != name)
      throw std::runtime_error{"No such command"};

    assert(found->handler != nullptr);
    found->handler(std::move(prog), out);

    if (out.bad())
      MONERO_THROW(std::io_errc::stream, "Writing to stdout failed");

    out << std::endl;
  }
} // anonymous

int main (int argc, char** argv)
{
  try
  {
    mlog_configure("", false, 0, 0); // disable logging

    boost::optional<std::pair<std::string, program>> prog;

    try
    {
      prog = get_program(argc, argv);
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    if (prog)
      run(prog->first, std::move(prog->second), std::cout);
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
