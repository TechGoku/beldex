#pragma once

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <stdexcept>
#include <string>
#include <sstream>

#include "common/command_line.h" // beldex/src
#include "common/file.h"         // beldex/src
#include "common/fs.h"           // beldex/src
#include "cryptonote_config.h"   // beldex/src
#include "config.h"

namespace lws
{
   const std::string default_db_subdir = "/light_wallet_server";
   const std::string dir_slash = "/";
  //  std::cout<< std::getenv("HOME");
   /* `HOME` is unset under systemd units, in containers, and after a bare
      `su`. The previous form was `const char* + std::string`, so an unset HOME
      was a null-pointer dereference during static initialisation - the process
      died before `main()` with no diagnostic at all. Fall back to the current
      directory instead; `--db-path` overrides this either way. */
   inline std::string default_home_dir()
   {
     const char* const home = std::getenv("HOME");
     return (home && *home) ? std::string{home} : std::string{"."};
   }
   const std::string default_db_dir = default_home_dir() + dir_slash + std::string(cryptonote::DATA_DIRNAME);
  // const std::string default_db_dir = std::string("/home/blockhash")+ dir_slash + CRYPTONOTE_NAME;
   struct options
  {
    const command_line::arg_descriptor<std::string> db_path;
    const command_line::arg_descriptor<std::string> network;

    options()
       : db_path{"db-path", "LMDB database directory", default_db_dir + default_db_subdir}
      , network{"network", "main, dev or test", "main"}
    {}

    /*! \return The options every LWS tool understands, as a captioned group.

        Returned as a group rather than added to one flat list so each tool's
        `--help` can present related options together. `options_description::add`
        keeps the caption when the parent is printed. */
    boost::program_options::options_description database_group() const
    {
      boost::program_options::options_description group{"Database and network"};
      command_line::add_arg(group, db_path);
      command_line::add_arg(group, network);
      return group;
    }

    //! \return Options every tool shares that are not about the database.
    static boost::program_options::options_description general_group()
    {
      boost::program_options::options_description group{"General"};
      command_line::add_arg(group, command_line::arg_help);
      return group;
    }

    /*! Add every shared option to `description`.

        Tools call this first and then add their own groups, so the shared
        options appear first and in the same order everywhere. */
    void prepare(boost::program_options::options_description& description) const
    {
      description.add(general_group());
      description.add(database_group());
    }

    void set_network(boost::program_options::variables_map const& args) const
    {
      const std::string net = command_line::get_arg(args, network);
      if (net == "main")
        lws::config::network = cryptonote::MAINNET;
      else if (net == "dev")
        lws::config::network = cryptonote::DEVNET;
      else if (net == "test")
        lws::config::network = cryptonote::TESTNET;
      else
        throw std::runtime_error{"Bad --network value"};
    }
  };
}