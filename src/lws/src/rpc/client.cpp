#include "client.h"

#include <boost/thread/mutex.hpp>
#include <boost/utility/string_ref.hpp>
#include <cassert>
#include <system_error>

#include "cryptonote_config.h"


namespace lws
{
namespace rpc
{

  Connection connect_daemon()
  {
    Connection connection;
    connection.m_LMQ = std::make_shared<oxenmq::OxenMQ>(); 
    connection.m_LMQ->start();
    const std::string dir_slash = "/";
    // See options.h: an unset HOME must not be dereferenced as a null pointer.
    const char* const home_env = std::getenv("HOME");
    const std::string default_db_dir =
      ((home_env && *home_env) ? std::string{home_env} : std::string{"."}) + dir_slash + std::string(cryptonote::DATA_DIRNAME);
    const std::string default_sock_file = "ipc://"+default_db_dir+dir_slash+"beldexd.sock";
    connection.c = connection.m_LMQ->connect_remote(default_sock_file,
    [&connection](ConnectionID conn) { connection.daemon_connected = true;},
    [](ConnectionID conn, std::string_view f) { MERROR("connect failed:");} 
    );
    std::this_thread::sleep_for(5s);
    if(connection.daemon_connected)
    {
      MINFO("LWS-daemon connected with beldexd");
    }
    return connection;
  }
}//rpc
}//lws