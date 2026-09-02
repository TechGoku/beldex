#include <boost/bind/bind.hpp>
#include <boost/thread.hpp>
#include <boost/optional/optional.hpp>

#include "epee/misc_log_ex.h"
#include "epee/net/abstract_tcp_server2.h"      // beldex/contrib/epee/include
#include "epee/net/http_protocol_handler.h"     // beldex/contrib/epee/include
#include "epee/net/http_server_handlers_map2.h" // beldex/contrib/epee/include

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "net.http"

namespace lws
{
  template<class t_child_class, class t_connection_context = epee::net_utils::connection_context_base>
  class http_server_impl_base: public epee::net_utils::http::i_http_server_handler<t_connection_context>
  {

  public:
    http_server_impl_base()
        : m_net_server(epee::net_utils::e_connection_type_RPC)
    {}

    explicit http_server_impl_base(boost::asio::io_service& external_io_service)
      : m_net_server(external_io_service, epee::net_utils::e_connection_type_RPC)
    {}

    bool init(const std::string& bind_port, const std::string& bind_ip,
      std::vector<std::string> access_control_origins, epee::net_utils::ssl_options_t ssl_options)
    {

      //set self as callback handler
      m_net_server.get_config_object().m_phandler = static_cast<t_child_class*>(this);
  
      //here set folder for hosting reqests
      m_net_server.get_config_object().m_folder = "";

      //set access control allow origins if configured
      std::sort(access_control_origins.begin(), access_control_origins.end());
      m_net_server.get_config_object().m_access_control_origins = std::move(access_control_origins);

  
      MGINFO("Binding on " << bind_ip << " (IPv4):" << bind_port);
      // bool res = m_net_server.init_server(bind_port, bind_ip, bind_port, std::string{}, false, true, std::move(ssl_options));
       bool res = m_net_server.init_server(bind_port, bind_ip, bind_port, std::string{}, false, true, std::move(ssl_options));
      if(!res)
      {
        LOG_ERROR("Failed to bind server");
        return false;
      }
      return true;
    }

    bool run(size_t threads_count, bool wait = true)
    {
      //go to loop
      MINFO("Run net_service loop( " << threads_count << " threads)...");
      // Report the failure instead of swallowing it: this returned `true`
      // unconditionally, so `rest_server` treated a server that never started
      // as running and the process carried on serving nothing.
      if(!m_net_server.run_server(threads_count, wait))
      {
        LOG_ERROR("Failed to run net tcp server!");
        return false;
      }

      if(wait)
        MINFO("net_service loop stopped.");
      return true;
    }

    bool deinit()
    {
      return m_net_server.deinit_server();
    }

    bool timed_wait_server_stop(uint64_t ms)
    {
      return m_net_server.timed_wait_server_stop(ms);
    }

    bool send_stop_signal()
    {
      m_net_server.send_stop_signal();
      return true;
    }

    int get_binded_port()
    {
      return m_net_server.get_binded_port();
    }

    long get_connections_count() const
    {
      return m_net_server.get_connections_count();
    }

  protected: 
    epee::net_utils::boosted_tcp_server<epee::net_utils::http::http_custom_handler<t_connection_context> > m_net_server;
  };
} // lws
