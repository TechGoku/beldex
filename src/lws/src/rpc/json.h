#include "wire/json.h"

namespace lws
{
namespace rpc
{
  struct json_request_base
  {
    static constexpr const char jsonrpc[] = "2.0";

    //! `method` must be in static memory.
    explicit json_request_base(const char* method)
      : id(0), method(method)
    {}
    
    unsigned id;
    const char* method; //!< Must be in static memory
  };
  constexpr const char json_request_base::jsonrpc[];

  //! \tparam W implements the WRITE concept \tparam M implements the METHOD concept
  template<typename W, typename M>
  struct json_request : json_request_base
  {
    template<typename... U>
    explicit json_request(U&&... args)
      : json_request_base(M::name()),
        params{std::forward<U>(args)...}
    {}

    W params;
  };

  template<typename W, typename M>
  inline void write_bytes(wire::json_writer& dest, const json_request<W, M>& self)
  {
    // pull fields from base class into the same object
    wire::object(dest, WIRE_FIELD_COPY(id), WIRE_FIELD_COPY(jsonrpc), WIRE_FIELD_COPY(method), WIRE_FIELD(params));
  }


  //! \tparam R implements the READ concept
  template<typename R>
  struct json_response
  {
    json_response() = delete;

    unsigned id;
    R result;
  };

  template<typename R>
  inline void read_bytes(wire::json_reader& source, json_response<R>& self)
  {
    // `id` is echoed verbatim by the daemon (the HTTP JSON-RPC request sends it
    // as the string "0"), and nothing here consumes it, so it is left unread -
    // skipped as an unknown key - rather than requiring an integer. The old
    // scanner path rebuilt the envelope with an integer id before parsing.
    wire::object(source, WIRE_FIELD(result));
  }


  /*! Implements the RPC concept (JSON-RPC 2.0).
    \tparam M must implement the METHOD concept. */
  template<typename M>
  struct json
  {
    using wire_type = wire::json;
    using request = json_request<typename M::request, M>;
    using response = json_response<typename M::response>;
  };
} // rpc
} // lws
