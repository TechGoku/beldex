// Checks that a REST request body which is JSON but does not fit the endpoint
// is classified as the client's mistake (lws::error::bad_request, answered
// 400) rather than falling through to 500.
//
// The bodies go through the same reader the server uses
// (wire::json::from_bytes on rpc::get_address_info_request), so a malformed
// address really is rejected the way it is on the live server: as a
// wire::error::schema error raised while reading, before any lws::error
// code is involved.
//
// Built as `lws-bad-request-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <iostream>
#include <string>
#include <system_error>

#include "common/expect.h"
#include "crypto/crypto.h"
#include "db/data.h"
#include "db/string.h"
#include "error.h"
#include "rpc/light_wallet.h"
#include "rpc/request_error.h"
#include "string_tools.h"
#include "wire/error.h"
#include "wire/json.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  std::error_code read_info(std::string body)
  {
    auto req = wire::json::from_bytes<lws::rpc::get_address_info_request>(std::move(body));
    return req ? std::error_code{} : req.error();
  }
}

int main()
{
  crypto::public_key view_pub{}, spend_pub{};
  crypto::secret_key view_sec{}, spend_sec{};
  crypto::generate_keys(view_pub, view_sec);
  crypto::generate_keys(spend_pub, spend_sec);

  const std::string address =
    lws::db::address_string(lws::db::account_address{view_pub, spend_pub});
  const std::string view_key = epee::string_tools::pod_to_hex(view_sec);
  const auto body = [](const std::string& address, const std::string& key)
  {
    return "{\"address\":\"" + address + "\",\"view_key\":\"" + key + "\"}";
  };

  check(!read_info(body(address, view_key)), "a well-formed request is read");

  std::string broken = address;
  broken.replace(broken.size() - 3, 3, "abc");
  const std::error_code bad_address = read_info(body(broken, view_key));
  check(bad_address.category() == wire::error::schema_category(),
        "a malformed address fails as a schema error while reading");
  check(lws::rpc::classify_request_error(bad_address) == lws::error::bad_request,
        "... which is classified as bad_request (400)");

  const std::error_code no_key =
    read_info("{\"address\":\"" + address + "\"}");
  check(lws::rpc::classify_request_error(no_key) == lws::error::bad_request,
        "a missing view_key is bad_request");

  const std::error_code short_key = read_info(body(address, view_key.substr(0, 10)));
  check(lws::rpc::classify_request_error(short_key) == lws::error::bad_request,
        "a view_key of the wrong length is bad_request");

  const std::error_code not_json = read_info("{\"address\":");
  check(bool(not_json) && not_json.category() != wire::error::schema_category(),
        "a body that is not JSON fails outside the schema category");
  check(lws::rpc::classify_request_error(not_json) == not_json,
        "... and is left unchanged (the dispatcher already answers it 400)");

  const std::error_code daemon_error = lws::error::bad_daemon_response;
  check(lws::rpc::classify_request_error(daemon_error) == daemon_error,
        "a non-schema error is left unchanged");
  const std::error_code timeout = std::make_error_code(std::errc::timed_out);
  check(lws::rpc::classify_request_error(timeout) == timeout,
        "a timeout is left unchanged");

  check(std::error_code{lws::error::bad_request} != std::error_code{lws::error::bad_address},
        "bad_request is its own error code");
  check(!std::error_code{lws::error::bad_request}.message().empty() &&
        std::error_code{lws::error::bad_request}.message().find("Unknown") == std::string::npos,
        "bad_request has a message");

  if (failures)
  {
    std::cout << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "all checks passed\n";
  return 0;
}
