#pragma once

#include <system_error>

#include "error.h"
#include "wire/error.h"

namespace lws
{
namespace rpc
{
  /*! Classify an error from reading a REST client's request body.

      A body that is valid JSON but does not fit the endpoint - a missing
      field, a malformed address or key, a value of the wrong type - fails with
      a `wire::error::schema` error. That is the client's mistake, so it
      becomes `lws::error::bad_request`, which the dispatcher answers with 400.

      Only use this on errors from reading the request itself. The same schema
      errors also come from parsing daemon replies, and those are the server's
      problem and must stay 500.

      \return `lws::error::bad_request` for a schema error, else `error`. */
  inline std::error_code classify_request_error(const std::error_code error) noexcept
  {
    if (error.category() == wire::error::schema_category())
      return lws::error::bad_request;
    return error;
  }
} // rpc
} // lws
