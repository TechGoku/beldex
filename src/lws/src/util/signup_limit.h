#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace lws
{
  /*! The key signups from `host` are counted under.

      An IPv4 address counts as itself. An IPv6 client usually controls a whole
      /64, so counting each address separately would hand it 2^64 allowances;
      those are counted by their /64 prefix instead. Anything that does not
      parse as an address is used verbatim. */
  std::string signup_bucket(const std::string& host);

  /*! Per-client ceiling on account creation (`--signup-rate-limit`).

      A fixed one-hour window per client: the first signup opens it, and once
      `limit` have been counted the rest are refused until it closes.

      The table is bounded. When it fills, expired windows are dropped; if it
      is still full it is cleared, which briefly forgets everyone's count.
      Failing open is deliberate: the alternative is that anyone able to fill
      the table blocks every new user. */
  class signup_limiter
  {
  public:
    using clock = std::chrono::steady_clock;

    //! How long a client's window stays open.
    static constexpr std::chrono::hours period() noexcept { return std::chrono::hours{1}; }

    explicit signup_limiter(std::size_t max_tracked = 100000);

    /*! Count one signup from `host`.

        \param limit Signups allowed per window; `0` disables the limit, and
          nothing is recorded.
        \param now Injectable for tests.
        \return False if `host` has used up its window. */
    bool allow(const std::string& host, unsigned limit, clock::time_point now = clock::now());

    //! \return Number of clients currently being counted.
    std::size_t tracked() const;

  private:
    struct window
    {
      clock::time_point opened;
      unsigned count;
    };

    const std::size_t max_tracked_;
    mutable std::mutex sync_;
    std::unordered_map<std::string, window> seen_;
  };
} // lws
