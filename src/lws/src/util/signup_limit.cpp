#include "signup_limit.h"

#include <algorithm>
#include <boost/asio/ip/address.hpp>
#include <cstdint>
#include <iterator>

namespace lws
{
  std::string signup_bucket(const std::string& host)
  {
    boost::system::error_code failed{};
    const auto ip = boost::asio::ip::address::from_string(host, failed);
    if (failed || !ip.is_v6())
      return host;

    auto bytes = ip.to_v6().to_bytes();
    std::fill(bytes.begin() + 8, bytes.end(), std::uint8_t(0));
    return boost::asio::ip::address_v6{bytes}.to_string() + "/64";
  }

  signup_limiter::signup_limiter(const std::size_t max_tracked)
    : max_tracked_(std::max<std::size_t>(1, max_tracked)), sync_(), seen_()
  {}

  bool signup_limiter::allow(const std::string& host, const unsigned limit, const clock::time_point now)
  {
    if (!limit)
      return true;

    const std::lock_guard<std::mutex> lock{sync_};

    auto slot = seen_.find(signup_bucket(host));
    if (slot == seen_.end())
    {
      if (max_tracked_ <= seen_.size())
      {
        for (auto it = seen_.begin(); it != seen_.end();)
          it = (period() <= now - it->second.opened) ? seen_.erase(it) : std::next(it);
        if (max_tracked_ <= seen_.size())
          seen_.clear();
      }
      slot = seen_.emplace(signup_bucket(host), window{now, 0}).first;
    }
    else if (period() <= now - slot->second.opened)
      slot->second = window{now, 0};

    if (limit <= slot->second.count)
      return false;
    ++slot->second.count;
    return true;
  }

  std::size_t signup_limiter::tracked() const
  {
    const std::lock_guard<std::mutex> lock{sync_};
    return seen_.size();
  }
} // lws
