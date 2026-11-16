#pragma once

#include <cstdint>
#include <utility>

namespace lws
{
  /*! Keeps a per-account cache to the database its entries came from.

      The REST caches are keyed by account id, and ids are only meaningful
      within one database: `beldex-lws-rebuild` renumbers accounts, so after a
      `/switch_db` the same id can name a different account. Every database
      the server serves gets a generation number, larger for each switch, and
      each request carries the generation of the database it was handed.

      Call `admit` with the cache's own mutex held, before touching it:

        * a request from a newer database clears the cache first, so nothing
          built from the old one can be served again;
        * a request still running against an older database must not read the
          cache (it holds the new database's entries) nor write to it (it
          would plant old entries under the new numbering), so it is refused;
        * generation 0 means "not known" and is always refused. */
  class cache_generation
  {
    std::uint64_t current_ = 0;

  public:
    //! \return True if a request from database `request` may use the cache.
    template<typename Clear>
    bool admit(const std::uint64_t request, Clear&& clear)
    {
      if (request == 0 || request < current_)
        return false;
      if (current_ < request)
      {
        std::forward<Clear>(clear)();
        current_ = request;
      }
      return true;
    }

    //! \return Generation of the entries currently in the cache; 0 if none yet.
    std::uint64_t current() const noexcept { return current_; }
  };
} // lws
