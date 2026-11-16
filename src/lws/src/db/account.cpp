#include "account.h"

#include <algorithm>
#include <cstring>

#include "common/error.h"
#include "common/expect.h"
#include "db/data.h"
#include "db/string.h"

namespace lws
{
  struct account::internal
  {
    explicit internal(db::account const& source)
      : address(db::address_string(source.address)), id(source.id), pubs(source.address), view_key()
    {
      using inner_type =
        std::remove_reference<decltype(tools::unwrap(view_key))>::type;

      static_assert(std::is_standard_layout<db::view_key>(), "need standard layout source");
      static_assert(std::is_pod<inner_type>(), "need pod target");
      static_assert(sizeof(view_key) == sizeof(source.key), "different size keys");
      std::memcpy(
        std::addressof(tools::unwrap(view_key)),
        std::addressof(source.key),
        sizeof(source.key)
      );
    }

    std::string address;
    db::account_id id;
    db::account_address pubs;
    crypto::secret_key view_key;
  };

  account::account(std::shared_ptr<const internal> immutable, db::block_id height, std::vector<db::output_id> spendable, std::vector<std::uint64_t> key_prints) noexcept
    : immutable_(std::move(immutable))
    , spendable_(std::move(spendable))
    , key_prints_(std::move(key_prints))
    , spends_()
    , outputs_()
    , height_(height)
  {}

  void account::null_check() const
  {
    if (!immutable_)
      MONERO_THROW(::common_error::kInvalidArgument, "using moved from account");
  }

  account::account(db::account const& source, std::vector<db::output_id> spendable, std::vector<std::uint64_t> key_prints)
    : account(std::make_shared<internal>(source), source.scan_height, std::move(spendable), std::move(key_prints))
  {
    std::sort(spendable_.begin(), spendable_.end());
    std::sort(key_prints_.begin(), key_prints_.end());
  }

  account::~account() noexcept
  {}

  account account::clone() const
  {
    account result{immutable_, height_, spendable_, key_prints_};
    result.outputs_ = outputs_;
    result.spends_ = spends_;
    return result;
  }

  void account::updated(db::block_id new_height) noexcept
  {
    height_ = std::max(height_, new_height);
    spends_.clear();
    spends_.shrink_to_fit();
    outputs_.clear();
    outputs_.shrink_to_fit();
  }

  db::account_id account::id() const noexcept
  {
    if (immutable_)
      return immutable_->id;
    return db::account_id::invalid;
  }

  std::string const& account::address() const
  {
    null_check();
    return immutable_->address;
  }

  db::account_address const& account::db_address() const
  {
    null_check();
    return immutable_->pubs;
  }

  crypto::public_key const& account::view_public() const
  {
    null_check();
    return immutable_->pubs.view_public;
  }

  crypto::public_key const& account::spend_public() const
  {
    null_check();
    return immutable_->pubs.spend_public;
  }

  crypto::secret_key const& account::view_key() const
  {
    null_check();
    return immutable_->view_key;
  }

  bool account::has_spendable(db::output_id const& id) const noexcept
  {
    return std::binary_search(spendable_.begin(), spendable_.end(), id);
  }

  std::uint64_t account::key_fingerprint(crypto::public_key const& key) noexcept
  {
    std::uint64_t out = 0;
    static_assert(sizeof(out) <= sizeof(key), "key too small");
    std::memcpy(std::addressof(out), std::addressof(key), sizeof(out));
    return out;
  }

  bool account::add_out(db::output const& out)
  {
    // Same output seen again (e.g. a re-scan of a block): nothing new.
    const auto position =
      std::lower_bound(spendable_.begin(), spendable_.end(), out.spend_meta.id);
    if (position != spendable_.end() && *position == out.spend_meta.id)
      return false;

    /* A different output with a one-time key already received. Both share one
       key image, so at most one can ever be spent; keep the first. The id
       check above cannot catch this - the second output has its own id. */
    const std::uint64_t print = key_fingerprint(out.pub);
    const auto print_position =
      std::lower_bound(key_prints_.begin(), key_prints_.end(), print);
    if (print_position != key_prints_.end() && *print_position == print)
      return false;

    spendable_.insert(position, out.spend_meta.id);
    key_prints_.insert(print_position, print);
    outputs_.push_back(out);
    return true;
  }

  void account::add_spend(db::spend const& spend)
  {
    // std::cout <<"inside the spend" << std::endl;
    spends_.push_back(spend);
  }
} // lws

