#include "light_wallet.h"

#include <boost/range/adaptor/indexed.hpp>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include "wire.h"
#include "db/string.h"
#include "error.h"
#include "misc_os_dependent.h"      // beldex/contrib/epee/include
#include "ringct/rctOps.h"          // beldex/src
#include "span.h"                   // beldex/contrib/epee/include
#include "util/random_outputs.h"
#include "wire/crypto.h"
#include "wire/error.h"
#include "wire/json.h"
#include "wire/traits.h"
#include "wire/vector.h"


namespace
{
  enum class iso_timestamp : std::uint64_t {};

  struct rct_bytes
  {
    rct::key commitment;
    rct::key mask;
    rct::key amount;
  };
  static_assert(sizeof(rct_bytes) == 32 * 3, "padding in rct struct");

  struct expand_outputs
  {
    const std::pair<lws::db::output, std::vector<crypto::key_image>>& data;
    const crypto::secret_key& user_key;
  };
} // anonymous

namespace wire
{
  template<>
  struct is_blob<rct_bytes>
    : std::true_type
  {};
}

namespace
{
  void write_bytes(wire::json_writer& dest, const iso_timestamp self)
  {
    static_assert(std::is_integral<std::time_t>::value, "unexpected  time_t type");
    if (std::numeric_limits<std::time_t>::max() < std::uint64_t(self))
      throw std::runtime_error{"Exceeded max time_t value"};

    std::tm value;
    if (!epee::misc_utils::get_gmt_time(std::time_t(self), value))
      throw std::runtime_error{"Failed to convert std::time_t to std::tm"};

    char buf[21] = {0};
    if (sizeof(buf) - 1 != std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::addressof(value)))
      throw std::runtime_error{"strftime failed"};

    dest.string({buf, sizeof(buf) - 1});
  }

  void write_bytes(wire::json_writer& dest, const expand_outputs self)
  {
    /*! \TODO Sending the public key for the output isn't necessary, as it can be
      re-computed from the other parts. Same with the rct commitment and rct
      amount. Consider dropping these from the API after client upgrades. Not
      storing them in the DB saves 96-bytes per received out. */
    // std::cout << "called ringct write_bytes\n";
    rct_bytes rct{};
    rct_bytes const* optional_rct = nullptr;
    if (unpack(self.data.first.extra).first)
    {
      crypto::key_derivation derived;
      if (!crypto::generate_key_derivation(self.data.first.spend_meta.tx_public, self.user_key, derived))
        MONERO_THROW(lws::error::crypto_failure, "generate_key_derivation failed");

      crypto::secret_key scalar;
      rct::ecdhTuple encrypted{self.data.first.ringct_mask, rct::d2h(self.data.first.spend_meta.amount)};

      crypto::derivation_to_scalar(derived, self.data.first.spend_meta.index, scalar);
      rct::ecdhEncode(encrypted, rct::sk2rct(scalar), false);

      rct.commitment = rct::commit(self.data.first.spend_meta.amount, self.data.first.ringct_mask);
      rct.mask = encrypted.mask;
      rct.amount = encrypted.amount;

      optional_rct = std::addressof(rct);
    }

    /* HF22: a privacy-token output. The client rebuilds the output and recovers
       its own blinding scalar from these when spending - that scalar has no
       other source and the server cannot derive it on the wallet's behalf.
       Omitted entirely for an ordinary BDX output, so a server that predates
       tokens and a wallet that predates them both behave as before. */
    crypto::public_key const* token_id = nullptr;
    crypto::public_key const* blinded_token_id = nullptr;
    crypto::public_key const* amount_commitment = nullptr;
    boost::optional<lws::rpc::safe_uint64> encrypted_amount;
    if (self.data.first.token_id != crypto::public_key{})
    {
      token_id = std::addressof(self.data.first.token_id);
      blinded_token_id = std::addressof(self.data.first.blinded_token_id);
      amount_commitment = std::addressof(self.data.first.amount_commitment);
      encrypted_amount = lws::rpc::safe_uint64(self.data.first.encrypted_amount);
    }

    wire::object(dest,
      wire::field("amount", lws::rpc::safe_uint64(self.data.first.spend_meta.amount)),
      wire::field("public_key", self.data.first.pub),
      wire::field("index", self.data.first.spend_meta.index),
      wire::field("global_index", self.data.first.spend_meta.id.low),
      wire::field("tx_id", self.data.first.spend_meta.id.low),
      wire::field("tx_hash", std::cref(self.data.first.link.tx_hash)),
      wire::field("tx_prefix_hash", std::cref(self.data.first.tx_prefix_hash)),
      wire::field("tx_pub_key", self.data.first.spend_meta.tx_public),
      wire::field("timestamp", iso_timestamp(self.data.first.timestamp)),
      wire::field("height", self.data.first.link.height),
      wire::field("spend_key_images", std::cref(self.data.second)),
      wire::optional_field("rct", optional_rct),
      wire::optional_field("token_id", token_id),
      wire::optional_field("blinded_token_id", blinded_token_id),
      wire::optional_field("amount_commitment", amount_commitment),
      wire::optional_field("encrypted_amount", encrypted_amount)
    );
  }

  void convert_address(const boost::string_ref source, lws::db::account_address& dest)
  {
    expect<lws::db::account_address> bytes = lws::db::address_string(source);
    if (!bytes)
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "invalid Monero address format - " << bytes.error());
    dest = std::move(*bytes);
  }
} // anonymous

namespace lws
{
  static void write_bytes(wire::json_writer& dest, random_output const& self)
  {
    const rct_bytes rct{self.keys.mask, rct::zero(), rct::zero()};
    // HF22: only present when this decoy is a private-token output. Absent
    // means native, which is what beldex-core-cpp already assumes when the
    // field is missing, so an ordinary BDX ring is unchanged.
    const auto blinded_token_id = self.keys.blinded_token_id != crypto::null_tid ?
      std::addressof(self.keys.blinded_token_id) : nullptr;
    wire::object(dest,
      wire::field("global_index", rpc::safe_uint64(self.index)),
      wire::field("public_key", std::cref(self.keys.key)),
      wire::field("rct", std::cref(rct)),
      wire::optional_field("blinded_token_id", blinded_token_id)
    );
  }
  static void write_bytes(wire::json_writer& dest, random_ring const& self)
  {
    wire::object(dest,
      wire::field("amount", rpc::safe_uint64(self.amount)),
      wire::field("outputs", std::cref(self.ring))
    );
  };

  void rpc::read_bytes(wire::json_reader& source, safe_uint64& self)
  {
    self = safe_uint64(wire::integer::cast_unsigned<std::uint64_t>(source.safe_unsigned_integer()));
  }
  void rpc::write_bytes(wire::json_writer& dest, const safe_uint64 self)
  {
    auto buf = wire::json_writer::to_string(std::uint64_t(self));
    dest.string(buf.data());
  }
  void rpc::read_bytes(wire::json_reader& source, safe_uint64_array& self)
  {
    for (std::size_t count = source.start_array(); !source.is_array_end(count); --count)
    self.values.emplace_back(wire::integer::cast_unsigned<std::uint64_t>(source.safe_unsigned_integer()));
    source.end_array();
  }

  void rpc::read_bytes(wire::json_reader& source, account_credentials& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.key))))
    );
    convert_address(address, self.address);
  }

  void rpc::read_bytes(wire::json_reader& source, get_address_txs_request& self)
  {
    std::string address;
    boost::optional<std::uint64_t> min_height;
    boost::optional<std::uint64_t> max_count;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      wire::optional_field("min_height", std::ref(min_height)),
      wire::optional_field("max_count", std::ref(max_count))
    );
    convert_address(address, self.creds.address);
    self.min_height = min_height.value_or(0);
    self.max_count = max_count.value_or(0);
  }

  void rpc::read_bytes(wire::json_reader& source, get_address_info_request& self)
  {
    std::string address;
    boost::optional<std::uint64_t> min_height;
    boost::optional<std::uint64_t> max_count;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      wire::optional_field("min_height", std::ref(min_height)),
      wire::optional_field("max_count", std::ref(max_count))
    );
    convert_address(address, self.creds.address);
    self.min_height = min_height.value_or(0);
    self.max_count = max_count.value_or(0);
  }

  namespace rpc
  {
    namespace
    {
      constexpr const char* map_daemon_state[] = {"ok", "no_connections", "synchronizing", "unavailable"};
      constexpr const char* map_network_type[] = {"main", "test", "stage", "fake"};
    }
    WIRE_DEFINE_ENUM(daemon_state, map_daemon_state);
    WIRE_DEFINE_ENUM(network_type, map_network_type);
  }

  void rpc::write_bytes(wire::json_writer& dest, const daemon_status_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(outgoing_connections_count),
      WIRE_FIELD(incoming_connections_count),
      WIRE_FIELD(height),
      WIRE_FIELD(target_height),
      WIRE_FIELD(network),
      WIRE_FIELD(state)
    );
  }
  
  void rpc::write_bytes(wire::json_writer& dest, const transaction_spend& self)
  {
    // The block this candidate spend was seen in. A client that fetches
    // spent_outputs incrementally (min_height) needs it to tell which window an
    // entry belongs to - so it can de-duplicate the reorg-margin overlap between
    // two fetches, and confirm the server honoured its cursor at all rather than
    // silently ignoring the parameter (older builds skip unknown request fields).
    //
    // Emitted only for such a client. A legacy caller sends neither min_height nor
    // max_count, cannot use the field, and would just pay for it: ~18 bytes on
    // every entry, which is megabytes of dead weight on an account with a large
    // candidate-spend list. `with_height` is set at construction in rest_server.
    const std::uint64_t height = std::uint64_t(self.possible_spend.link.height);
    const std::uint64_t* const height_field = self.with_height ? std::addressof(height) : nullptr;
    wire::object(dest,
      wire::optional_field("height", height_field),
      wire::field("amount", safe_uint64(self.meta.amount)),
      wire::field("key_image", std::cref(self.possible_spend.image)),
      wire::field("tx_pub_key", std::cref(self.meta.tx_public)),
      wire::field("out_index", self.meta.index),
      wire::field("mixin", self.possible_spend.mixin_count)
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const token_balance& self)
  {
    wire::object(dest,
      WIRE_FIELD_COPY(token_id),
      WIRE_FIELD_COPY(total_received),
      WIRE_FIELD_COPY(total_sent),
      WIRE_FIELD_COPY(locked_funds)
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const get_address_info_response& self)
  {
    wire::object(dest,
      WIRE_FIELD_COPY(locked_funds),
      WIRE_FIELD_COPY(total_received),
      WIRE_FIELD_COPY(total_sent),
      WIRE_FIELD_COPY(scanned_height),
      WIRE_FIELD_COPY(scanned_block_height),
      WIRE_FIELD_COPY(start_height),
      WIRE_FIELD_COPY(transaction_height),
      WIRE_FIELD_COPY(blockchain_height),
      WIRE_FIELD_COPY(next_min_height),
      WIRE_FIELD(spent_outputs),
      WIRE_FIELD(tokens)
      // WIRE_OPTIONAL_FIELD(rates)
    );
  }

  namespace rpc
  {
    static void write_bytes(wire::json_writer& dest, const get_address_txs_response::transaction::token_leg& self)
    {
      wire::object(dest,
        WIRE_FIELD_COPY(token_id),
        wire::field("received", safe_uint64(self.received)),
        wire::field("sent", safe_uint64(self.sent))
      );
    }

    static void write_bytes(wire::json_writer& dest, boost::range::index_value<const get_address_txs_response::transaction&> self)
    {
      epee::span<const std::uint8_t> const* payment_id = nullptr;
      epee::span<const std::uint8_t> payment_id_bytes;

      const auto extra = db::unpack(self.value().info.extra);
      if (extra.second)
      {
        payment_id = std::addressof(payment_id_bytes);

        if (extra.second == sizeof(self.value().info.payment_id.short_))
          payment_id_bytes = epee::as_byte_span(self.value().info.payment_id.short_);
        else
          payment_id_bytes = epee::as_byte_span(self.value().info.payment_id.long_);
      }

      const bool is_coinbase = (extra.first & db::coinbase_output);


      std::vector<get_address_txs_response::transaction::token_leg> const* token_legs = nullptr;
      if (!self.value().token_legs.empty())
        token_legs = std::addressof(self.value().token_legs);

      wire::object(dest,
        wire::field("id", std::uint64_t(self.index())),
        wire::field("hash", std::cref(self.value().info.link.tx_hash)),
        wire::field("timestamp", iso_timestamp(self.value().info.timestamp)),
        wire::field("total_received", safe_uint64(self.value().info.spend_meta.amount)),
        wire::field("total_sent", safe_uint64(self.value().spent)),
        wire::field("unlock_time", self.value().info.unlock_time),
        wire::field("height", self.value().info.link.height),
        wire::optional_field("payment_id", payment_id),
        wire::field("coinbase", is_coinbase),
        wire::field("mempool", false),
        wire::field("mixin", self.value().info.spend_meta.mixin_count),
        wire::field("spent_outputs", std::cref(self.value().spends)),
        // HF22: one entry per token this transaction moved. Omitted entirely
        // for an ordinary BDX transaction, so those are byte-for-byte what
        // they always were.
        wire::optional_field("token_legs", token_legs)
      );
    }
  } // rpc
  void rpc::write_bytes(wire::json_writer& dest, const get_address_txs_response& self)
  {
    wire::object(dest,
      wire::field("total_received", safe_uint64(self.total_received)),
      wire::field("locked_funds", safe_uint64(self.locked_funds)),
      WIRE_FIELD_COPY(scanned_height),
      WIRE_FIELD_COPY(scanned_block_height),
      WIRE_FIELD_COPY(start_height),
      WIRE_FIELD_COPY(transaction_height),
      WIRE_FIELD_COPY(blockchain_height),
      WIRE_FIELD_COPY(next_min_height),
      wire::field("transactions", wire::as_array(boost::adaptors::index(self.transactions)))
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const token_balance_entry& self)
  {
    wire::object(dest,
      WIRE_FIELD(token_id),
      WIRE_FIELD(status),
      WIRE_FIELD_COPY(total_received),
      WIRE_FIELD_COPY(total_sent),
      WIRE_FIELD_COPY(locked_funds),
      WIRE_FIELD_COPY(unlocked_balance),
      WIRE_FIELD(ticker),
      WIRE_FIELD(full_name),
      WIRE_FIELD(owner),
      WIRE_FIELD(meta_info),
      WIRE_FIELD_COPY(current_supply),
      WIRE_FIELD_COPY(total_max_supply),
      WIRE_FIELD_COPY(decimal_point)
    );
  }
  void rpc::read_bytes(wire::json_reader& source, get_token_balances_request& self)
  {
    std::string address;
    boost::optional<std::vector<std::string>> token_ids;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      wire::optional_field("token_ids", std::ref(token_ids))
    );
    if (token_ids)
      self.token_ids = std::move(*token_ids);
    convert_address(address, self.creds.address);
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_token_balances_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(tokens),
      WIRE_FIELD_COPY(scanned_height),
      WIRE_FIELD_COPY(blockchain_height)
    );
  }

  void rpc::read_bytes(wire::json_reader& source, get_token_info_request& self)
  {
    wire::object(source, WIRE_FIELD(token_id));
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_token_info_response& self)
  {
    wire::object(dest,
      WIRE_FIELD(token_id),
      WIRE_FIELD(ticker),
      WIRE_FIELD(full_name),
      WIRE_FIELD(owner),
      WIRE_FIELD(meta_info),
      WIRE_FIELD_COPY(current_supply),
      WIRE_FIELD_COPY(total_max_supply),
      WIRE_FIELD_COPY(decimal_point)
    );
  }
  void rpc::read_bytes(wire::json_reader& source, get_token_list_request& self)
  {
    // Both fields are optional; the struct's defaults (offset 0, count 100)
    // stand when the caller omits them.
    boost::optional<std::uint64_t> offset;
    boost::optional<std::uint64_t> count;
    wire::object(source,
      wire::optional_field("offset", std::ref(offset)),
      wire::optional_field("count", std::ref(count))
    );
    if (offset) self.offset = *offset;
    if (count)  self.count  = *count;
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_token_list_response& self)
  {
    wire::object(dest, WIRE_FIELD(token_ids), WIRE_FIELD_COPY(total_count));
  }

  void rpc::read_bytes(wire::json_reader& source, get_random_outs_request& self)
  {
    boost::optional<std::vector<std::string>> token_ids;
    wire::object(source,
      WIRE_FIELD(count),
      WIRE_FIELD(amounts),
      wire::optional_field("token_ids", std::ref(token_ids))
    );
    if (token_ids)
      self.token_ids = std::move(*token_ids);
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_random_outs_response& self)
  {
    wire::object(dest, WIRE_FIELD(amount_outs));
  }

  void rpc::read_bytes(wire::json_reader& source, get_unspent_outs_request& self)
  {
    std::string address;
    boost::optional<std::uint64_t> min_height;
    boost::optional<std::uint64_t> max_count;
    boost::optional<std::string> token_id;
    boost::optional<bool> all_tokens;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      WIRE_FIELD(amount),
      WIRE_OPTIONAL_FIELD(mixin),
      WIRE_OPTIONAL_FIELD(use_dust),
      WIRE_OPTIONAL_FIELD(dust_threshold),
      wire::optional_field("min_height", std::ref(min_height)),
      wire::optional_field("max_count", std::ref(max_count)),
      wire::optional_field("token_id", std::ref(token_id)),
      wire::optional_field("all_tokens", std::ref(all_tokens))
    );
    if (token_id)
      self.token_id = std::move(*token_id);
    self.all_tokens = all_tokens.value_or(false);
    convert_address(address, self.creds.address);
    self.min_height = min_height.value_or(0);
    self.max_count = max_count.value_or(0);
  }
  void rpc::write_bytes(wire::json_writer& dest, const get_unspent_outs_response& self)
  {
    const auto expand = [&self] (const std::pair<db::output, std::vector<crypto::key_image>>& src)
    {
      return expand_outputs{src, self.user_key};
    };
    wire::object(dest,
      // WIRE_FIELD_COPY(per_byte_fee),
      WIRE_FIELD_COPY(fee_per_byte),
      WIRE_FIELD_COPY(fee_per_output),
      WIRE_FIELD_COPY(flash_fee_per_byte),
      WIRE_FIELD_COPY(flash_fee_per_output),
      WIRE_FIELD_COPY(flash_fee_fixed),
      WIRE_FIELD_COPY(quantization_mask),
      WIRE_FIELD_COPY(fork_version),
      // WIRE_FIELD_COPY(fee_mask),
      WIRE_FIELD_COPY(amount),
      WIRE_FIELD_COPY(next_min_height),
      WIRE_FIELD_COPY(blockchain_height),
      wire::field("outputs", wire::as_array(std::cref(self.outputs), expand))
    );
  }

  void rpc::write_bytes(wire::json_writer& dest, const import_response& self)
  {
    wire::object(dest,
      WIRE_FIELD_COPY(import_fee),
      WIRE_FIELD_COPY(status),
      WIRE_FIELD_COPY(new_request),
      WIRE_FIELD_COPY(request_fulfilled)
    );
  }

  void rpc::read_bytes(wire::json_reader& source, login_request& self)
  {
    std::string address;
    wire::object(source,
      wire::field("address", std::ref(address)),
      wire::field("view_key", std::ref(unwrap(unwrap(self.creds.key)))),
      WIRE_FIELD(create_account),
      WIRE_FIELD(generated_locally)
    );
    convert_address(address, self.creds.address);
  }
  void rpc::write_bytes(wire::json_writer& dest, const login_response self)
  {
    wire::object(dest, WIRE_FIELD_COPY(new_address), WIRE_FIELD_COPY(generated_locally));
  }

  void rpc::read_bytes(wire::json_reader& source, submit_raw_tx_request& self)
  {
    wire::object(source, WIRE_FIELD(tx),
    WIRE_FIELD(fee)
    );
  }
  void rpc::write_bytes(wire::json_writer& dest, const submit_raw_tx_response self)
  {
    wire::object(dest, WIRE_FIELD_COPY(status));
  }
} // lws
