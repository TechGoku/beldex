#include "daemon_zmq.h"

#include <boost/optional/optional.hpp>
#include <string>
#include <utility>
#include <vector>
#include "crypto/crypto.h"            // monero/src
#include "epee/hex.h"                 // monero/contrib/epee/include
#include "epee/span.h"                // monero/contrib/epee/include
#include "rpc/message_data_structs.h" // monero/src
#include "wire/crypto.h"
#include "wire/error.h"
#include "wire/json.h"
#include "wire/vector.h"
#include "wire/read.h"
#include "cryptonote_basic/txtypes.h"

namespace
{
  constexpr const std::size_t default_blocks_fetched = 1000;
  constexpr const std::size_t default_transaction_count = 100;
  constexpr const std::size_t default_inputs = 2;
  constexpr const std::size_t default_outputs = 4;
  // tx.extra is a few dozen bytes for a normal tx (pubkey + nonce) and at most
  // a few KB for special txs; reserve a small amount to avoid reallocs. The
  // previous value (~40 MB) reserved that much PER transaction, and a
  // get_blocks_fast batch holds every parsed tx at once, so a tx-heavy batch
  // reserved (txs x 40 MB) of address space at once - allocator thrash / OOM
  // that manifested as the scanner hanging on large, tx-heavy accounts.
  constexpr const std::size_t default_txextra_size = 1024;

  /*! Beldex `get_blocks_fast` double-encodes each `block`, each `transaction`,
      and `output_indices` as a JSON *string*. This wrapper reads the field once:
      if the next value is a JSON string, parse its contents as `T`; otherwise
      read `T` in place. Mirrors the old scanner's `is_string()` un-stringify,
      but without a separate nlohmann parse + re-serialize + re-parse pass. */
  template<typename T>
  struct maybe_stringified
  {
    T value;
  };

  template<typename T>
  void read_bytes(wire::json_reader& source, maybe_stringified<T>& self)
  {
    if (source.peek_token() == '"')
    {
      auto parsed = wire::json::from_bytes<T>(source.string());
      if (!parsed)
        WIRE_DLOG_THROW(wire::error::schema::object,
          "invalid stringified nested json: " << parsed.error().message());
      self.value = std::move(*parsed);
    }
    else
      wire::read_value(source, self.value); // already a native object/array
  }

  /*! Reads an array of hashes, silently dropping JSON `null` entries. Beldex
      `get_blocks_fast` can include null placeholders in a block's `tx_hashes`;
      the old nlohmann normalization dropped them before the struct parse. */
  struct tx_hash_dropnull
  {
    std::vector<crypto::hash>* out;
  };

  void read_bytes(wire::json_reader& source, tx_hash_dropnull self)
  {
    self.out->clear();
    // Beldex sends `"tx_hashes": null` for a block with no non-coinbase txs;
    // the old nlohmann path iterated the null as empty. Treat null as [].
    if (source.try_read_null())
      return;
    std::size_t count = source.start_array();
    while (!source.is_array_end(count))
    {
      if (source.try_read_null())
      {
        ++count;
        continue;
      }
      self.out->emplace_back();
      wire::read_value(source, self.out->back());
      ++count;
    }
    source.end_array(); // balance start_array() so depth() returns to 0
  }

  /*! Reads a block's `transactions`: a (possibly null) array whose elements are
      each JSON-in-string (or native). Null becomes empty, matching the old
      nlohmann path. */
  struct transactions_field
  {
    std::vector<cryptonote::transaction>* out;
  };

  void read_bytes(wire::json_reader& source, transactions_field self)
  {
    self.out->clear();
    if (source.try_read_null()) // "transactions": null -> empty
      return;
    std::size_t count = source.start_array();
    while (!source.is_array_end(count))
    {
      ++count;
      // A real transaction is always a JSON object (native `{...}` or a
      // stringified `"{...}"`). Beldex pads an empty block's transactions with
      // a junk placeholder - a stringified empty array `"[]"` - which the old
      // nlohmann path swallowed (it parsed to [], then the count fixup cleared
      // the whole transactions list). Skip any element that is not an object.
      const char tok = source.peek_token();
      if (tok == '"')
      {
        std::string elem = source.string();
        const std::size_t first = elem.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || elem[first] != '{')
          continue; // junk placeholder (e.g. "[]") -> skip
        auto parsed = wire::json::from_bytes<cryptonote::transaction>(std::move(elem));
        if (!parsed)
          WIRE_DLOG_THROW(wire::error::schema::object, "invalid stringified transaction");
        self.out->push_back(std::move(*parsed));
      }
      else if (tok == '{')
      {
        self.out->emplace_back();
        wire::read_value(source, self.out->back());
      }
      else
        source.skip_next_value(); // native non-object element -> skip
    }
    source.end_array(); // balance start_array() so depth() returns to 0
  }
}

namespace lws
{
namespace rpc
{
  //! Reads one Beldex `minor_tx_hashes` entry: the 2-element array `[height, hash]`.
  static void read_bytes(wire::json_reader& source, minor_tx_hash_entry& self)
  {
    std::size_t count = source.start_array();
    if (source.is_array_end(count))
      WIRE_DLOG_THROW(wire::error::schema::array, "empty minor_tx_hashes entry");
    wire::read_value(source, self.height);
    ++count;
    if (source.is_array_end(count))
      WIRE_DLOG_THROW(wire::error::schema::array, "minor_tx_hashes entry missing hash");
    wire::read_value(source, self.hash);
    ++count;
    if (!source.is_array_end(count))
      WIRE_DLOG_THROW(wire::error::schema::array, "minor_tx_hashes entry has extra elements");
    source.end_array(); // balance start_array() so depth() returns to 0
  }
} // rpc
} // lws

namespace rct
{

  static void read_bytes(wire::json_reader& source, ctkey& self)
  {
    self.dest = {};
    read_bytes(source, self.mask);
  }

  static void read_bytes(wire::json_reader& source, ecdhTuple& self)
  {
    // Normalization moved here from the scanner's old nlohmann pre-pass so the
    // response is parsed only once. Behaviour is byte-for-byte identical:
    //   - mask is forced to all-zero (the real mask is recomputed by the
    //     scanner during amount decoding), matching the old
    //     `it["mask"] = "0000...0000"`.
    //   - amount arrives as an 8-byte (16 hex) value; the old code appended 48
    //     '0' chars when the length wasn't already 64, then read it as a
    //     32-byte key (amount bytes first, remainder zero). Reproduced exactly.
    self.mask = rct::key{}; // 32 zero bytes

    std::string amount_hex;
    wire::object(source, wire::field("amount", std::ref(amount_hex)));

    if (amount_hex.size() != 64)
      amount_hex.append(48, '0');
    if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(self.amount), amount_hex))
      WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "bad ecdh amount hex length");
  }

  static void read_bytes(wire::json_reader& source, rctSig& self)
  {
    boost::optional<std::vector<ecdhTuple>> ecdhInfo;
    boost::optional<ctkeyV> outPk;
    boost::optional<xmr_amount> txnFee;

    self.outPk.reserve(default_inputs);
    wire::object(source,
      WIRE_FIELD(type),
      wire::optional_field("ecdhInfo", std::ref(ecdhInfo)),
      wire::optional_field("outPk", std::ref(outPk)),
      wire::optional_field("txnFee", std::ref(txnFee))
    );

    // std::cout << "txnFee :" << txnFee << std::endl;
    // std::cout << "self.type != RCTType::Null : " << (self.type != RCTType::Null) << "\n";
    if (ecdhInfo || outPk || txnFee){  //|| txnFee
      self.ecdhInfo = std::move(*ecdhInfo);
      self.outPk = std::move(*outPk);
      self.txnFee = std::move(*txnFee);
    }

    // if (self.type != RCTType::Null)
    // {
    //   std::cout << "enterd into the next in RCT condition\n";
    //   if (!ecdhInfo || !outPk || !txnFee)
    //     WIRE_DLOG_THROW(wire::error::schema::missing_key, "Expected fields `encrypted`, `commitments`, and `fee`");
    //   self.ecdhInfo = std::move(*ecdhInfo);
    //   self.outPk = std::move(*outPk);
    //   self.txnFee = std::move(*txnFee);
    // }
    // else if (ecdhInfo || outPk || txnFee)
    //   WIRE_DLOG_THROW(wire::error::schema::invalid_key, "Did not expected `encrypted`, `commitments`, or `fee`");
  }
  
  static void read_bytes(wire::json_reader& source, RCTType& self)
  {
    unsigned char dest = (unsigned char)self;
    wire::read_bytes(source, dest);
  }

} // rct

namespace cryptonote
{
  static void read_bytes(wire::json_reader& source,cryptonote::txversion& self)
  {
    uint8_t value;
    wire::read_bytes(source, value);  // read as an integer first
    self = static_cast<cryptonote::txversion>(value); // cast to enum or custom type
  }

  inline void read_bytes(wire::json_reader& source, cryptonote::hf& self)
  {
      // assuming `cryptonote::hf` is an enum or has a from_string/from_int method
      uint8_t value;
      wire::read_bytes(source, value);  // read as an integer first
      self = static_cast<cryptonote::hf>(value); // cast to enum or custom type
  }

  static void read_bytes(wire::json_reader& source, txout_to_script& self)
  {
    wire::object(source, WIRE_FIELD(keys), WIRE_FIELD(script));
  }
  static void read_bytes(wire::json_reader& source, txout_to_scripthash& self)
  {
    wire::object(source, WIRE_FIELD(hash));
  }
  static void read_bytes(wire::json_reader& source, txout_to_key& self)
  {
    // The daemon nests the output type inside "target" as {"key": "<hex>"},
    // so by the time this runs the reader is positioned on the bare key.
    wire::read_bytes(source, self.key);
  }
  static void read_bytes(wire::json_reader& source, tx_out_zarcanum& self)
  {
    wire::object(source,
      wire::field("stealth_address", std::ref(self.stealth_address)),
      wire::field("amount_commitment", std::ref(self.amount_commitment)),
      wire::field("blinded_token_id", std::ref(self.blinded_token_id)),
      wire::field("encrypted_amount", std::ref(self.encrypted_amount)),
      wire::field("mix_attr", std::ref(self.mix_attr)),
      wire::field("version", std::ref(self.version))
    );
  }
  static void read_bytes(wire::json_reader& source, txout_target_v& self)
  {
    // "target" holds a single-key object naming the output type -- the same
    // shape txin_v uses. HF22 adds "zarcanum"; without it every block carrying
    // a privacy-token output fails to parse and kills the scanner.
    wire::object(source,
      wire::variant_field("transaction output variant", std::ref(self),
        wire::option<txout_to_key>{"key"},
        wire::option<tx_out_zarcanum>{"zarcanum"},
        wire::option<txout_to_script>{"to_script"},
        wire::option<txout_to_scripthash>{"to_scripthash"}
      )
    );
  }
  static void read_bytes(wire::json_reader& source, tx_out& self)
  {
    wire::object(source,
      WIRE_FIELD(amount),
      wire::field("target", std::ref(self.target))
    );
  }

  static void read_bytes(wire::json_reader& source, txin_gen& self)
  {
    wire::object(source, WIRE_FIELD(height));
  }
  static void read_bytes(wire::json_reader& source, txin_to_script& self)
  {
    wire::object(source, WIRE_FIELD(prev), WIRE_FIELD(prevout), WIRE_FIELD(sigset));
  }
  static void read_bytes(wire::json_reader& source, txin_to_scripthash& self)
  {
    wire::object(source, WIRE_FIELD(prev), WIRE_FIELD(prevout), WIRE_FIELD(script), WIRE_FIELD(sigset));
  }
  static void read_bytes(wire::json_reader& source, txin_to_key& self)
  {
    wire::object(source, WIRE_FIELD(amount), WIRE_FIELD(key_offsets), wire::field("k_image", std::ref(self.k_image)));
  }
  /* HF22: the input side of a privacy-token spend.

     Mirrors tx_out_zarcanum on the output side. A token output is consumed by
     this variant rather than txin_to_key, so any transaction that SPENDS a
     token - a burn, a mint, a transfer - carries one. Without it the reader
     throws "Schema expected object" on the whole get_blocks_fast reply and the
     scan threads die, which takes the light wallet server down with them: not
     just the token accounts, every account, from the first such block onward.

     The shape is txin_to_key's minus `amount` - a token amount is hidden in the
     commitment and is not on the input. */
  static void read_bytes(wire::json_reader& source, txin_zc_input& self)
  {
    wire::object(source,
      WIRE_FIELD(key_offsets),
      wire::field("k_image", std::ref(self.k_image))
    );
  }
  static void read_bytes(wire::json_reader& source, txin_v& self)
  {
    wire::object(source,
      wire::variant_field("transaction input variant", std::ref(self),
        wire::option<txin_to_key>{"key"},
        wire::option<txin_gen>{"gen"},
        wire::option<txin_zc_input>{"zc_input"},
        wire::option<txin_to_script>{"to_script"},
        wire::option<txin_to_scripthash>{"to_scripthash"}
      )
    );
  }

  static void read_bytes(wire::json_reader& source, transaction& self)
  {
    self.vin.reserve(default_inputs);
    self.vout.reserve(default_outputs);
    self.extra.reserve(default_txextra_size);
    // `rct_signatures` is optional: a default-constructed transaction already
    // has `rct_signatures.type == RCTType::Null` (see transaction::set_null),
    // so an absent field reproduces the old code's "add {rct_signatures:{type:0}}"
    // fixup for a miner_tx that lacks it. (optional_field needs a boost::optional
    // target, hence the temporary.)
    boost::optional<rct::rctSig> rct_signatures;
    boost::optional<std::vector<std::uint64_t>> output_unlock_times;
    wire::object(source,
      WIRE_FIELD(version),
      WIRE_FIELD(unlock_time),
      wire::field("vin", std::ref(self.vin)),
      wire::field("vout", std::ref(self.vout)),
      WIRE_FIELD(extra),
      // Since txversion v3 the per-output unlock times are the authoritative
      // ones and tx.unlock_time is a legacy tx-wide value. Without reading
      // these, transaction::get_unlock_time() falls back to that 0 and every
      // time-locked output -- an HF22 registration's collateral above all --
      // is recorded as immediately spendable. Optional: a v1/v2 tx has none.
      wire::optional_field("output_unlock_times", std::ref(output_unlock_times)),
      wire::optional_field("rct_signatures", std::ref(rct_signatures))
    );
    if (output_unlock_times)
      self.output_unlock_times = std::move(*output_unlock_times);
    if (rct_signatures)
      self.rct_signatures = std::move(*rct_signatures);
  }

  static void read_bytes(wire::json_reader& source, block& self)
  {
    self.tx_hashes.reserve(default_transaction_count);
    // `tx_hashes` is read with the null-dropping reader (see tx_hash_dropnull):
    // Beldex can include null placeholders that the old nlohmann pass removed.
    wire::object(source,
      WIRE_FIELD(major_version),
      WIRE_FIELD(minor_version),
      WIRE_FIELD(timestamp),
      WIRE_FIELD(miner_tx),
      wire::field("tx_hashes", tx_hash_dropnull{std::addressof(self.tx_hashes)}),
      WIRE_FIELD(prev_id),
      WIRE_FIELD(nonce)
    );
  }

  namespace rpc
  {
    static void read_bytes(wire::json_reader& source, block_with_transactions& self)
    {
      // Both `block` and each element of `transactions` arrive JSON-in-string;
      // they are un-stringified before being read as their real type (reusing
      // the block/transaction readers above, incl. ecdh normalization).
      // `transactions` may also be null (empty block).
      maybe_stringified<cryptonote::block> block;
      self.transactions.reserve(default_transaction_count);

      wire::object(source,
        wire::field("block", std::ref(block)),
        wire::field("transactions", transactions_field{std::addressof(self.transactions)})
      );

      self.block = std::move(block.value);
    }
  } // rpc
} // cryptonote

void lws::rpc::read_bytes(wire::json_reader& source, get_blocks_fast_response& self)
{
  self.blocks.reserve(default_blocks_fetched);

  // `output_indices` arrives JSON-in-string (or, defensively, as a native
  // array); un-stringify it the same way as block/transactions.
  maybe_stringified<std::vector<std::vector<std::vector<std::uint64_t>>>> output_indices;
  output_indices.value.reserve(default_blocks_fetched);

  // `minor_tx_hashes` and `status` are optional and were consumed by the old
  // scanner pre-pass before the struct parse; capture them here instead.
  boost::optional<std::vector<minor_tx_hash_entry>> minor_tx_hashes;
  boost::optional<std::string> status;

  wire::object(source,
    WIRE_FIELD(blocks),
    wire::field("output_indices", std::ref(output_indices)),
    WIRE_FIELD(start_height),
    WIRE_FIELD(current_height),
    wire::optional_field("minor_tx_hashes", std::ref(minor_tx_hashes)),
    wire::optional_field("status", std::ref(status))
  );

  self.output_indices = std::move(output_indices.value);
  if (minor_tx_hashes)
    self.minor_tx_hashes = std::move(*minor_tx_hashes);
  if (status)
    self.status = std::move(*status);
}