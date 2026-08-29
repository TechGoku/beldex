#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common/expect.h" // monero/src
#include "crypto/crypto.h" // monero/src
#include "db/data.h"
// #include "rpc/rates.h"
#include "util/fwd.h"
#include "wire/json/fwd.h"


namespace lws
{
namespace rpc
{
    
    //! Read/write uint64 value as JSON string.
    enum class safe_uint64 : std::uint64_t {};
    void read_bytes(wire::json_reader&, safe_uint64&);
    void write_bytes(wire::json_writer&, safe_uint64);

    //! Read an array of uint64 values as JSON strings.
    struct safe_uint64_array
    {
      std::vector<std::uint64_t> values; // so this can be passed to another function without copy
    };
    void read_bytes(wire::json_reader&, safe_uint64_array&);

    struct transaction_spend
    {
      transaction_spend() = delete;
      lws::db::output::spend_meta_ meta;
      lws::db::spend possible_spend;
      //! Emit the `height` field; set only for an incremental/paginated request.
      bool with_height;
    };
    void write_bytes(wire::json_writer&, const transaction_spend&);

    struct account_credentials
    {
      lws::db::account_address address;
      crypto::secret_key key;
    };
    void read_bytes(wire::json_reader&, account_credentials&);

    //! get_address_txs request: credentials plus an optional incremental cursor.
    //! `min_height` defaults to 0 (return the full history, unchanged behavior);
    //! a client that sends the height it last synced to gets back only the txs
    //! at height >= min_height, turning a full-history refresh into a small delta.
    struct get_address_txs_request
    {
      account_credentials creds;
      std::uint64_t min_height = 0; //!< return only txs with height >= min_height
      std::uint64_t max_count = 0;  //!< 0 = unbounded; else cap transactions per page (whole blocks)
    };
    void read_bytes(wire::json_reader&, get_address_txs_request&);

    //! get_address_info request: credentials plus the same optional incremental
    //! cursor as get_address_txs. `min_height` defaults to 0 (full history); a
    //! client that sends the height it last synced to gets back only the
    //! `spent_outputs` at height >= min_height, while the scalar totals stay
    //! cumulative over the whole account. Turns the (potentially hundreds of MB)
    //! spent_outputs dump into a small delta.
    struct get_address_info_request
    {
      account_credentials creds;
      std::uint64_t min_height = 0; //!< return only spent_outputs with height >= min_height
      std::uint64_t max_count = 0;  //!< 0 = unbounded; else cap spent_outputs per page (whole blocks)
    };
    void read_bytes(wire::json_reader&, get_address_info_request&);

    /*! One HF22 privacy token held by the account.

        Amounts are in that token's own atomic units - the scale is set by the
        descriptor's decimal_point, which lives on the daemon and not here, so a
        client that wants to display these must resolve it via get_token_info.
        Reported as three numbers rather than one balance for the same reason the
        native side is: the client decides whether it wants the spendable figure
        or the total. */
    struct token_balance
    {
      token_balance() = delete;
      crypto::public_key token_id;
      safe_uint64 total_received;
      safe_uint64 total_sent;
      safe_uint64 locked_funds;
    };
    void write_bytes(wire::json_writer&, const token_balance&);

    struct get_address_info_response
    {
      get_address_info_response() noexcept
        : locked_funds(safe_uint64(0)),
          total_received(safe_uint64(0)),
          total_sent(safe_uint64(0)),
          scanned_height(0),
          scanned_block_height(0),
          start_height(0),
          transaction_height(0),
          blockchain_height(0),
          next_min_height(0),
          spent_outputs(),
          tokens()
          // rates(common_error::kInvalidArgument)
      {}

      safe_uint64 locked_funds;
      safe_uint64 total_received;
      safe_uint64 total_sent;
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::uint64_t next_min_height; //!< 0 = last page; else min_height for the next page
      std::vector<transaction_spend> spent_outputs;
      //! Empty for an account holding no tokens, which is every pre-HF22 wallet.
      std::vector<token_balance> tokens;
      // expect<lws::rates> rates;
    };
    void write_bytes(wire::json_writer&, const get_address_info_response&);

    struct get_address_txs_response
    {
      get_address_txs_response() = delete;
      struct transaction
      {
        transaction() = delete;
        db::output info;
        std::vector<transaction_spend> spends;
        std::uint64_t spent;
        /*! HF22: what this entry moved, per token.

            Kept beside the BDX figures rather than folded into them: a token
            amount is denominated in its own token, so adding it to `info`'s
            amount would report a transfer of 1,200 POP as 1,200 BDX.

            A list rather than one id and one pair, because a single
            transaction can touch more than one token - and does so routinely
            even when the owner only moved one, since any of the account's
            outputs may appear as a decoy in the rings. Collapsing them summed
            unrelated tokens together and reported, for instance, 1,010 sent of
            a token the account had only ever held 1,000 of. Empty for an
            ordinary BDX transaction, which is every entry a pre-HF22 wallet
            will ever see. */
        struct token_leg
        {
          crypto::public_key token_id{};
          std::uint64_t received = 0;
          std::uint64_t sent = 0;
        };
        std::vector<token_leg> token_legs;

        //! \return The leg for `id`, appending one if this is its first sight.
        token_leg& leg(const crypto::public_key& id)
        {
          for (token_leg& l : token_legs)
            if (l.token_id == id)
              return l;
          token_legs.push_back(token_leg{id, 0, 0});
          return token_legs.back();
        }
      };

      safe_uint64 total_received;
      safe_uint64 locked_funds; //!< server-authoritative (view-key derivable); cumulative even in an incremental response
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::uint64_t next_min_height; //!< 0 = last page; else min_height for the next page
      std::vector<transaction> transactions;
    };
    void write_bytes(wire::json_writer&, const get_address_txs_response&);

    enum class daemon_state : std::uint8_t
    {
      ok = 0,
      no_connections,
      synchronizing,
      unavailable
    };
    WIRE_DECLARE_ENUM(daemon_state);
  
    enum class network_type : std::uint8_t
    {
      main = 0,
      test,
      stage,
      fake
    };
    WIRE_DECLARE_ENUM(network_type);
  struct daemon_status_request
  {
    daemon_status_request() = delete;
  };
  inline void read_bytes(const wire::reader&, const daemon_status_request&)
  {}

  struct daemon_status_response
  {
    //! Defaults to current network in unavailable state
    daemon_status_response() = default;

    std::uint64_t outgoing_connections_count;
    std::uint64_t incoming_connections_count;
    std::uint64_t height;
    std::uint64_t target_height;
    network_type network;
    daemon_state state;
  };
  void write_bytes(wire::json_writer&, const daemon_status_response&);


    /*! One token in a get_token_balances reply: what the account holds, and
        what the token is.

        The two halves come from different places - holdings from the outputs
        this server scanned, identity from the daemon's blockchain database - and
        a wallet needs both to render a single row. Fetching them separately cost
        one request per token on top of the balance call; this carries them
        together. */
    struct token_balance_entry
    {
      token_balance_entry() = default;

      std::string token_id;

      //! "confirmed" when the chain describes this token, "not_found" when it
      //! does not, "unknown" when the daemon could not be asked.
      std::string status;

      //! Atomic units in this token's own scale. unlocked = received - sent - locked.
      safe_uint64 total_received{safe_uint64(0)};
      safe_uint64 total_sent{safe_uint64(0)};
      safe_uint64 locked_funds{safe_uint64(0)};
      safe_uint64 unlocked_balance{safe_uint64(0)};

      //! Descriptor, present only when status is "confirmed".
      std::string ticker;
      std::string full_name;
      std::string owner;
      std::string meta_info;
      safe_uint64 current_supply{safe_uint64(0)};
      safe_uint64 total_max_supply{safe_uint64(0)};
      std::uint32_t decimal_point = 0;
    };
    void write_bytes(wire::json_writer&, const token_balance_entry&);

    struct get_token_balances_request
    {
      get_token_balances_request() = default;
      account_credentials creds;
      /*! Extra ids to report on beyond what the account holds.

          A registration that has been broadcast but not yet mined leaves the
          wallet holding nothing, so it would otherwise be invisible here -
          which is the moment its owner most wants to know where it stands. */
      std::vector<std::string> token_ids;
    };
    void read_bytes(wire::json_reader&, get_token_balances_request&);

    struct get_token_balances_response
    {
      get_token_balances_response() = default;
      std::vector<token_balance_entry> tokens;
      std::uint64_t scanned_height = 0;
      std::uint64_t blockchain_height = 0;
    };
    void write_bytes(wire::json_writer&, const get_token_balances_response&);

    /* ── HF22 privacy tokens: descriptor lookups ────────────────────────
       Forwarded to the daemon, which is the only holder of token state. They
       carry no credentials because they read nothing account-specific: a token
       descriptor is public chain data, exactly like a block header. */

    struct get_token_info_request
    {
      get_token_info_request() = delete;
      std::string token_id;   //!< 64 hex characters
    };
    void read_bytes(wire::json_reader&, get_token_info_request&);

    struct get_token_info_response
    {
      get_token_info_response() = default;
      std::string token_id;
      std::string ticker;
      std::string full_name;
      std::string owner;
      std::string meta_info;
      //! Atomic units, scaled by decimal_point.
      safe_uint64 current_supply{safe_uint64(0)};
      safe_uint64 total_max_supply{safe_uint64(0)};
      std::uint32_t decimal_point = 0;
    };
    void write_bytes(wire::json_writer&, const get_token_info_response&);

    struct get_token_list_request
    {
      get_token_list_request() = default;
      std::uint64_t offset = 0;
      std::uint64_t count = 100;
    };
    void read_bytes(wire::json_reader&, get_token_list_request&);

    struct get_token_list_response
    {
      get_token_list_response() = default;
      std::vector<std::string> token_ids;
      std::uint64_t total_count = 0;
    };
    void write_bytes(wire::json_writer&, const get_token_list_response&);

    struct get_random_outs_request
    {
      get_random_outs_request() = delete;
      std::uint64_t count;
      safe_uint64_array amounts;
      /*! Parallel to `amounts`: the token each ring is for, "" for native.

          A ring must be drawn from outputs of the same kind - native decoys in
          a token's ring produce a transaction the network rejects - and one
          transaction can need both, because a token transfer spends token
          outputs for the amount and native outputs for the BDX fee. So the
          choice is per ring. Omitted, or shorter than `amounts`, leaves the
          remaining rings native, which is what every existing caller expects. */
      std::vector<std::string> token_ids;
    };
    void read_bytes(wire::json_reader&, get_random_outs_request&);

    struct get_random_outs_response
    {
      get_random_outs_response() = delete;
      std::vector<random_ring> amount_outs;
    };
    void write_bytes(wire::json_writer&, const get_random_outs_response&);

    struct get_unspent_outs_request
    {
      get_unspent_outs_request() = delete;
      safe_uint64 amount;
      boost::optional<safe_uint64> dust_threshold;
      boost::optional<std::uint32_t> mixin;
      boost::optional<bool> use_dust;
      account_credentials creds;
      std::uint64_t min_height = 0; //!< return only outputs received at height >= min_height (incremental unspent pool)
      std::uint64_t max_count = 0;  //!< 0 = unbounded; else cap outputs per page (whole blocks)
      /*! Hex id of a privacy token to include alongside the native outputs.

          Empty means native only, which is what every pre-HF22 caller sends and
          what a BDX send must keep receiving - a token output picked up for a
          native send builds a transaction the daemon rejects outright.

          Set, the reply carries native outputs AND that one token's outputs.
          Both are needed in the same response because a token transfer spends
          two pools at once: token outputs for the amount, native outputs for
          the fee, which is always paid in BDX. The client separates them. */
      std::string token_id;
      /*! Return every token's outputs, not just one.

          A wallet cannot trust the server's per-token `total_sent`: this server
          is view-only, so it counts a spend for any ring member it owns and
          cannot tell a decoy from a real spend. The wallet settles that itself
          by computing each output's key image and checking it against
          `spend_key_images` - the same test it already applies when choosing
          inputs. Doing that for every token in one request is what this flag is
          for; without it the wallet would need a call per token on every
          balance refresh. */
      bool all_tokens = false;
    };
    void read_bytes(wire::json_reader&, get_unspent_outs_request&);

    struct get_unspent_outs_response
    {
      get_unspent_outs_response() = delete;
      // std::uint64_t per_byte_fee;
      std::uint64_t fee_per_byte;
      std::uint64_t fee_per_output;
      std::uint64_t flash_fee_per_byte;
      std::uint64_t flash_fee_per_output;
      std::uint64_t flash_fee_fixed; 
      std::uint64_t quantization_mask;
      std::uint64_t fork_version;
      // std::uint64_t fee_mask;
      safe_uint64 amount;
      std::vector<std::pair<db::output, std::vector<crypto::key_image>>> outputs;
      crypto::secret_key user_key;
      std::uint64_t next_min_height; //!< 0 = last page; else min_height for the next page
      //! Current chain tip. HF22 token registration must lock its collateral
      //! output to an absolute height, so the client has to know where the
      //! chain is; nothing else in this response conveys that.
      std::uint64_t blockchain_height;
    };
    void write_bytes(wire::json_writer&, const get_unspent_outs_response&);

    struct import_response
    {
      import_response() = delete;
      safe_uint64 import_fee;
      const char* status;
      bool new_request;
      bool request_fulfilled;
    };
    void write_bytes(wire::json_writer&, const import_response&);

    struct login_request
    {
      login_request() = delete;
      account_credentials creds;
      bool create_account;
      bool generated_locally;
    };
    void read_bytes(wire::json_reader&, login_request&);

    struct login_response
    {
      login_response() = delete;
      bool new_address;
      bool generated_locally;
    };
    void write_bytes(wire::json_writer&, login_response);

      struct submit_raw_tx_request
    {
      submit_raw_tx_request() = delete;
      std::string tx;
      std::string fee;
    };
    void read_bytes(wire::json_reader&, submit_raw_tx_request&);

    struct submit_raw_tx_response
    {
      submit_raw_tx_response() = delete;
      const char* status;
    };
    void write_bytes(wire::json_writer&, submit_raw_tx_response);

} 
} //lws
