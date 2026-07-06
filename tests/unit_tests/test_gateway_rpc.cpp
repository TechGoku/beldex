// Unit test for the gateway read-only RPC request parsing (GET_GATEWAY_INFO,
// GET_GATEWAY_TX_HISTORY). This only exercises request parsing (hex string -> crypto type
// conversion via get_values()); it does not stand up a live core_rpc_server/daemon.
#include <gtest/gtest.h>
#include "rpc/core_rpc_server_command_parser.h"
#include "common/hex.h"

using namespace cryptonote::rpc;

TEST(gateway_rpc, get_gateway_info_parses_required_and_optional_fields)
{
  crypto::public_key gw{};
  crypto::public_key asset{};
  memset(&gw, 0x11, sizeof(gw));
  memset(&asset, 0x22, sizeof(asset));

  nlohmann::json j{
    {"gateway_address_id", tools::type_to_hex(gw)},
    {"asset_id", tools::type_to_hex(asset)},
  };
  rpc_input in{j};

  GET_GATEWAY_INFO info;
  ASSERT_NO_THROW(parse_request(info, in));
  ASSERT_EQ(info.request.gateway_address_id, gw);
  ASSERT_TRUE(info.request.asset_id.has_value());
  ASSERT_EQ(*info.request.asset_id, asset);
}

TEST(gateway_rpc, get_gateway_info_asset_id_is_optional)
{
  crypto::public_key gw{};
  memset(&gw, 0x33, sizeof(gw));

  nlohmann::json j{{"gateway_address_id", tools::type_to_hex(gw)}};
  rpc_input in{j};

  GET_GATEWAY_INFO info;
  ASSERT_NO_THROW(parse_request(info, in));
  ASSERT_EQ(info.request.gateway_address_id, gw);
  ASSERT_FALSE(info.request.asset_id.has_value());
}

TEST(gateway_rpc, get_gateway_info_requires_gateway_address_id)
{
  nlohmann::json j = nlohmann::json::object();
  rpc_input in{j};

  GET_GATEWAY_INFO info;
  ASSERT_THROW(parse_request(info, in), std::runtime_error);
}

TEST(gateway_rpc, get_gateway_tx_history_parses_hash_list)
{
  crypto::hash h1{}, h2{};
  memset(&h1, 0x44, sizeof(h1));
  memset(&h2, 0x55, sizeof(h2));

  nlohmann::json j{{"tx_hashes", nlohmann::json::array({tools::type_to_hex(h1), tools::type_to_hex(h2)})}};
  rpc_input in{j};

  GET_GATEWAY_TX_HISTORY history;
  ASSERT_NO_THROW(parse_request(history, in));
  ASSERT_EQ(2u, history.request.tx_hashes.size());
  ASSERT_EQ(h1, history.request.tx_hashes[0]);
  ASSERT_EQ(h2, history.request.tx_hashes[1]);
}
