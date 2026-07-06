// Copyright (c) 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include <vector>

#include "common/util.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

namespace
{
  uint64_t const TEST_FEE = 5000000000; // 5 * 10^9
}

TEST(gateway_transaction_support, accepts_gateway_inputs_and_outputs)
{
  cryptonote::transaction tx{};
  tx.version = cryptonote::txversion::v2_ringct;
  tx.type = cryptonote::txtype::standard;

  cryptonote::keypair gateway_keypair{};
  crypto::generate_keys(gateway_keypair.pub, gateway_keypair.sec, gateway_keypair.sec, true);

  cryptonote::txin_gateway gateway_in{};
  gateway_in.amount = 42;
  gateway_in.gateway_addr = gateway_keypair.pub;
  gateway_in.asset_id = gateway_keypair.pub;
  tx.vin.emplace_back(gateway_in);

  cryptonote::tx_out gateway_out{};
  gateway_out.amount = 42;
  cryptonote::txout_gateway out_target{};
  out_target.gateway_addr = gateway_keypair.pub;
  out_target.asset_id = gateway_keypair.pub;
  out_target.amount = 42;
  gateway_out.target = out_target;
  tx.vout.emplace_back(gateway_out);

  uint64_t money = 0;
  ASSERT_TRUE(cryptonote::get_inputs_money_amount(tx, money));
  ASSERT_EQ(42, money);
  ASSERT_TRUE(cryptonote::check_inputs_types_supported(tx));
  ASSERT_TRUE(cryptonote::check_outs_valid(tx));
  ASSERT_TRUE(cryptonote::check_inputs_overflow(tx));
  ASSERT_TRUE(cryptonote::check_outs_overflow(tx));
}

TEST(gateway_transaction_support, rejects_malformed_gateway_inputs_and_outputs)
{
  cryptonote::transaction tx{};
  tx.version = cryptonote::txversion::v2_ringct;
  tx.type = cryptonote::txtype::standard;

  cryptonote::keypair gateway_keypair{};
  crypto::generate_keys(gateway_keypair.pub, gateway_keypair.sec, gateway_keypair.sec, true);

  cryptonote::txin_gateway malformed_in{};
  malformed_in.amount = 0;
  malformed_in.gateway_addr = gateway_keypair.pub;
  malformed_in.asset_id = gateway_keypair.pub;
  tx.vin.emplace_back(malformed_in);
  ASSERT_FALSE(cryptonote::check_inputs_types_supported(tx));

  cryptonote::transaction tx_out{};
  tx_out.version = cryptonote::txversion::v2_ringct;
  tx_out.type = cryptonote::txtype::standard;
  cryptonote::tx_out malformed_out{};
  malformed_out.amount = 0;
  cryptonote::txout_gateway malformed_target{};
  malformed_target.gateway_addr = gateway_keypair.pub;
  malformed_target.asset_id = gateway_keypair.pub;
  malformed_target.amount = 0;
  malformed_out.target = malformed_target;
  tx_out.vout.emplace_back(malformed_out);
  ASSERT_FALSE(cryptonote::check_outs_valid(tx_out));
}

TEST(parse_tx_extra, handles_empty_extra)
{
  std::vector<uint8_t> extra;
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_TRUE(tx_extra_fields.empty());
}

TEST(parse_tx_extra, handles_padding_only_size_1)
{
  const uint8_t extra_arr[] = {0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_padding>(tx_extra_fields[0]));
  ASSERT_EQ(1, var::get<cryptonote::tx_extra_padding>(tx_extra_fields[0]).size);
}

TEST(parse_tx_extra, handles_padding_only_size_2)
{
  const uint8_t extra_arr[] = {0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_padding>(tx_extra_fields[0]));
  ASSERT_EQ(2, var::get<cryptonote::tx_extra_padding>(tx_extra_fields[0]).size);
}

TEST(parse_tx_extra, handles_padding_only_max_size)
{
  std::vector<uint8_t> extra(cryptonote::TX_EXTRA_PADDING_MAX_COUNT, 0);
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_padding>(tx_extra_fields[0]));
  ASSERT_EQ(cryptonote::TX_EXTRA_PADDING_MAX_COUNT, var::get<cryptonote::tx_extra_padding>(tx_extra_fields[0]).size);
}

TEST(parse_tx_extra, handles_padding_only_exceed_max_size)
{
  std::vector<uint8_t> extra(cryptonote::TX_EXTRA_PADDING_MAX_COUNT + 1, 0);
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_FALSE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
}

TEST(parse_tx_extra, handles_invalid_padding_only)
{
  std::vector<uint8_t> extra(2, 0);
  extra[1] = 42;
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_FALSE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
}

TEST(parse_tx_extra, handles_pub_key_only)
{
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_pub_key>(tx_extra_fields[0]));
}

TEST(parse_tx_extra, handles_extra_nonce_only)
{
  const uint8_t extra_arr[] = {2, 1, 42};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(1, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_nonce>(tx_extra_fields[0]));
  cryptonote::tx_extra_nonce extra_nonce = var::get<cryptonote::tx_extra_nonce>(tx_extra_fields[0]);
  ASSERT_EQ(1, extra_nonce.nonce.size());
  ASSERT_EQ(42, extra_nonce.nonce[0]);
}

TEST(parse_tx_extra, handles_pub_key_and_padding)
{
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
  ASSERT_EQ(2, tx_extra_fields.size());
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_pub_key>(tx_extra_fields[0]));
  ASSERT_TRUE(std::holds_alternative<cryptonote::tx_extra_padding>(tx_extra_fields[1]));
}

TEST(parse_and_validate_tx_extra, is_valid_tx_extra_parsed)
{
  cryptonote::transaction tx{};
  cryptonote::account_base acc;
  acc.generate();
  cryptonote::blobdata b = "dsdsdfsdfsf";
  ASSERT_TRUE(cryptonote::construct_miner_tx(0, 0, 10000000000000, 1000, TEST_FEE, tx, cryptonote::beldex_miner_tx_context::miner_block(cryptonote::FAKECHAIN, acc.get_keys().m_account_address), b));
  crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(tx);
  ASSERT_NE(tx_pub_key, crypto::null_pkey);
}
TEST(parse_and_validate_tx_extra, fails_on_big_extra_nonce)
{
  cryptonote::transaction tx{};
  cryptonote::account_base acc;
  acc.generate();
  cryptonote::blobdata b(cryptonote::TX_EXTRA_NONCE_MAX_COUNT + 1, 0);
  ASSERT_FALSE(cryptonote::construct_miner_tx(0, 0, 10000000000000, 1000, TEST_FEE, tx, cryptonote::beldex_miner_tx_context::miner_block(cryptonote::FAKECHAIN, acc.get_keys().m_account_address), b));
}
TEST(parse_and_validate_tx_extra, fails_on_wrong_size_in_extra_nonce)
{
  cryptonote::transaction tx{};
  tx.extra.resize(20, 0);
  tx.extra[0] = cryptonote::TX_EXTRA_NONCE;
  tx.extra[1] = 255;
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  ASSERT_FALSE(cryptonote::parse_tx_extra(tx.extra, tx_extra_fields));
}
TEST(validate_parse_amount_case, validate_parse_amount)
{
  uint64_t res = 0;
  bool r = cryptonote::parse_amount(res, "0.0001");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 100000);

  r = cryptonote::parse_amount(res, "100.0001");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 100000100000);

  r = cryptonote::parse_amount(res, "000.0000");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 0);

  r = cryptonote::parse_amount(res, "0");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 0);


  r = cryptonote::parse_amount(res, "   100.0001    ");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 100000100000);

  r = cryptonote::parse_amount(res, "   100.0000    ");
  ASSERT_TRUE(r);
  ASSERT_EQ(res, 100000000000);

  r = cryptonote::parse_amount(res, "   100. 0000    ");
  ASSERT_FALSE(r);

  r = cryptonote::parse_amount(res, "100. 0000");
  ASSERT_FALSE(r);

  r = cryptonote::parse_amount(res, "100 . 0000");
  ASSERT_FALSE(r);

  r = cryptonote::parse_amount(res, "100.00 00");
  ASSERT_FALSE(r);

  r = cryptonote::parse_amount(res, "1 00.00 00");
  ASSERT_FALSE(r);
}

TEST(sort_tx_extra, empty)
{
  std::vector<uint8_t> extra, sorted;
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  ASSERT_EQ(extra, sorted);
}

TEST(sort_tx_extra, pubkey)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  ASSERT_EQ(extra, sorted);
}

TEST(sort_tx_extra, two_pubkeys)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
    1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  ASSERT_EQ(extra, sorted);
}

TEST(sort_tx_extra, keep_order)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
    2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  ASSERT_EQ(extra, sorted);
}

TEST(sort_tx_extra, switch_order)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230};
  const uint8_t expected_arr[] = {1, 30, 208, 98, 162, 133, 64, 85, 83, 112, 91, 188, 89, 211, 24, 131, 39, 154, 22, 228,
    80, 63, 198, 141, 173, 111, 244, 183, 4, 149, 186, 140, 230,
    2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  std::vector<uint8_t> expected(&expected_arr[0], &expected_arr[0] + sizeof(expected_arr));
  ASSERT_EQ(expected, sorted);
}

TEST(gateway_transactions, accepts_gateway_inputs_and_outputs)
{
  cryptonote::transaction tx{};
  tx.version = cryptonote::txversion::v2_ringct;
  tx.type = cryptonote::txtype::standard;

  tx.vin.emplace_back(cryptonote::txin_gateway{});
  tx.vout.emplace_back(cryptonote::tx_out{1, cryptonote::txout_gateway{}});

  ASSERT_TRUE(cryptonote::check_inputs_types_supported(tx));
  ASSERT_TRUE(cryptonote::check_outs_valid(tx));
}

TEST(sort_tx_extra, invalid)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {1};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_FALSE(cryptonote::sort_tx_extra(extra, sorted));
}

TEST(sort_tx_extra, invalid_suffix)
{
  std::vector<uint8_t> sorted;
  const uint8_t extra_arr[] = {2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  std::vector<uint8_t> extra(&extra_arr[0], &extra_arr[0] + sizeof(extra_arr));
  ASSERT_FALSE(cryptonote::sort_tx_extra(extra, sorted));
}
