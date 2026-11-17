// Copyright (c) 2026, The Beldex Project
//
// A v3+ transaction must carry one unlock time per output. The coinbase is
// only checked by the deserializer (and prevalidate_miner_transaction), and
// storing a block indexes output_unlock_times by output, so a coinbase with
// too few would read past the end of the vector.
#include "gtest/gtest.h"

#include <stdexcept>
#include <string>

#include "cryptonote_basic/cryptonote_basic.h"
#include "serialization/binary_utils.h"

namespace
{
  cryptonote::transaction_prefix one_output_tx()
  {
    cryptonote::transaction_prefix tx;
    tx.version = cryptonote::txversion::v4_tx_types;
    tx.type = cryptonote::txtype::standard;
    tx.unlock_time = 0;
    tx.vin.push_back(cryptonote::txin_gen{7});
    cryptonote::tx_out out{};
    out.amount = 1;
    out.target = cryptonote::txout_to_key{};
    tx.vout.push_back(out);
    tx.output_unlock_times = {5};
    return tx;
  }
}

TEST(output_unlock_times, matching_count_round_trips)
{
  cryptonote::transaction_prefix tx = one_output_tx();
  const std::string blob = serialization::dump_binary(tx);
  cryptonote::transaction_prefix parsed;
  ASSERT_NO_THROW(serialization::parse_binary(blob, parsed));
  EXPECT_EQ(parsed.output_unlock_times, tx.output_unlock_times);
  EXPECT_EQ(parsed.vout.size(), 1u);
}

TEST(output_unlock_times, too_few_is_rejected_when_read)
{
  cryptonote::transaction_prefix tx = one_output_tx();
  const std::string blob = serialization::dump_binary(tx);

  // The blob starts: version (1 byte), unlock-time count, the unlock time.
  // Drop the one unlock time and keep the output: 1 output, 0 unlock times.
  ASSERT_GE(blob.size(), 3u);
  ASSERT_EQ(blob[1], '\x01');
  ASSERT_EQ(blob[2], '\x05');
  const std::string short_blob = blob.substr(0, 1) + '\x00' + blob.substr(3);

  cryptonote::transaction_prefix parsed;
  EXPECT_THROW(serialization::parse_binary(short_blob, parsed), std::invalid_argument);
}

TEST(output_unlock_times, too_many_is_rejected_when_read)
{
  cryptonote::transaction_prefix tx = one_output_tx();
  const std::string blob = serialization::dump_binary(tx);
  ASSERT_GE(blob.size(), 3u);
  ASSERT_EQ(blob[1], '\x01');
  // Two unlock times for the one output.
  const std::string long_blob = blob.substr(0, 1) + "\x02\x05\x05" + blob.substr(3);

  cryptonote::transaction_prefix parsed;
  EXPECT_THROW(serialization::parse_binary(long_blob, parsed), std::invalid_argument);
}

TEST(output_unlock_times, mismatch_is_refused_when_written)
{
  cryptonote::transaction_prefix tx = one_output_tx();
  tx.output_unlock_times.clear();
  EXPECT_THROW(serialization::dump_binary(tx), std::invalid_argument);
}
