// Test that gateway entries added via DB on block add are rolled back on pop
#include <gtest/gtest.h>
#include "common/fs.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_storage.h"
#include "serialization/binary_utils.h"

using namespace cryptonote;

static transaction make_gateway_tx(const gateway_address_id_type &gw_addr, const crypto::public_key &asset_id, uint64_t amount)
{
  transaction tx{};
  tx.version = txversion::v1;
  tx.vin.clear();
  tx.vout.clear();

  txout_gateway gw;
  gw.version = 0;
  gw.gateway_addr = gw_addr;
  gw.asset_id = asset_id;
  gw.amount = amount;
  gw.payment_id = 0;

  tx_out out{};
  out.amount = amount;
  out.target = gw;
  tx.vout.push_back(out);

  return tx;
}

// A bare transaction (no real inputs/outputs) carrying only a gateway operation in
// tx_extra, added directly via the DB (bypassing consensus, same as make_gateway_tx
// above) -- this exercises BlockchainDB::add_transaction/remove_transaction's
// registration/owner-change handling.
static transaction make_gateway_op_tx(const tx_extra_gateway_operation& op)
{
  transaction tx{};
  tx.version = txversion::v1;
  tx.vin.clear();
  tx.vout.clear();
  add_gateway_operation_to_tx_extra(tx.extra, op);
  return tx;
}

static void add_block_with_tx(BlockchainLMDB& db, const transaction& tx)
{
  crypto::hash tx_hash = get_transaction_hash(tx);

  block bl{};
  bl.miner_tx = transaction();
  bl.tx_hashes.clear();
  bl.tx_hashes.push_back(tx_hash);

  cryptonote::blobdata block_blob = cryptonote::block_to_blob(bl);

  std::vector<std::pair<transaction, blobdata>> txs;
  txs.emplace_back(std::make_pair(tx, tx_to_blob(tx)));

  db_wtxn_guard guard(&db);
  uint64_t prev_height = db.add_block(std::make_pair(bl, block_blob), /*block_weight*/0, /*long_term*/0, /*cumulative_difficulty*/0, /*coins_generated*/0, txs);
  (void)prev_height;
}

TEST(gateway_db, block_add_pop_rolls_back_gateway_state)
{
  fs::path dirPath = fs::temp_directory_path() / ("beldex_gateway_reorg_test_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  ASSERT_NO_THROW(fs::create_directories(dirPath));

  BlockchainLMDB db;
  ASSERT_NO_THROW(db.open(dirPath, cryptonote::FAKECHAIN));

  // prepare a gateway address and asset
  gateway_address_id_type gw_addr = crypto::null_pkey;
  crypto::public_key asset_id = crypto::null_pkey;
  uint64_t amount = 12345;

  // construct a tx and block
  transaction tx = make_gateway_tx(gw_addr, asset_id, amount);
  crypto::hash tx_hash = get_transaction_hash(tx);

  block bl{};
  bl.miner_tx = transaction();
  bl.tx_hashes.clear();
  bl.tx_hashes.push_back(tx_hash);

  cryptonote::blobdata block_blob = cryptonote::block_to_blob(bl);

  std::vector<std::pair<transaction, blobdata>> txs;
  txs.emplace_back(std::make_pair(tx, tx_to_blob(tx)));

  // add block via DB (bypasses consensus validators)
  ASSERT_NO_THROW({
    db_wtxn_guard guard(&db);
    uint64_t prev_height = db.add_block(std::make_pair(bl, block_blob), /*block_weight*/0, /*long_term*/0, /*cumulative_difficulty*/0, /*coins_generated*/0, txs);
    (void)prev_height;
  });

  // verify gateway history and balance present
  gateway_tx_entry loaded_entry;
  ASSERT_TRUE(db.get_gateway_tx_history(tx_hash, loaded_entry));
  ASSERT_EQ(loaded_entry.amount, amount);
  ASSERT_EQ(loaded_entry.gateway_addr, gw_addr);

  ASSERT_EQ(amount, db.get_gateway_balance(gw_addr, asset_id));

  // pop the block. BlockchainLMDB::pop_block manages its own write txn
  // internally, so it must not be wrapped in a db_wtxn_guard here.
  ASSERT_NO_THROW({
    block popped;
    std::vector<transaction> popped_txs;
    db.pop_block(popped, popped_txs);
  });

  // after pop, history should be removed and balance rolled back
  gateway_tx_entry after_entry;
  ASSERT_FALSE(db.get_gateway_tx_history(tx_hash, after_entry));
  ASSERT_EQ(0ull, db.get_gateway_balance(gw_addr, asset_id));

  ASSERT_NO_THROW(db.close());
  ASSERT_NO_THROW(fs::remove_all(dirPath));
}

TEST(gateway_db, block_add_pop_rolls_back_registration)
{
  fs::path dirPath = fs::temp_directory_path() / ("beldex_gateway_reorg_reg_test_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  ASSERT_NO_THROW(fs::create_directories(dirPath));

  BlockchainLMDB db;
  ASSERT_NO_THROW(db.open(dirPath, cryptonote::FAKECHAIN));

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  tx_extra_gateway_operation reg_op = make_gateway_registration(owner_sec, "reorg test gateway");
  transaction reg_tx = make_gateway_op_tx(reg_op);
  crypto::hash reg_tx_hash = get_transaction_hash(reg_tx);

  ASSERT_NO_THROW(add_block_with_tx(db, reg_tx));

  gateway_record record;
  ASSERT_TRUE(db.get_gateway_record(owner_pub, record));
  ASSERT_EQ(record.owner_key, owner_pub);
  ASSERT_EQ(record.meta_info, "reorg test gateway");

  gateway_tx_entry reg_entry;
  ASSERT_TRUE(db.get_gateway_tx_history(reg_tx_hash, reg_entry));
  ASSERT_EQ(reg_entry.type, 0);
  ASSERT_EQ(reg_entry.gateway_addr, owner_pub);

  ASSERT_NO_THROW({
    block popped;
    std::vector<transaction> popped_txs;
    db.pop_block(popped, popped_txs);
  });

  gateway_record after_record;
  ASSERT_FALSE(db.get_gateway_record(owner_pub, after_record));
  gateway_tx_entry after_entry;
  ASSERT_FALSE(db.get_gateway_tx_history(reg_tx_hash, after_entry));

  ASSERT_NO_THROW(db.close());
  ASSERT_NO_THROW(fs::remove_all(dirPath));
}

TEST(gateway_db, block_add_pop_rolls_back_owner_change)
{
  fs::path dirPath = fs::temp_directory_path() / ("beldex_gateway_reorg_chg_test_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  ASSERT_NO_THROW(fs::create_directories(dirPath));

  BlockchainLMDB db;
  ASSERT_NO_THROW(db.open(dirPath, cryptonote::FAKECHAIN));

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  // Register directly via DB (not through a block) so the registration itself isn't
  // part of what we're popping in this test.
  gateway_record record{};
  record.gateway_addr = owner_pub;
  record.owner_key = owner_pub;
  record.meta_info = "pre-existing";
  record.creation_height = 0;
  {
    db_wtxn_guard guard(&db);
    db.add_gateway_record(record);
  }

  crypto::secret_key new_owner_sec;
  crypto::public_key new_owner_pub;
  crypto::generate_keys(new_owner_pub, new_owner_sec);

  tx_extra_gateway_operation chg_op = make_gateway_owner_change(owner_pub, owner_sec, new_owner_pub);
  transaction chg_tx = make_gateway_op_tx(chg_op);
  crypto::hash chg_tx_hash = get_transaction_hash(chg_tx);

  ASSERT_NO_THROW(add_block_with_tx(db, chg_tx));

  gateway_record changed;
  ASSERT_TRUE(db.get_gateway_record(owner_pub, changed));
  ASSERT_EQ(changed.owner_key, new_owner_pub);

  gateway_tx_entry chg_entry;
  ASSERT_TRUE(db.get_gateway_tx_history(chg_tx_hash, chg_entry));
  ASSERT_EQ(chg_entry.type, 3);
  ASSERT_EQ(chg_entry.prev_owner_key, owner_pub);

  ASSERT_NO_THROW({
    block popped;
    std::vector<transaction> popped_txs;
    db.pop_block(popped, popped_txs);
  });

  gateway_record reverted;
  ASSERT_TRUE(db.get_gateway_record(owner_pub, reverted));
  ASSERT_EQ(reverted.owner_key, owner_pub) << "owner should be restored to the pre-change key after pop";

  ASSERT_NO_THROW(db.close());
  ASSERT_NO_THROW(fs::remove_all(dirPath));
}
