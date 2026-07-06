// Simple unit test to validate gateway_storage types and serialization
#include <gtest/gtest.h>
#include "common/fs.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/gateway_storage.h"
#include "serialization/binary_utils.h"

using namespace cryptonote;

TEST(gateway_db, serialize_gateway_record)
{
  gateway_record r;
  // set fields
  r.gateway_addr = crypto::null_pkey; // default
  r.owner_key = crypto::null_pkey;
  r.meta_info = "test-gateway";
  r.creation_height = 42;

  std::string blob = serialization::dump_binary(r);
  gateway_record r2;
  ASSERT_NO_THROW(serialization::parse_binary(blob, r2));
  ASSERT_EQ(r2.owner_key, r.owner_key);
  ASSERT_EQ(r2.meta_info, r.meta_info);
  ASSERT_EQ(r2.creation_height, r.creation_height);
}

TEST(gateway_db, serialize_gateway_tx_entry)
{
  gateway_tx_entry e;
  e.type = 1;
  e.amount = 1000;
  e.height = 100;

  std::string blob = serialization::dump_binary(e);
  gateway_tx_entry e2;
  ASSERT_NO_THROW(serialization::parse_binary(blob, e2));
  ASSERT_EQ(e2.type, e.type);
  ASSERT_EQ(e2.amount, e.amount);
  ASSERT_EQ(e2.height, e.height);
  ASSERT_EQ(e2.version, 0); // only kind that exists today -- see gateway_storage.h
  ASSERT_TRUE(e2.amount_commitment.empty()); // reserved for a future confidential asset entry
}

// gateway_balance_value is the on-disk value type for the gateway_balances table
// (db_lmdb.cpp), deliberately versioned so a future confidential-asset balance can
// share this table without a schema migration -- see gateway_storage.h. Only version 0
// (transparent) is ever produced today; this just proves the type round-trips.
TEST(gateway_db, serialize_gateway_balance_value)
{
  gateway_balance_value v;
  v.balance = 123456789;

  std::string blob = serialization::dump_binary(v);
  gateway_balance_value v2;
  ASSERT_NO_THROW(serialization::parse_binary(blob, v2));
  ASSERT_EQ(v2.version, 0);
  ASSERT_EQ(v2.balance, v.balance);
  ASSERT_TRUE(v2.confidential_commitment.empty());
}

TEST(gateway_db, lmdb_gateway_storage)
{
  using namespace cryptonote;

  fs::path dirPath = fs::temp_directory_path() / ("beldex_gateway_test_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  ASSERT_NO_THROW(fs::create_directories(dirPath));

  BlockchainLMDB db;
  ASSERT_NO_THROW(db.open(dirPath, cryptonote::FAKECHAIN));

  gateway_record record;
  record.gateway_addr = crypto::null_pkey;
  record.owner_key = crypto::null_pkey;
  record.meta_info = "test-gateway";
  record.creation_height = 42;

  gateway_tx_entry entry;
  entry.tx_hash = crypto::null_hash;
  entry.type = 1;
  entry.gateway_addr = record.gateway_addr;
  entry.asset_id = crypto::null_pkey;
  entry.amount = 1000;
  entry.height = 100;

  // Scope the write txn guard so it commits before db.close() runs below --
  // BlockchainLMDB::close() tears down the LMDB environment without checking
  // for an active write txn, so committing after close() would use-after-free.
  {
    db_wtxn_guard guard(&db);

    ASSERT_NO_THROW(db.add_gateway_record(record));

    gateway_record loaded_record;
    ASSERT_TRUE(db.get_gateway_record(record.gateway_addr, loaded_record));
    ASSERT_EQ(record.meta_info, loaded_record.meta_info);
    ASSERT_EQ(record.creation_height, loaded_record.creation_height);

    ASSERT_NO_THROW(db.add_gateway_tx_history(entry.tx_hash, entry));

    gateway_tx_entry loaded_entry;
    ASSERT_TRUE(db.get_gateway_tx_history(entry.tx_hash, loaded_entry));
    ASSERT_EQ(entry.amount, loaded_entry.amount);
    ASSERT_EQ(entry.height, loaded_entry.height);
    ASSERT_EQ(entry.gateway_addr, loaded_entry.gateway_addr);

    ASSERT_EQ(0ull, db.get_gateway_balance(record.gateway_addr, entry.asset_id));
    ASSERT_NO_THROW(db.update_gateway_balance(record.gateway_addr, entry.asset_id, 500));
    ASSERT_EQ(500ull, db.get_gateway_balance(record.gateway_addr, entry.asset_id));

    ASSERT_NO_THROW(db.remove_gateway_record(record.gateway_addr));
    gateway_record deleted_record;
    ASSERT_FALSE(db.get_gateway_record(record.gateway_addr, deleted_record));
  }

  ASSERT_NO_THROW(db.close());
  ASSERT_NO_THROW(fs::remove_all(dirPath));
}
