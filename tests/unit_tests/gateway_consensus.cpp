// Basic consensus-level checks for gateway inputs/outputs
#define IN_UNIT_TESTS

#include "gtest/gtest.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/uptime_proof.h"
#include "blockchain_utilities/blockchain_objects.h"
#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"

using namespace cryptonote;

// Small helper macro to initialize a Blockchain instance for testing

TEST(gateway_consensus, blockchain_rejects_gateway_inputs)
{
  blockchain_objects_t bc_objects;
  const std::vector<cryptonote::hard_fork> hard_forks{ {cryptonote::hf::hf7,0,0,0}, {cryptonote::hf::hf9_master_nodes,0,1,0} };
  const cryptonote::test_options test_options{ hard_forks, 1000 };
  cryptonote::Blockchain *bc = &bc_objects.m_blockchain;
  struct LocalTestDB: public BaseTestDB { LocalTestDB() { m_open = true; } };
  ASSERT_TRUE(bc->init(new LocalTestDB(), nullptr, cryptonote::FAKECHAIN, true, &test_options, 0));

  transaction tx{};
  tx.version = txversion::v2_ringct;
  tx.type = txtype::standard;

  cryptonote::keypair gw{};
  crypto::generate_keys(gw.pub, gw.sec, gw.sec, true);

  txin_gateway in{};
  in.amount = 1; // non-zero but blockchain path currently rejects gateway usage
  in.gateway_addr = gw.pub;
  in.asset_id = gw.pub;
  tx.vin.emplace_back(in);

  tx_verification_context tvc{};
  uint64_t max_h = 0;
  crypto::hash max_id = crypto::null_hash;

  bool ok = bc->check_tx_inputs(tx, max_h, max_id, tvc, false);
  ASSERT_FALSE(ok);
  ASSERT_TRUE(tvc.m_invalid_input || tvc.m_verifivation_failed);
}

TEST(gateway_consensus, blockchain_rejects_gateway_outputs)
{
  blockchain_objects_t bc_objects;
  const std::vector<cryptonote::hard_fork> hard_forks{ {cryptonote::hf::hf7,0,0,0}, {cryptonote::hf::hf9_master_nodes,0,1,0} };
  const cryptonote::test_options test_options{ hard_forks, 1000 };
  cryptonote::Blockchain *bc = &bc_objects.m_blockchain;
  struct LocalTestDB: public BaseTestDB { LocalTestDB() { m_open = true; } };
  ASSERT_TRUE(bc->init(new LocalTestDB(), nullptr, cryptonote::FAKECHAIN, true, &test_options, 0));

  transaction tx{};
  tx.version = txversion::v2_ringct;
  tx.type = txtype::standard;

  cryptonote::keypair gw{};
  crypto::generate_keys(gw.pub, gw.sec, gw.sec, true);

  tx_out out{};
  out.amount = 1;
  txout_gateway gwt{};
  gwt.gateway_addr = gw.pub;
  gwt.asset_id = gw.pub;
  gwt.amount = 1;
  out.target = gwt;
  tx.vout.emplace_back(out);

  tx_verification_context tvc{};
  bool ok = bc->check_tx_outputs(tx, tvc);
  ASSERT_FALSE(ok);
  ASSERT_TRUE(tvc.m_invalid_output || tvc.m_verifivation_failed);
}
