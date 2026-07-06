// Tests for gateway registration/owner-change validation logic
// (cryptonote_core/gateway_validation.h), which is what
// Blockchain::check_tx_inputs calls once a tx_extra_gateway_operation is found (see
// blockchain.cpp) and the hf22_gateway_addresses hardfork gate has already passed.
//
// This deliberately does not drive the check through a fully constructed, signed
// ring-signature transaction and Blockchain::check_tx_inputs end-to-end: that requires a
// real chain-generator test harness (see tests/core_tests/chaingen.h) to produce a valid
// txin_to_key/CLSAG input, which is out of scope here. Instead it tests the actual
// decision logic directly against a real BlockchainLMDB instance (the same approach
// gateway_reorg.cpp already uses to test DB-level effects without going through
// consensus), which is what determines accept/reject for a gateway operation once the
// hardfork gate is satisfied.
#include <gtest/gtest.h>
#include "common/fs.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_validation.h"

using namespace cryptonote;

namespace
{
  struct TempDB
  {
    fs::path dir;
    BlockchainLMDB db;

    TempDB()
      : dir(fs::temp_directory_path() / ("beldex_gateway_validation_test_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count())))
    {
      fs::create_directories(dir);
      db.open(dir, cryptonote::FAKECHAIN);
    }
    ~TempDB()
    {
      db.close();
      fs::remove_all(dir);
    }
  };
}

TEST(gateway_registration_validation, accepts_valid_registration)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  tx_extra_gateway_operation op = make_gateway_registration(owner_sec, "my gateway");

  std::string fail_reason;
  EXPECT_TRUE(validate_gateway_operation(t.db, op, fail_reason)) << fail_reason;
}

TEST(gateway_registration_validation, rejects_registration_with_tampered_content)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  tx_extra_gateway_operation op = make_gateway_registration(owner_sec, "my gateway");
  auto* reg = std::get_if<gateway_address_descriptor_operation_register>(&op.operation);
  ASSERT_NE(reg, nullptr);
  reg->descriptor.meta_info = "tampered"; // signature no longer matches this content

  std::string fail_reason;
  EXPECT_FALSE(validate_gateway_operation(t.db, op, fail_reason));
  EXPECT_FALSE(fail_reason.empty());
}

TEST(gateway_registration_validation, rejects_duplicate_registration)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  {
    db_wtxn_guard guard(&t.db);
    gateway_record existing{};
    existing.gateway_addr = owner_pub;
    existing.owner_key = owner_pub;
    existing.meta_info = "already here";
    existing.creation_height = 0;
    t.db.add_gateway_record(existing);
  }

  tx_extra_gateway_operation op = make_gateway_registration(owner_sec, "second attempt");

  std::string fail_reason;
  EXPECT_FALSE(validate_gateway_operation(t.db, op, fail_reason));
  EXPECT_FALSE(fail_reason.empty());
}

TEST(gateway_registration_validation, accepts_owner_change_signed_by_current_owner)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  {
    db_wtxn_guard guard(&t.db);
    gateway_record existing{};
    existing.gateway_addr = owner_pub;
    existing.owner_key = owner_pub;
    existing.meta_info = "pre-existing";
    existing.creation_height = 0;
    t.db.add_gateway_record(existing);
  }

  crypto::secret_key new_owner_sec;
  crypto::public_key new_owner_pub;
  crypto::generate_keys(new_owner_pub, new_owner_sec);

  tx_extra_gateway_operation op = make_gateway_owner_change(owner_pub, owner_sec, new_owner_pub);

  std::string fail_reason;
  EXPECT_TRUE(validate_gateway_operation(t.db, op, fail_reason)) << fail_reason;
}

TEST(gateway_registration_validation, rejects_owner_change_signed_by_non_owner)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);

  {
    db_wtxn_guard guard(&t.db);
    gateway_record existing{};
    existing.gateway_addr = owner_pub;
    existing.owner_key = owner_pub;
    existing.meta_info = "pre-existing";
    existing.creation_height = 0;
    t.db.add_gateway_record(existing);
  }

  // Signed by an unrelated key, not the registered owner.
  crypto::secret_key impostor_sec;
  crypto::public_key impostor_pub;
  crypto::generate_keys(impostor_pub, impostor_sec);

  crypto::secret_key new_owner_sec;
  crypto::public_key new_owner_pub;
  crypto::generate_keys(new_owner_pub, new_owner_sec);

  tx_extra_gateway_operation op = make_gateway_owner_change(owner_pub, impostor_sec, new_owner_pub);

  std::string fail_reason;
  EXPECT_FALSE(validate_gateway_operation(t.db, op, fail_reason));
  EXPECT_FALSE(fail_reason.empty());
}

TEST(gateway_registration_validation, rejects_owner_change_for_unregistered_address)
{
  TempDB t;

  crypto::secret_key owner_sec;
  crypto::public_key owner_pub;
  crypto::generate_keys(owner_pub, owner_sec);
  // Note: no add_gateway_record call -- this address was never registered.

  crypto::secret_key new_owner_sec;
  crypto::public_key new_owner_pub;
  crypto::generate_keys(new_owner_pub, new_owner_sec);

  tx_extra_gateway_operation op = make_gateway_owner_change(owner_pub, owner_sec, new_owner_pub);

  std::string fail_reason;
  EXPECT_FALSE(validate_gateway_operation(t.db, op, fail_reason));
  EXPECT_FALSE(fail_reason.empty());
}
