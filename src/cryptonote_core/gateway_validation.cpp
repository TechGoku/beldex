// SPDX-License-Identifier: BSD-3-Clause
#include "gateway_validation.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/gateway_storage.h"
#include "crypto/crypto.h"

namespace cryptonote {

bool validate_gateway_operation(const BlockchainDB& db, const tx_extra_gateway_operation& op, std::string& fail_reason)
{
  const crypto::hash op_hash = hash_gateway_operation(op.operation);

  if (auto* reg = std::get_if<gateway_address_descriptor_operation_register>(&op.operation))
  {
    const crypto::public_key* owner_key = std::get_if<crypto::public_key>(&reg->descriptor.owner_key);
    if (!owner_key || !crypto::check_key(*owner_key))
    {
      fail_reason = "gateway registration has an invalid owner key";
      return false;
    }

    gateway_record existing;
    if (db.get_gateway_record(*owner_key, existing))
    {
      fail_reason = "attempts to register a gateway address that's already registered";
      return false;
    }

    if (!check_gateway_ownership_proof(op_hash, *owner_key, op.proof))
    {
      fail_reason = "gateway registration has an invalid ownership proof";
      return false;
    }

    return true;
  }

  if (auto* chg = std::get_if<gateway_address_descriptor_operation_owner_change>(&op.operation))
  {
    const crypto::public_key* new_owner_key = std::get_if<crypto::public_key>(&chg->new_owner_key);
    if (!new_owner_key || !crypto::check_key(*new_owner_key))
    {
      fail_reason = "gateway owner-change has an invalid new owner key";
      return false;
    }

    gateway_record existing;
    if (!db.get_gateway_record(chg->gateway_addr, existing))
    {
      fail_reason = "attempts to change the owner of an unregistered gateway address";
      return false;
    }

    if (!check_gateway_ownership_proof(op_hash, existing.owner_key, op.proof))
    {
      fail_reason = "gateway owner-change has an invalid ownership proof (must be signed by the current owner)";
      return false;
    }

    return true;
  }

  fail_reason = "unrecognized gateway operation variant";
  return false;
}

} // namespace cryptonote
