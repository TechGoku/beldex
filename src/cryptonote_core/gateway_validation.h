// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"

namespace cryptonote {

// Validates a gateway registration/owner-change operation against the current registry
// state in `db`: signature correctness (see cryptonote_format_utils.h's
// hash_gateway_operation/check_gateway_ownership_proof for what's actually signed) and
// registry consistency (no double-registration, owner-change only by the current owner
// of an address that exists). Returns true if `op` would be accepted, in which case
// `fail_reason` is left untouched; otherwise returns false and sets `fail_reason` to a
// human-readable explanation suitable for a MERROR_VER/tvc.m_verbose_error message.
//
// This is deliberately independent of Blockchain/hardfork state: the caller
// (Blockchain::check_tx_inputs) is responsible for the hf22_gateway_addresses gate --
// this function only checks whether `op` is internally valid and consistent with `db`,
// which is exactly the part that's practical to unit test without a fully constructed,
// signed ring-signature transaction.
bool validate_gateway_operation(const BlockchainDB& db, const tx_extra_gateway_operation& op, std::string& fail_reason);

} // namespace cryptonote
