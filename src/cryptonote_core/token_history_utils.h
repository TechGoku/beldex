// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#pragma once

#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"

namespace cryptonote
{

using token_history_t = std::vector<tx_extra_token_descriptor_operation>;
struct token_consensus_state
{
  bool exists = false;
  token_descriptor_base descriptor{};
  uint64_t current_supply = 0;
  uint64_t total_max_supply = 0;
};

bool load_token_history(BlockchainDB& db, const crypto::token_id& token_id, token_history_t& history);
void store_token_history(BlockchainDB& db, const crypto::token_id& token_id, const token_history_t& history);

bool append_tokens_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool rewind_tokens_from_transactions(BlockchainDB& db, const std::vector<transaction>& txs, std::string* reason = nullptr);
bool validate_token_descriptor_operation(const tx_extra_token_descriptor_operation& op, std::string& reason);
bool apply_token_operation_to_state(const crypto::token_id& token_id, const tx_extra_token_descriptor_operation& op, token_consensus_state& state, std::string& reason);
bool load_token_state_from_history(BlockchainDB& db, const crypto::token_id& token_id, token_consensus_state& state, std::string& reason);
// hf_version gates the HF21 fan-out rule (deploy/mint must produce
// >= MIN_TOKEN_MINT_OUTPUTS tx_out_zarcanum outputs).
bool validate_tx_token_operations_against_db(BlockchainDB& db, const transaction& tx,
                                              std::string& reason, hf hf_version = hf::none);

} // namespace cryptonote
