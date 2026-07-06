// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include "crypto/hash.h"
#include "serialization/string.h"

namespace cryptonote {

// Schema-versioning convention used throughout this file, adopted so that a future
// "confidential assets" feature (tentatively hf24, not designed or implemented yet --
// see IMPLEMENTATION_PHASES.md) can extend these on-disk shapes without another
// incompatible LMDB migration:
//
//   - Every stored struct carries its own `version` byte.
//   - `version == 0` is the only kind that exists today: a fully transparent
//     (plaintext) asset, exactly as originally implemented.
//   - `version == 1` is RESERVED for a future confidential-asset representation (a
//     Pedersen commitment to the amount, plus an ECDH-encrypted amount the owner can
//     decrypt -- the same shape RingCT already uses for normal output amounts). No
//     code writes or interprets version 1 today; reader code that only understands
//     transparent assets must reject anything other than version 0 explicitly rather
//     than silently misinterpreting it (see db_lmdb.cpp's gateway balance accessors).
//   - Because nothing has shipped on any real network yet (hf22_gateway_addresses is
//     deliberately unscheduled -- see cryptonote_config.h), this versioning costs
//     nothing today and removes the need for an LMDB key-schema migration later: hf24
//     work only needs to start writing version 1 values into the *same* tables.

struct gateway_record
{
  uint8_t version = 0; // see the file-level comment above; 0 = only kind that exists today
  gateway_address_id_type gateway_addr = crypto::null_pkey;
  crypto::public_key owner_key = crypto::null_pkey;
  std::string meta_info;
  uint64_t creation_height = 0;

  BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(version)
    FIELD(gateway_addr)
    FIELD(owner_key)
    FIELD(meta_info)
    VARINT_FIELD(creation_height)
  END_SERIALIZE()
};

struct gateway_tx_entry
{
  uint8_t version = 0; // see the file-level comment above; 0 = only kind that exists today
  crypto::hash tx_hash{};
  uint8_t type = 0; // 0 = register, 1 = transfer/credit, 2 = withdraw/debit, 3 = owner_change
  gateway_address_id_type gateway_addr = crypto::null_pkey;
  crypto::public_key asset_id = crypto::null_pkey; // meaningful for type 1/2 only
  uint64_t amount = 0; // meaningful for type 1/2 only, when version == 0 (transparent)
  uint64_t height = 0;
  // For type == 3 (owner_change) only: the owner_key that was on file *before* this
  // change, so a reorg can restore it. Unused (null) for every other type.
  crypto::public_key prev_owner_key = crypto::null_pkey;
  // Reserved for a future confidential-asset history entry (version == 1): would hold
  // a serialized Pedersen commitment to `amount` (plus enough to let the owner recover
  // the plaintext amount, e.g. an ECDH-encrypted value). Always empty at version 0;
  // not read or written by any code today.
  std::string amount_commitment;

  BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(version)
    FIELD(tx_hash)
    VARINT_FIELD(type)
    FIELD(gateway_addr)
    FIELD(asset_id)
    VARINT_FIELD(amount)
    VARINT_FIELD(height)
    FIELD(prev_owner_key)
    FIELD(amount_commitment)
  END_SERIALIZE()
};

// On-disk value type for the `gateway_balances` table (see db_lmdb.cpp). Split out from
// a bare uint64_t (what this table originally stored) specifically so a future
// confidential balance can share this exact table instead of needing a new one --
// only this struct's `version` and contents change, the LMDB key layout
// (gateway_addr, asset_id) does not.
struct gateway_balance_value
{
  uint8_t version = 0; // see the file-level comment above; 0 = only kind that exists today
  uint64_t balance = 0; // meaningful when version == 0 (transparent)
  // Reserved for a future confidential balance (version == 1): a Pedersen commitment to
  // the running balance, plus whatever the owner needs to decrypt/recompute it. Always
  // empty at version 0; not read or written by any code today.
  std::string confidential_commitment;

  BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(version)
    VARINT_FIELD(balance)
    FIELD(confidential_commitment)
  END_SERIALIZE()
};

} // namespace cryptonote
