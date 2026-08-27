#pragma once

#include <type_traits>

#include "crypto/crypto.h"   // monero/src
#include "ringct/rctTypes.h" // monero/src
#include "wire/traits.h"

namespace wire
{
  template<>
  struct is_blob<crypto::ec_scalar>
    : std::true_type
  {};

  template<>
  struct is_blob<crypto::hash>
    : std::true_type
  {};

  template<>
  struct is_blob<crypto::key_derivation>
    : std::true_type
  {};

  template<>
  struct is_blob<crypto::key_image>
    : std::true_type
  {};

  template<>
  struct is_blob<crypto::public_key>
    : std::true_type
  {};

  template<>
  struct is_blob<crypto::signature>
    : std::true_type
  {};

  // HF22 privacy tokens: tx_out_zarcanum carries a blinded token id, which is
  // an ec_point like every other key above and is read the same way.
  template<>
  struct is_blob<crypto::token_id>
    : std::true_type
  {};

  template<>
  struct is_blob<rct::key>
    : std::true_type
  {};
}