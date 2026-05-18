/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

// Ed25519 (PureEdDSA) PSA Crypto Accelerator Driver - C implementation
//
// This file bridges the PSA Crypto driver interface with the Rust
// ed25519-dalek implementation.  It is compiled by cc-rs and linked
// into the final binary alongside the mbedtls static libraries.

#include "ed25519_psa_driver.h"
#include <string.h>

/* ---------------------------------------------------------------------------
 * FFI: implemented in Rust (src/ed25519.rs)
 *
 * Returns 0 on successful verification, non-zero on failure.
 * ---------------------------------------------------------------------------
 */
extern int rust_ed25519_verify(const uint8_t *pub_key, size_t pub_key_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);

/* Ed25519 public-key size (RFC 8032) */
#define ED25519_PUB_KEY_SIZE 32
/* Ed25519 signature size (RFC 8032) */
#define ED25519_SIG_SIZE 64

/* ---------------------------------------------------------------------------
 * psa_import_key  -  transparent driver entry point
 * ---------------------------------------------------------------------------
 */
psa_status_t ed25519_psa_import_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *data, size_t data_length,
                                    uint8_t *key_buffer, size_t key_buffer_size,
                                    size_t *key_buffer_length, size_t *bits) {
  psa_key_type_t type = psa_get_key_type(attributes);

  /* Only handle Twisted-Edwards public keys. */
  if (type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  if (data_length != ED25519_PUB_KEY_SIZE) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  if (key_buffer_size < ED25519_PUB_KEY_SIZE) {
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }

  memcpy(key_buffer, data, ED25519_PUB_KEY_SIZE);
  *key_buffer_length = ED25519_PUB_KEY_SIZE;
  *bits = 255;

  return PSA_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * psa_verify_message  -  transparent driver entry point
 * ---------------------------------------------------------------------------
 */
psa_status_t ed25519_psa_verify_message(
    const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
    size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input,
    size_t input_length, const uint8_t *signature, size_t signature_length) {
  psa_key_type_t type = psa_get_key_type(attributes);

  /* Only handle PureEdDSA on Twisted-Edwards keys. */
  if (alg != PSA_ALG_PURE_EDDSA) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS) &&
      type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  if (signature_length != ED25519_SIG_SIZE) {
    return PSA_ERROR_INVALID_SIGNATURE;
  }
  if (key_buffer_size < ED25519_PUB_KEY_SIZE) {
    return PSA_ERROR_CORRUPTION_DETECTED;
  }

  int rc = rust_ed25519_verify(key_buffer, ED25519_PUB_KEY_SIZE, input,
                               input_length, signature, signature_length);

  return rc == 0 ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}
