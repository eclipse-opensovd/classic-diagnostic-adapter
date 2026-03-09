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

// Ed25519 (PureEdDSA) PSA Crypto Accelerator Driver
//
// This transparent driver handles:
//   - Key import for
// PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)
//   - Signature verification via PSA_ALG_PURE_EDDSA
//
// The actual Ed25519 cryptographic operations are delegated to a Rust
// implementation (ed25519-dalek) via the rust_ed25519_verify() FFI function.

#ifndef ED25519_PSA_DRIVER_H
#define ED25519_PSA_DRIVER_H

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief  Import an Ed25519 public key into the PSA key store.
 *
 * Only handles PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS).
 * Returns PSA_ERROR_NOT_SUPPORTED for all other key types so the PSA core
 * can fall through to the built-in driver.
 */
psa_status_t ed25519_psa_import_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *data, size_t data_length,
                                    uint8_t *key_buffer, size_t key_buffer_size,
                                    size_t *key_buffer_length, size_t *bits);

/**
 * \brief  Verify a PureEdDSA (Ed25519) signature over a message.
 *
 * Only handles PSA_ALG_PURE_EDDSA on TWISTED_EDWARDS keys.
 * Returns PSA_ERROR_NOT_SUPPORTED for all other algorithms / key types.
 */
psa_status_t ed25519_psa_verify_message(
    const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
    size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input,
    size_t input_length, const uint8_t *signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_PSA_DRIVER_H */
