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

//! Ed25519 (`PureEdDSA`) signature verification via `ed25519-dalek`.
//!
//! This module provides the `#[no_mangle] extern "C"` function that the
//! C PSA accelerator driver (`csrc/ed25519_psa_driver.c`) calls to perform
//! the actual Ed25519 cryptographic verification.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const ED25519_PUB_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

const VERIFY_FAIL: i32 = -1;
const VERIFY_SUCCESS: i32 = 0;

/// Verify an Ed25519 signature.
///
/// # Safety
///
/// All pointer+length pairs must reference valid, readable memory.
///
/// # Returns
///
/// * `0` - signature is valid
/// * `-1` - verification failed or invalid input
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_ed25519_verify(
    pub_key: *const u8,
    pub_key_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pub_key.is_null() || sig.is_null() {
        return VERIFY_FAIL;
    }
    if pub_key_len != ED25519_PUB_KEY_LEN || sig_len != ED25519_SIG_LEN || msg.is_null() {
        return VERIFY_FAIL;
    }

    // SAFETY: caller guarantees valid pointers and lengths.
    let pub_key_bytes: &[u8; 32] =
        if let Ok(b) = unsafe { core::slice::from_raw_parts(pub_key, 32) }.try_into() {
            b
        } else {
            tracing::error!("ed25519 verify failed: unable to read public key");
            return VERIFY_FAIL;
        };

    let sig_bytes: &[u8; 64] =
        if let Ok(b) = unsafe { core::slice::from_raw_parts(sig, 64) }.try_into() {
            b
        } else {
            tracing::error!("ed25519 verify failed: unable to read signature");
            return VERIFY_FAIL;
        };

    let message = unsafe { core::slice::from_raw_parts(msg, msg_len) };
    let Ok(verifying_key) = VerifyingKey::from_bytes(pub_key_bytes) else {
        return VERIFY_FAIL;
    };

    let signature = Signature::from_bytes(sig_bytes);

    match verifying_key.verify(message, &signature) {
        Ok(()) => VERIFY_SUCCESS,
        Err(e) => {
            tracing::error!("ed25519 verify failed: {e}");
            VERIFY_FAIL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_verify_rfc8032_vector() {
        // RFC 8032 §7.1 TEST 1
        let pub_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let msg: &[u8] = b""; // empty message
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a\
            33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let pub_key = hex::decode(pub_key_hex).unwrap();
        let sig = hex::decode(sig_hex).unwrap();

        // First test: dalek directly
        let vk = VerifyingKey::from_bytes(pub_key.as_slice().try_into().unwrap()).unwrap();
        let signature = Signature::from_bytes(sig.as_slice().try_into().unwrap());
        assert!(
            vk.verify(msg, &signature).is_ok(),
            "dalek direct verify should pass"
        );

        // Second test: via FFI function
        let result = unsafe {
            rust_ed25519_verify(
                pub_key.as_ptr(),
                pub_key.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(result, 0, "RFC 8032 test vector 1 should verify");
    }

    #[test]
    fn test_ed25519_verify_bad_sig() {
        let pub_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pub_key = hex::decode(pub_key_hex).unwrap();
        let msg = b"hello";
        let bad_sig = [0u8; 64];

        let result = unsafe {
            rust_ed25519_verify(
                pub_key.as_ptr(),
                pub_key.len(),
                msg.as_ptr(),
                msg.len(),
                bad_sig.as_ptr(),
                bad_sig.len(),
            )
        };
        assert_ne!(result, 0, "bad signature should fail");
    }
}
