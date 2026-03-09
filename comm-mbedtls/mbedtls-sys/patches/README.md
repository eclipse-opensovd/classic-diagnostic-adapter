<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

## mbedtls-4 patch summary

These patches extends mbedtls 4.0.0 with two features absent from upstream:  
- **`record_size_limit` (RFC 8449) for TLS 1.2**
- **Ed25519 (PureEdDSA) support across the PSA, PK, X.509, and TLS 1.2 layers**

The patch order is `record-size-limit-tls12.patch` first and then `ed25519-psa-driver.patch`

### `record_size_limit` (RFC 8449) for TLS 1.2
RFC 8449 defines `record_size_limit` for all TLS versions including 1.2, but mbedtls 4.0.0 only implements it for TLS 1.3. The parsing/writing functions are gated behind `MBEDTLS_SSL_PROTO_TLS1_3`, making them inaccessible to TLS 1.2 code.
Changes:
- **Compilation guard** (`ssl_tls13_generic.c`): Moves `record_size_limit` functions from `MBEDTLS_SSL_PROTO_TLS1_3` to `MBEDTLS_SSL_TLS_C`, making them available to all TLS versions.
- **ClientHello** (`ssl_client.c`): Writes the `record_size_limit` extension in TLS 1.2 ClientHello, advertising `MBEDTLS_SSL_IN_CONTENT_LEN`.
- **ServerHello parsing** (`ssl_tls12_client.c`): Parses `record_size_limit` from the TLS 1.2 ServerHello. Enforces RFC 8449 section 5 mutual exclusion: aborts the handshake with `illegal_parameter` if both `record_size_limit` and `max_fragment_length` are present.

### Ed25519 / PureEdDSA (`ed25519-psa-driver.patch)
mbedtls 4.0.0 has no Ed25519 signature support in TLS 1.2 or X.509 certificate verification.
Changes:
- **PSA crypto config** (`crypto_config.h`): Enables `PSA_WANT_ECC_TWISTED_EDWARDS_255` and `PSA_WANT_ALG_PURE_EDDSA`.
- **PSA crypto core** (`psa_crypto.c`): The existing code unconditionally rejects `hash_alg==0` when signing/verifying a message. This doesn't work for PureEdDSA, which operates on the raw message directly without pre-hashing (the hashing is internal to the Ed25519 algorithm per RFC 8032). The patch narrows the rejection to only apply when the algorithm is not `PSA_ALG_PURE_EDDSA`.
- **PSA driver wrappers** (`psa_crypto_driver_wrappers.h`): Hooks an external Ed25519 PSA driver (gated on `MBEDTLS_ED25519_PSA_DRIVER`) for `verify_message` and `import_key`. This allows plugging in a platform-specific Ed25519 implementation.
- **ECP / PK layer** (`ecp.h`, `pk.h`, `pk_ecc.c`, `pk_internal.h`, `psa_crypto_ecp.c`, `psa_util.c`): Adds `MBEDTLS_ECP_DP_ED25519` group ID with bidirectional mapping to `PSA_ECC_FAMILY_TWISTED_EDWARDS`, includes Ed25519 in RFC 8410 key format handling, and sets `PSA_ALG_PURE_EDDSA` with sign/verify usage flags for Twisted Edwards keys.
- **OID tables** (`oid.c`, `x509_oid.c`): Registers the Ed25519 OID (`1.3.101.112`) and adds `MBEDTLS_PK_SIGALG_EDDSA` signature algorithm type.
- **X.509 cert verification** (`x509_crt.c`): Adds a PureEdDSA path that extracts the raw 32-byte public key (handling both raw and 44-byte DER-wrapped forms), imports it as a transient PSA key, and calls `psa_verify_message` over the raw TBS data.
- **TLS 1.2 client** (`ssl_misc.h`, `ssl_tls12_client.c`): Recognizes `MBEDTLS_TLS1_3_SIG_ED25519` (`0x0807`) as a supported TLS 1.2 signature algorithm per RFC 8422 section 5.1.3 (EdDSA bypasses the traditional hash+sig decomposition). Adds ServerKeyExchange signature verification: constructs the signed message (`client_random || server_random || params`), imports the peer's Ed25519 public key via PSA, and verifies with `psa_verify_message`.
