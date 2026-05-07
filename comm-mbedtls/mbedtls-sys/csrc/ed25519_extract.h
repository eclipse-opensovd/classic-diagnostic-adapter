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

/*
 * Helper to extract a raw 32-byte Ed25519 public key from either a bare key
 * or a DER-encoded SubjectPublicKeyInfo (RFC 8410).
 */

#ifndef ED25519_EXTRACT_H
#define ED25519_EXTRACT_H

#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include <string.h>

/* Raw Ed25519 public-key length (RFC 8032). */
#define ED25519_RAW_PUBKEY_LEN 32

/**
 * \brief  Extract a raw 32-byte Ed25519 public key.
 *
 * If \p pub_raw_len is 32 the input is taken as-is.  Otherwise it is
 * parsed as a DER-encoded SubjectPublicKeyInfo (RFC 8410 §4):
 *
 *   SEQUENCE {                           - SubjectPublicKeyInfo
 *     SEQUENCE {                         - AlgorithmIdentifier
 *       OID 1.3.101.112                  -   id-Ed25519
 *       -- parameters MUST be absent (RFC 8410 §3)
 *     }
 *     BIT STRING (0 unused bits)         - 32-byte raw public key
 *   }
 *
 * \param[in]  pub_raw      Raw key or DER-encoded SubjectPublicKeyInfo.
 *                          Passed as non-const as the mbedtls ASN.1
 *                          helpers advance a read cursor through the buffer.
 *                          The underlying data is never modified.
 * \param[in]  pub_raw_len  Length of \p pub_raw in bytes.
 * \param[out] out          Buffer receiving the 32-byte raw public key.
 *
 * \return  0 on success.
 * \return  #MBEDTLS_ERR_PK_INVALID_PUBKEY if the input cannot be parsed
 *          or does not contain a valid Ed25519 public key.
 */
static inline int ed25519_extract_raw_pubkey(
    unsigned char *pub_raw, const size_t pub_raw_len,
    unsigned char out[ED25519_RAW_PUBKEY_LEN])
{
    /* ---- input is already a bare 32-byte key. ---- */
    if (pub_raw_len == ED25519_RAW_PUBKEY_LEN) {
        memcpy(out, pub_raw, ED25519_RAW_PUBKEY_LEN);
        return 0;
    }

    /* ---- parse SubjectPublicKeyInfo from DER. ----
     *
     * Cast away const: the mbedtls ASN.1 helpers advance the read pointer
     * through the buffer but never modify the underlying data.
     */
    unsigned char *p   = pub_raw;
    unsigned char *end = p + pub_raw_len;
    size_t len;
    int ret;

    /*
     * Step 1 - Outer SEQUENCE (SubjectPublicKeyInfo).
     * It must span exactly the entire input; trailing data is rejected.
     */
    ret = mbedtls_asn1_get_tag(&p, end, &len,
              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0 || p + len != end) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }

    /*
     * Step 2 - Inner SEQUENCE (AlgorithmIdentifier).
     * Record where the AlgorithmIdentifier content ends so we can
     * verify that no unexpected trailing data (e.g. parameters) follows.
     */
    ret = mbedtls_asn1_get_tag(&p, end, &len,
              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }
    unsigned char *alg_end = p + len;

    /*
     * Step 3 - OID inside AlgorithmIdentifier.
     * After mbedtls_asn1_get_tag() succeeds, `p` points to the first
     * byte of the OID value and `oid_len` holds its length.
     * Verify it matches id-Ed25519 (1.3.101.112 --> 0x2B 0x65 0x70).
     */
    size_t oid_len;
    ret = mbedtls_asn1_get_tag(&p, alg_end, &oid_len, MBEDTLS_ASN1_OID);
    if (ret != 0) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }
    if (oid_len != MBEDTLS_OID_SIZE(MBEDTLS_OID_ED25519) ||
        memcmp(p, MBEDTLS_OID_ED25519, oid_len) != 0) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }
    p += oid_len;

    /*
     * Step 4 - RFC 8410 §3: "For all of the OIDs, the parameters
     * MUST be absent."  Reject if anything follows the OID inside
     * the AlgorithmIdentifier SEQUENCE.
     */
    if (p != alg_end) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }

    /*
     * Step 5 - BIT STRING containing the raw public key.
     * mbedtls_asn1_get_bitstring_null() parses the tag and length,
     * and verifies the "unused bits" octet is 0x00 (required for
     * Ed25519 since the key is an integral number of bytes).
     * After the call, `p` points to the first key byte.
     */
    ret = mbedtls_asn1_get_bitstring_null(&p, end, &len);
    if (ret != 0 || len != ED25519_RAW_PUBKEY_LEN) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }

    /*
     * Step 6 - Verify there is no trailing data after the BIT STRING
     * content.  (The outer SEQUENCE check in step 1 already bounds the
     * total size, but being explicit here catches internal parse bugs.)
     */
    if (p + len != end) {
        return MBEDTLS_ERR_PK_INVALID_PUBKEY;
    }

    memcpy(out, p, ED25519_RAW_PUBKEY_LEN);
    return 0;
}

#endif /* ED25519_EXTRACT_H */
