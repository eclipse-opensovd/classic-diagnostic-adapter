/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package webserver.token

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.server.plugins.BadRequestException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.time.Instant
import java.util.Date
import kotlin.time.Duration.Companion.hours

private const val ISSUER = "OpenSOVD::CDA::JwtAuthServerMock"

// this key pair should be persisted to allow restarts of the sim, without recreating the key
private val keyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()

val publicKey: RSAPublicKey =
    KeyFactory
        .getInstance(
            "RSA",
        ).generatePublic(X509EncodedKeySpec(keyPair.public.encoded, keyPair.public.algorithm)) as RSAPublicKey
private val privateKey =
    KeyFactory
        .getInstance(
            "RSA",
        ).generatePrivate(PKCS8EncodedKeySpec(keyPair.private.encoded, keyPair.private.algorithm)) as RSAPrivateKey
private var rsaAlgorithm = Algorithm.RSA256(publicKey, privateKey)

private val TokenValidity = 1.hours

private fun issuedAt() = Date(Instant.now(Clock.systemUTC()).toEpochMilli())

data class ClientCredentialsTokenRequest(
    val clientId: String,
    val clientSecret: String,
    val scopes: List<String>,
)

fun generateClientCredentialsResponse(tokenRequest: ClientCredentialsTokenRequest): TokenResponse {
    if (tokenRequest.clientId.isBlank() || tokenRequest.clientSecret.isBlank()) {
        throw BadRequestException("No clientId/secret")
    }

    val scopes = tokenRequest.scopes

    val validity = System.currentTimeMillis() + TokenValidity.inWholeMilliseconds
    val expiration = Date(validity)
    val token =
        JWT
            .create()
            .withKeyId("-")
            .withIssuedAt(issuedAt())
            .withSubject(tokenRequest.clientId)
            .withClaim("azp", tokenRequest.clientId)
            .withIssuer(ISSUER)
            .withExpiresAt(expiration)
            .withClaim("iatms", issuedAt().time)
            .withClaim("scopes", scopes)

    val signedToken = token.sign(rsaAlgorithm)
    return TokenResponse(
        accessToken = signedToken,
        idToken = signedToken,
        expiresIn = TokenValidity.inWholeSeconds,
        refreshToken = null,
    )
}

@Serializable
data class TokenResponse(
    @SerialName("access_token")
    var accessToken: String? = null,
    @SerialName("id_token")
    var idToken: String? = null,
    @SerialName("expires_in")
    var expiresIn: Long? = null,
    @SerialName("refresh_token")
    var refreshToken: String? = null,
    @SerialName("token_type")
    var tokenType: String? = "bearer",
)
