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

import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import java.util.Base64

private val log = LoggerFactory.getLogger("JwtAuthServerMock")

fun Route.addJwtAuthServerMockRoutes() {
    get("/keys") {
        MDC.clear()
        log.info("/keys called")
        val rsaPublicKey = publicKey
        val response =
            KeysResponse(
                keys =
                    listOf(
                        KeyResponse(
                            e = rsaPublicKey.publicExponent.toByteArray().encodeUrlBase64(),
                            n = rsaPublicKey.modulus.toByteArray().encodeUrlBase64(),
                            alg = "RS256",
                            kty = "RSA",
                            use = "SIG",
                            kid = "-",
                        ),
                    ),
            )
        call.respond(response)
    }

    post("/token") {
        MDC.clear()
        val params = call.receiveParameters()
        val req =
            TokenRequest(
                grantType = params["grant_type"],
                clientId = params["client_id"],
                clientSecret = params["client_secret"],
                scope = params["scope"],
            )

        log.info("/token called: $req")
        call.respond(HttpStatusCode.OK, generateTokenResponse(req))
    }
}

fun generateTokenResponse(tokenRequest: TokenRequest): TokenResponse =
    when (tokenRequest.grantType) {
        "client_credentials" ->
            generateClientCredentialsResponse(
                ClientCredentialsTokenRequest(
                    clientId = tokenRequest.clientId ?: throw BadRequestException("Requires client id"),
                    clientSecret = tokenRequest.clientSecret ?: throw BadRequestException("Requires client secret"),
                    scopes = tokenRequest.scope?.split(" ") ?: emptyList(),
                ),
            )
        else -> throw UnsupportedOperationException("grant type ${tokenRequest.grantType} isn't implemented yet")
    }

// form url encoded
data class TokenRequest(
    var grantType: String?, // client_credentials
    var clientId: String?, // client_credentials
    var clientSecret: String?, // client_credentials
    var scope: String?, // client_credentials
)

@kotlinx.serialization.Serializable
data class KeysResponse(
    var keys: List<KeyResponse> = emptyList(),
)

@kotlinx.serialization.Serializable
data class KeyResponse(
    var e: String?,
    var n: String?,
    var alg: String?,
    var kty: String?,
    var use: String?,
    var kid: String?,
)

private fun ByteArray.encodeUrlBase64(): String = Base64.getUrlEncoder().encodeToString(this)
