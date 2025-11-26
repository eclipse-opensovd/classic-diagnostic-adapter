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

package ecu

import RequestsData
import library.toByteArray
import utils.createSequencedByteArray
import utils.messagePayload
import utils.toByteArray
import java.nio.ByteBuffer

/*
    see Authentication_SID_29.md
 */

fun RequestsData.addAuthenticationRequests() {
    // decomposes the subfunctions into individual requests
    fun authenticationByProofOfOwnership(proofOfOwnershipClient: ByteArray): Authentication =
        try {
            Authentication.valueOf(proofOfOwnershipClient.decodeToString())
        } catch (e: IllegalArgumentException) {
            Authentication.UNAUTHENTICATED
        }

    fun determineAuthenticationReturn(
        authentication: Authentication,
        success: AuthenticationReturnParameter =
            AuthenticationReturnParameter.OWNERSHIP_VERIFIED__AUTHENTICATION_COMPLETE,
    ): AuthenticationReturnParameter =
        when (authentication) {
            Authentication.UNAUTHENTICATED -> AuthenticationReturnParameter.GENERAL_REJECT
            else -> success
        }

    request("29 00", "Authentication_Deauthenticate") {
        val ecuState = ecu.ecuState()
        ecuState.authentication = Authentication.UNAUTHENTICATED
        val response = DeauthenticateResponse(AuthenticationReturnParameter.DEAUTHENTICATION_SUCCESSFUL)
        ack(response.asByteArray)
    }

    request("29 01 []", "Authentication_VerifyCertificateUnidirectional") {
        VerifyCertificateUnidirectionalRequest.parse(messagePayload())
        val response =
            VerifyCertificateUnidirectionalResponse(
                authenticationReturn = AuthenticationReturnParameter.CERTIFICATE_VERIFIED__OWNERSHIP_VERIFICATION_NECESSARY,
                challengeServer = createSequencedByteArray(16, 0x01),
                ephemeralPublicKeyServer = createSequencedByteArray(16, 0x02),
            )
        ack(response.asByteArray)
    }

    request("29 02 []", "Authentication_VerifyCertificateBidirectional") {
        VerifyCertificateBidirectionalRequest.parse(messagePayload())
        val response =
            VerifyCertificateBidirectionalResponse(
                authenticationReturn = AuthenticationReturnParameter.CERTIFICATE_VERIFIED__OWNERSHIP_VERIFICATION_NECESSARY,
                challengeServer = createSequencedByteArray(16, 0x01),
                certificateServer = createSequencedByteArray(16, 0x02),
                ephemeralPublicKeyServer = createSequencedByteArray(16, 0x03),
                proofOfOwnershipServer = createSequencedByteArray(16, 0x04),
            )
        ack(response.asByteArray)
    }

    request("29 03 []", "Authentication_ProofOfOwnership") {
        val request = ProofOfOwnershipRequest.parse(messagePayload())
        val ecuState = ecu.ecuState()
        ecuState.authentication = authenticationByProofOfOwnership(request.proofOfOwnershipClient)
        val response =
            ProofOfOwnershipResponse(
                authenticationReturn =
                    determineAuthenticationReturn(
                        ecuState.authentication,
                        AuthenticationReturnParameter.OWNERSHIP_VERIFIED__AUTHENTICATION_COMPLETE,
                    ),
                sessionKeyInfo = createSequencedByteArray(16, 0x01),
            )
        ack(response.asByteArray)
    }

    request("29 04 []", "Authentication_TransmitCertificate") {
        TransmitCertificateRequest.parse(messagePayload())
        val response = TransmitCertificateResponse(AuthenticationReturnParameter.CERTIFICATE_VERIFIED)
        ack(response.asByteArray)
    }

    request("29 05 []", "Authentication_RequestChallengeForAuthentication") {
        RequestChallengeForAuthenticationRequest.parse(messagePayload())
        val response =
            RequestChallengeForAuthenticationResponse(
                authenticationReturn = AuthenticationReturnParameter.REQUEST_ACCEPTED,
                algorithmIndicator = createSequencedByteArray(16, 0x01),
                challengeServer = createSequencedByteArray(16, 0x02),
                neededAdditionalParameter = createSequencedByteArray(16, 0x03),
            )
        ack(response.asByteArray)
    }

    request("29 06 []", "Authentication_VerifyProofOfOwnershipUnidirectional") {
        val request = VerifyProofOfOwnershipUnidirectionalRequest.parse(messagePayload())
        val ecuState = ecu.ecuState()
        ecuState.authentication = authenticationByProofOfOwnership(request.proofOfOwnershipClient)
        val response =
            VerifyProofOfOwnershipUnidirectionalResponse(
                authenticationReturn = determineAuthenticationReturn(ecuState.authentication),
                algorithmIndicator = createSequencedByteArray(16, 0x01),
                sessionKeyInfo = createSequencedByteArray(16, 0x02),
            )
        ack(response.asByteArray)
    }

    request("29 07 []", "Authentication_VerifyProofOfOwnershipBidirectional") {
        val request = VerifyProofOfOwnershipBidirectionalRequest.parse(messagePayload())
        val ecuState = ecu.ecuState()
        ecuState.authentication = authenticationByProofOfOwnership(request.proofOfOwnershipClient)
        val response =
            VerifyProofOfOwnershipBidirectionalResponse(
                authenticationReturn = determineAuthenticationReturn(ecuState.authentication),
                algorithmIndicator = createSequencedByteArray(16, 0x01),
                proofOfOwnershipServer = createSequencedByteArray(16, 0x02),
                sessionKeyInfo = createSequencedByteArray(16, 0x03),
            )
        ack(response.asByteArray)
    }

    request("29 08", "Authentication_Configuration") {
        val response =
            AuthenticationConfigurationResponse(AuthenticationReturnParameter.AUTHENTICATION_CONFIGURATION_APCE)
        ack(response.asByteArray)
    }
}

enum class AuthenticationReturnParameter(
    val value: Byte,
) {
    REQUEST_ACCEPTED(0x00),
    GENERAL_REJECT(0x01),
    AUTHENTICATION_CONFIGURATION_APCE(0x02),
    AUTHENTICATION_CONFIGURATION_ACR_WITH_ASYMMETRIC_CRYPTO(0x03),
    AUTHENTICATION_CONFIGURATION_ACR_WITH_SYMMETRIC_CRYPTO(0x04),

    // ISO SAE Reserved 0x5-0x9
    DEAUTHENTICATION_SUCCESSFUL(0x10),
    CERTIFICATE_VERIFIED__OWNERSHIP_VERIFICATION_NECESSARY(0x11),
    OWNERSHIP_VERIFIED__AUTHENTICATION_COMPLETE(0x12),
    CERTIFICATE_VERIFIED(0x13),
}

class DeauthenticateResponse(
    val authenticationReturn: AuthenticationReturnParameter,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(authenticationReturn.value)
}

class VerifyCertificateUnidirectionalRequest(
    val communicationConfiguration: Byte,
    val certificateClient: ByteArray,
    val challengeClient: ByteArray,
) {
    companion object {
        fun parse(buffer: ByteBuffer): VerifyCertificateUnidirectionalRequest {
            val commConfig = buffer.get()

            val certLength = buffer.getShort().toUShort().toInt()
            val certClient = ByteArray(certLength)
            buffer.get(certClient)

            val challengeLength = buffer.getShort().toUShort().toInt()
            val challengeClient = ByteArray(challengeLength)
            buffer.get(challengeClient)

            return VerifyCertificateUnidirectionalRequest(
                communicationConfiguration = commConfig,
                certificateClient = certClient,
                challengeClient = challengeClient,
            )
        }
    }
}

class VerifyCertificateUnidirectionalResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val challengeServer: ByteArray,
    val ephemeralPublicKeyServer: ByteArray,
) {
    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                challengeServer.size.toShort().toByteArray() +
                challengeServer +
                ephemeralPublicKeyServer.size.toUShort().toByteArray() +
                ephemeralPublicKeyServer
}

class VerifyCertificateBidirectionalRequest(
    val communicationConfiguration: Byte,
    val certificateClient: ByteArray,
    val challengeClient: ByteArray,
) {
    companion object {
        fun parse(buffer: ByteBuffer): VerifyCertificateBidirectionalRequest {
            val coco = buffer.get()

            val certLength = buffer.getShort().toUShort().toInt()
            val certClient = ByteArray(certLength)
            buffer.get(certClient)

            val challengeLength = buffer.getShort().toUShort().toInt()
            val challengeClient = ByteArray(challengeLength)
            buffer.get(challengeClient)

            return VerifyCertificateBidirectionalRequest(
                communicationConfiguration = coco,
                certificateClient = certClient,
                challengeClient = challengeClient,
            )
        }
    }
}

class VerifyCertificateBidirectionalResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val challengeServer: ByteArray,
    val certificateServer: ByteArray,
    val ephemeralPublicKeyServer: ByteArray,
    val proofOfOwnershipServer: ByteArray,
) {
    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                challengeServer.size.toUShort().toByteArray() +
                challengeServer +
                certificateServer.size.toUShort().toByteArray() +
                certificateServer +
                proofOfOwnershipServer.size.toUShort().toByteArray() +
                proofOfOwnershipServer +
                ephemeralPublicKeyServer.size.toUShort().toByteArray() +
                ephemeralPublicKeyServer
}

class ProofOfOwnershipRequest(
    val proofOfOwnershipClient: ByteArray,
    val ephemeralPublicKey: ByteArray,
) {
    companion object {
        fun parse(buffer: ByteBuffer): ProofOfOwnershipRequest {
            val pooClientLength = buffer.getShort()
            val pooClient = ByteArray(pooClientLength.toInt())
            buffer.get(pooClient)

            val ephemeralKeyLength = buffer.getShort().toUShort().toInt()
            val ephemeralKey = ByteArray(ephemeralKeyLength)
            buffer.get(ephemeralKey)

            return ProofOfOwnershipRequest(
                proofOfOwnershipClient = pooClient,
                ephemeralPublicKey = ephemeralKey,
            )
        }
    }
}

class ProofOfOwnershipResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val sessionKeyInfo: ByteArray,
) {
    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                sessionKeyInfo.size.toUShort().toByteArray() +
                sessionKeyInfo
}

class TransmitCertificateRequest(
    val certEvalId: Short,
    val certData: ByteArray,
) {
    companion object {
        fun parse(buffer: ByteBuffer): TransmitCertificateRequest {
            val certEvalId = buffer.getShort()
            val certDataLength = buffer.getShort().toUShort().toInt()
            val certData = ByteArray(certDataLength)
            buffer.get(certData)
            return TransmitCertificateRequest(
                certEvalId = certEvalId,
                certData = certData,
            )
        }
    }
}

class TransmitCertificateResponse(
    val authenticationReturn: AuthenticationReturnParameter,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(authenticationReturn.value)
}

class RequestChallengeForAuthenticationRequest(
    val communicationConfiguration: Byte,
    val algorithmIndicator: ByteArray, // 16 byte
) {
    companion object {
        fun parse(buffer: ByteBuffer): RequestChallengeForAuthenticationRequest {
            val coco = buffer.get()
            val algorithmIndicator = ByteArray(16)
            buffer.get(algorithmIndicator)
            return RequestChallengeForAuthenticationRequest(
                communicationConfiguration = coco,
                algorithmIndicator = algorithmIndicator,
            )
        }
    }
}

class RequestChallengeForAuthenticationResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val algorithmIndicator: ByteArray, // 16 bytes
    val challengeServer: ByteArray,
    val neededAdditionalParameter: ByteArray,
) {
    init {
        if (algorithmIndicator.size != 16) {
            throw IllegalArgumentException("Algorithm indicator must have 16 bytes")
        }
    }

    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                algorithmIndicator +
                challengeServer.size.toUShort().toByteArray() +
                challengeServer +
                neededAdditionalParameter.size.toUShort().toByteArray() +
                neededAdditionalParameter
}

class VerifyProofOfOwnershipUnidirectionalRequest(
    val algorithmIndicator: ByteArray,
    val proofOfOwnershipClient: ByteArray,
    val challengeClient: ByteArray,
    val additionalParameter: ByteArray = ByteArray(0),
) {
    companion object {
        fun parse(buffer: ByteBuffer): VerifyProofOfOwnershipUnidirectionalRequest {
            val algorithmIndicator = ByteArray(16)
            buffer.get(algorithmIndicator)

            val pooClientLength = buffer.getShort().toUShort().toInt()
            val pooClient = ByteArray(pooClientLength)
            buffer.get(pooClient)

            val challengeClientLength = buffer.getShort().toUShort().toInt()
            val challengeClient = ByteArray(challengeClientLength)
            buffer.get(challengeClient)

            val additionalParamLength = buffer.getShort().toUShort().toInt()
            val additionalParam = ByteArray(additionalParamLength)
            buffer.get(additionalParam)

            return VerifyProofOfOwnershipUnidirectionalRequest(
                algorithmIndicator = algorithmIndicator,
                proofOfOwnershipClient = pooClient,
                challengeClient = challengeClient,
                additionalParameter = additionalParam,
            )
        }
    }
}

class VerifyProofOfOwnershipUnidirectionalResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val algorithmIndicator: ByteArray, // 16 bytes
    val sessionKeyInfo: ByteArray,
) {
    init {
        if (algorithmIndicator.size != 16) {
            throw IllegalArgumentException("Algorithm indicator must have 16 bytes")
        }
    }

    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                algorithmIndicator +
                sessionKeyInfo.size.toUShort().toByteArray() +
                sessionKeyInfo
}

class VerifyProofOfOwnershipBidirectionalRequest(
    val algorithmIndicator: ByteArray,
    val proofOfOwnershipClient: ByteArray,
    val challengeClient: ByteArray,
    val additionalParameter: ByteArray = ByteArray(0),
) {
    companion object {
        fun parse(buffer: ByteBuffer): VerifyProofOfOwnershipBidirectionalRequest {
            val algorithmIndicator = ByteArray(16)
            buffer.get(algorithmIndicator)

            val pooClientLength = buffer.getShort().toUShort().toInt()
            val pooClient = ByteArray(pooClientLength)
            buffer.get(pooClient)

            val challengeClientLength = buffer.getShort().toUShort().toInt()
            val challengeClient = ByteArray(challengeClientLength)
            buffer.get(challengeClient)

            val additionalParamLength = buffer.getShort().toUShort().toInt()
            val additionalParam = ByteArray(additionalParamLength)
            buffer.get(additionalParam)

            return VerifyProofOfOwnershipBidirectionalRequest(
                algorithmIndicator = algorithmIndicator,
                proofOfOwnershipClient = pooClient,
                challengeClient = challengeClient,
                additionalParameter = additionalParam,
            )
        }
    }
}

class VerifyProofOfOwnershipBidirectionalResponse(
    val authenticationReturn: AuthenticationReturnParameter,
    val algorithmIndicator: ByteArray, // 16 bytes
    val proofOfOwnershipServer: ByteArray,
    val sessionKeyInfo: ByteArray,
) {
    init {
        if (algorithmIndicator.size != 16) {
            throw IllegalArgumentException("Algorithm indicator must have 16 bytes")
        }
    }

    val asByteArray: ByteArray
        get() =
            byteArrayOf(authenticationReturn.value) +
                algorithmIndicator +
                proofOfOwnershipServer.size.toUShort().toByteArray() +
                proofOfOwnershipServer +
                sessionKeyInfo.size.toUShort().toByteArray() +
                sessionKeyInfo
}

class AuthenticationConfigurationResponse(
    val authenticationReturn: AuthenticationReturnParameter,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(authenticationReturn.value)
}
