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

import RequestResponseData
import RequestsData
import library.toByteArray
import kotlin.time.Duration.Companion.seconds

data class DiagnosticSessionControlResponse(
    val p26ServerMax: Short = 0x32,
    val p26ServerStar: Short = 0x1f4,
) {
    val asByteArray: ByteArray
        get() = p26ServerMax.toByteArray() + p26ServerStar.toByteArray()
}

fun RequestResponseData.enableS3Timeout() {
    val addOrReplaceEcuTimer = {
        addOrReplaceEcuTimer("S3_TIMEOUT", 5.seconds) {
            val ecuState = ecu.ecuState()
            if (ecuState.sessionState != SessionState.DEFAULT ||
                ecuState.securityAccess != SecurityAccess.LOCKED
            ) {
                ecu.logger.info(
                    "Resetting ECU session, authenticationState and securityAccess to initial state, due to TesterPresent not being sent for 5 seconds",
                )
                ecuState.sessionState = SessionState.DEFAULT
                ecuState.variant = Variant.APPLICATION
            }
        }
        false
    }

    ecu.addOrReplaceEcuInterceptor(name = "_S3_TIMEOUT_", alsoCallWhenEcuIsBusy = true) {
        addOrReplaceEcuTimer()
    }

    ecu.addOrReplaceEcuOutboundInterceptor(name = "_S3_TIMEOUT_OUTBOUND_") {
        addOrReplaceEcuTimer()
    }
}

fun RequestResponseData.disableS3Timeout() {
    cancelEcuTimer("S3_TIMEOUT")
    removeEcuInterceptor("_S3_TIMEOUT_")
    ecu.removeOutboundInterceptor("_S3_TIMEOUT_")
}

fun RequestsData.addSessionRequests() {
    request("10 01", name = "DefaultSession") {
        val ecuState = ecu.ecuState()
        ecuState.sessionState = SessionState.DEFAULT

        disableS3Timeout()

        val response = DiagnosticSessionControlResponse()
        ack(response.asByteArray)
    }

    request("10 02", name = "ProgrammingSession") {
        val ecuState = ecu.ecuState()
        ecuState.sessionState = SessionState.PROGRAMMING
        ecuState.variant = Variant.BOOT

        enableS3Timeout()

        val response = DiagnosticSessionControlResponse()
        ack(response.asByteArray)
    }

    request("10 03", name = "ExtendedDiagnosticSession") {
        val ecuState = ecu.ecuState()
        ecuState.sessionState = SessionState.EXTENDED

        enableS3Timeout()

        val response = DiagnosticSessionControlResponse()
        ack(response.asByteArray)
    }

    request("10 04", name = "SafetySystemDiagnosticSession") {
        val ecuState = ecu.ecuState()
        ecuState.sessionState = SessionState.SAFETY

        enableS3Timeout()

        val response = DiagnosticSessionControlResponse()
        ack(response.asByteArray)
    }

    request("10 44", name = "CustomSession") {
        val ecuState = ecu.ecuState()
        ecuState.sessionState = SessionState.CUSTOM

        enableS3Timeout()

        val response = DiagnosticSessionControlResponse()
        ack(response.asByteArray)
    }
}
