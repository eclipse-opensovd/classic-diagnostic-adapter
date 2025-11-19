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
import library.ExperimentalDoipDslApi
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalDoipDslApi::class)
fun RequestsData.addResetRequests() {
    request("11 01", name = "HardReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION

        if (ecuState.hardResetForSeconds > 0) {
            hardResetEntityFor(ecuState.hardResetForSeconds.seconds)
        }
        disableS3Timeout()

        ack()
    }

    request("11 02", name = "KeyOffOnReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION
        disableS3Timeout()
        ack()
    }

    request("11 03", name = "SoftReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION
        disableS3Timeout()
        ack()
    }
}
