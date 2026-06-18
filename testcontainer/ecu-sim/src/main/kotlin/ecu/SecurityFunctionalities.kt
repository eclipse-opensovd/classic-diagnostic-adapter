/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

import NrcError
import RequestsData
import utils.getByteArray
import utils.messagePayload

fun RequestsData.addSecurityAccessRequests() {
    request("27 []", name = "RequestSeed_SendKey") {
        val ecuState = ecu.ecuState()

        val subFunction = message[1]
        if (subFunction % 2 == 1) {
            // Request Seed
            val level = SecurityAccess.parse(subFunction)
            if (level == null) {
                nrc(NrcError.RequestOutOfRange)
            } else {
                // Create deterministic seed: 0x00, 0x01, 0x02, ..., 0x07
                val generatedSeed = ByteArray(8) { it.toByte() }

                var seed by ecu.storedProperty { ByteArray(0) }
                seed = generatedSeed

                ack(seed)
            }
        } else {
            // Send key
            val level =
                SecurityAccess.parse(
                    level = (subFunction - 1).toByte(),
                )
            if (level == null) {
                nrc(NrcError.RequestOutOfRange)
            } else {
                val messagePayload = this.messagePayload()
                messagePayload.get() // skip subFunction byte
                val data = messagePayload.getByteArray(messagePayload.remaining())
                var seed by ecu.storedProperty { ByteArray(0) }

                if (seed.size == 8) {
                    // Use a super secure algorithm
                    val expectedData = seed.map { it.toUByte().plus(13u).toByte() }.toByteArray()

                    if (data.contentEquals(expectedData)) {
                        ecuState.securityAccess = level
                        @Suppress("AssignedValueIsNeverRead")
                        seed = ByteArray(0)
                        ack()
                    } else {
                        nrc(NrcError.InvalidKey)
                    }
                } else {
                    nrc(NrcError.RequestSequenceError)
                }
            }
        }
    }
}
