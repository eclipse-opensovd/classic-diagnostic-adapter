/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
import kotlin.random.Random

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
                // Create seed and fill with random data
                val generatedSeed = ByteArray(8)
                Random.nextBytes(generatedSeed)

                var seed by ecu.storedProperty { ByteArray(0) }
                seed = generatedSeed

                ack(byteArrayOf((level.level + 1).toByte(), *seed))
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
