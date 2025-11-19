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

package utils

import io.ktor.server.plugins.BadRequestException
import java.nio.ByteBuffer
import java.util.regex.Pattern

fun String.dtcToId(): Int {
    // UDS (3 Byte DTC)
    // check for invalid characters and correct size of the input string
    if (!Pattern.matches("[bBcCPpUu][0-9a-fA-F]{6}", this) &&
        !Pattern.matches("[0-9a-fA-F]{6}", this)
    ) {
        throw BadRequestException("Not a valid dtc number")
    }
    if (this.length == 7) {
        // SAE formatted -> convert
        return saeDtcToInt(this)
    }
    return this.toInt(16)
}

fun saeDtcToInt(saeDtc: String): Int {
    if (saeDtc.length != 7) {
        throw IllegalArgumentException("Invalid SAE dtc code '$saeDtc'")
    }
    // System
    // 00 - Power train (P)
    // 01 - Chassis (C)
    // 10 - Body (B)
    // 11- Network Communications (U)
    val system = when (saeDtc[0]) {
        'P' -> 0
        'C' -> 1
        'B' -> 2
        'U' -> 3
        else -> throw IllegalArgumentException("Unknown system digit in SAE dtc code '$saeDtc'")
    }

    // Group:
    // 00 - SAE/ISO Controlled (0)
    // 01 - Manufacturer Controlled (1)
    // 10 - For (P) SAE/ISO / Rest Manufacturer Controlled (2)
    // 11 - SAE/ISO Controlled (3)
    val group = when (saeDtc[1]) {
        '0' -> 0
        '1' -> 1
        '2' -> 2
        '3' -> 3
        else -> throw IllegalArgumentException("Unknown group digit in SAE dtc code '$saeDtc'")
    }

    return (system shl 22) or (group shl 20) or saeDtc.substring(2).toInt(16)

}

fun Int.to24BitByteArray(): ByteArray =
    byteArrayOf((this and 0xFF0000 shr 16).toByte(), (this and 0xFF00 shr 8).toByte(), this.toByte())

fun ByteBuffer.get24BitInt(): Int =
    byteArrayOf(0x00, this.get(), this.get(), this.get()).toInt()
