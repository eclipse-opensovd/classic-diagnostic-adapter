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

@file:OptIn(ExperimentalUuidApi::class)

package utils

import RequestResponseData
import ecu.MajorMinorPatch
import ecu.YearMonthDayBCD
import io.ktor.server.plugins.BadRequestException
import kotlinx.io.bytestring.encode
import library.toByteArray
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.BitSet
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

fun List<ByteArray>.combine(): ByteArray {
    val out = ByteArrayOutputStream()
    this.forEach { out.write(it) }
    return out.toByteArray()
}

fun ByteArray.toShort(): Short {
    require(this.size == 2)
    return ByteBuffer.wrap(this).getShort(0)
}

fun ByteArray.toInt(): Int {
    require(this.size == 4)
    return ByteBuffer.wrap(this).getInt(0)
}

fun ByteArray.toULong(): ULong =
    when (this.size) {
        4 ->
            ByteBuffer
                .wrap(this)
                .getInt(0)
                .toULong()
                .and(0xFFFFFFFF.toULong())
        8 -> ByteBuffer.wrap(this).getLong(0).toULong()
        else -> throw NotImplementedError("Converting Byte-Array to ULong (size ${this.size}) not implemented")
    }

fun List<ByteArray>.concat(): ByteArray =
    if (this.isEmpty()) {
        ByteArray(0)
    } else if (this.size == 1) {
        this[0]
    } else {
        val byteBuffer = ByteBuffer.allocate(this.sumOf { it.size })
        this.forEach { byteBuffer.put(it) }
        byteBuffer.array()
    }

fun Int.toFittedByteArray(): ByteArray =
    if (this <= UByte.MAX_VALUE.toInt()) {
        byteArrayOf(this.toByte())
    } else if (this <= UShort.MAX_VALUE.toInt()) {
        this.toShort().toByteArray()
    } else {
        this.toByteArray()
    }

fun UShort.toByteArray(): ByteArray = this.toShort().toByteArray()

fun Long.toByteArray(): ByteArray =
    byteArrayOf(
        (this and 0xFF00000000000000u.toLong() shr 56).toByte(),
        (this and 0xFF000000000000u.toLong() shr 48).toByte(),
        (this and 0xFF0000000000u.toLong() shr 40).toByte(),
        (this and 0xFF00000000u.toLong() shr 32).toByte(),
        (this and 0xFF000000 shr 24).toByte(),
        (this and 0xFF0000 shr 16).toByte(),
        (this and 0xFF00 shr 8).toByte(),
        (this and 0xFF).toByte(),
    )

fun ULong.toByteArray(size: Int): ByteArray =
    when (size) {
        2 -> this.toShort().toByteArray()
        4 -> this.toInt().toByteArray()
        8 -> this.toLong().toByteArray()
        else -> throw IllegalArgumentException("Unknown size $size")
    }

fun BitSet.paddedByteArray(nBits: Int): ByteArray {
    val length = nBits / 8
    val data = this.toByteArray()
    if (data.size < length) {
        return ByteArray(length - data.size) + data
    }
    return data
}

fun ByteArray.padLeft(
    length: Int,
    value: Byte = 0,
): ByteArray =
    if (this.size < length) {
        val r =
            ByteArray(length) {
                value
            }
        System.arraycopy(this, 0, r, r.size - this.size, this.size)
        r
    } else {
        this
    }

fun ByteArray.padRight(
    length: Int,
    value: Byte = 0,
): ByteArray =
    if (this.size < length) {
        val r =
            ByteArray(length) {
                value
            }
        System.arraycopy(this, 0, r, 0, this.size)
        r
    } else {
        this
    }

fun ByteArray.encodeBase64(): String = Base64.encode(this)

fun String.decodeBase64(): ByteArray = Base64.decode(this)

fun createSequencedByteArray(
    size: Int,
    first: Byte = 0x00,
): ByteArray {
    val array = ByteArray(size)
    for (i in 0 until size) {
        array[i] = (i % 256).toByte()
    }
    if (size > 0) {
        array[0] = first
    }
    return array
}

fun createRandomByteArray(size: Int): ByteArray {
    val array = ByteArray(size)
    Random.nextBytes(array)
    return array
}

fun RequestResponseData.messagePayload(offset: Int = -1): ByteBuffer =
    when (offset) {
        -1 -> {
            val calculatedOffset = this.caller.requestBytes.size
            ByteBuffer.wrap(this.message, calculatedOffset, this.message.size - calculatedOffset)
        }
        else -> ByteBuffer.wrap(this.message, offset, this.message.size - offset)
    }

fun ByteBuffer.getByteArray(length: Int): ByteArray {
    val data = ByteArray(length)
    this.get(data)
    return data
}

fun ByteBuffer.getLengthPrefixedByteArray(prefixLength: Int = 2): ByteArray {
    val length =
        when (prefixLength) {
            2 -> this.short.toUShort().toInt()
            4 -> this.int.toUInt().toInt()
            else -> throw UnsupportedOperationException("Unsupported prefix length")
        }
    return this.getByteArray(length)
}

fun String.toUuid(): Uuid = Uuid.parse(this)

fun String.toMajorMinorPatch(): MajorMinorPatch {
    val split = Regex("([0-9]{1,2})\\.([0-9]{1,2})\\.([0-9]{1,2})")
    split.matchEntire(this)?.let {
        val major = it.groupValues[1].toByte()
        val minor = it.groupValues[2].toByte()
        val patch = it.groupValues[3].toByte()
        return MajorMinorPatch(major, minor, patch)
    }
    throw BadRequestException("Invalid Major Minor patch format")
}

fun String.toYearMonthDayBCD(): YearMonthDayBCD {
    val split = Regex("([0-9]{1,2})/([0-9]{1,2})/([0-9]{1,2})")
    split.matchEntire(this)?.let {
        val major = it.groupValues[1].toByte(16)
        val minor = it.groupValues[2].toByte(16)
        val patch = it.groupValues[3].toByte(16)
        return YearMonthDayBCD(major, minor, patch)
    }
    throw BadRequestException("Invalid Major Minor patch format")
}
