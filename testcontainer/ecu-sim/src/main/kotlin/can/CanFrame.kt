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

package can

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Wire format for a single CAN frame on the TCP frame hub.
 *
 * Mirrors Linux `struct can_frame` (16 bytes) with fixed little-endian encoding,
 * matching the format spoken by `tokio-socketcan-isotp`'s TCP backend.
 *
 * Layout:
 *  - bytes 0..4   u32 LE can_id; bit 31 set => 29-bit (extended) ID
 *  - byte  4      u8 dlc (0..8)
 *  - bytes 5..8   reserved, zero
 *  - bytes 8..16  data (zero-padded beyond `dlc` bytes)
 */
data class CanFrame(
    val canId: Int,
    val dlc: Int,
    val data: ByteArray,
) {
    init {
        require(dlc in 0..8) { "DLC must be in 0..8, got $dlc" }
        require(data.size == 8) { "Data must be exactly 8 bytes (zero-padded), got ${data.size}" }
    }

    val isExtended: Boolean
        get() = (canId and EFF_FLAG) != 0

    /** CAN ID without the EFF flag bit. */
    val rawId: Int
        get() = canId and EFF_MASK

    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(WIRE_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(canId)
        buf.put(dlc.toByte())
        buf.put(0)
        buf.put(0)
        buf.put(0)
        buf.put(data)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CanFrame) return false
        return canId == other.canId && dlc == other.dlc && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = canId
        result = 31 * result + dlc
        result = 31 * result + data.contentHashCode()
        return result
    }

    companion object {
        const val WIRE_SIZE: Int = 16
        const val EFF_FLAG: Int = 0x8000_0000.toInt()
        const val EFF_MASK: Int = 0x7FFF_FFFF

        fun decode(buf: ByteArray): CanFrame {
            require(buf.size == WIRE_SIZE) { "Wire frame must be $WIRE_SIZE bytes, got ${buf.size}" }
            val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
            val id = bb.int
            val dlc = bb.get().toInt() and 0xFF
            bb.get() // reserved
            bb.get() // reserved
            bb.get() // reserved
            val data = ByteArray(8)
            bb.get(data)
            return CanFrame(id, dlc, data)
        }

        /** Build a frame from a (possibly shorter) data array, zero-padding to 8 bytes. */
        fun build(
            id: Int,
            data: ByteArray,
            extended: Boolean = false,
        ): CanFrame {
            val effectiveId = if (extended) id or EFF_FLAG else id
            val padded = ByteArray(8)
            val copyLen = minOf(data.size, 8)
            System.arraycopy(data, 0, padded, 0, copyLen)
            return CanFrame(effectiveId, copyLen, padded)
        }
    }
}
