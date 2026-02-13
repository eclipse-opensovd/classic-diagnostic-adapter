/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

package ecu

import utils.concat
import utils.paddedByteArray
import utils.to24BitByteArray
import java.nio.ByteBuffer
import java.util.BitSet
import java.util.Collections.emptyList
import kotlin.experimental.and

enum class FaultMemory(
    val memory: Byte,
) {
    Standard(0x00),
    Development(0x01),
    ;

    companion object {
        fun byName(name: String) = entries.first { it.name == name }
    }
}

class DtcFault(
    val id: Int,
    val status: DTCStatusMask,
    val emissionsRelated: Boolean = false,
    val snapshots: List<DTCSnapshotParameter> = emptyList(),
    val extendedData: List<DTCExtendedDataRecord> = emptyList(),
) {
    fun toDTCAndStatusRecord(): DTCAndStatusRecord =
        DTCAndStatusRecord(
            dtc = this.id,
            status = this.status,
        )
}

@Suppress("unused", "EnumEntryName")
enum class DTCFormatIdentifier(
    val data: Byte,
) {
    Iso15031_6(0x00),
    Iso14229_1(0x01),
    SaeJ1939_73(0x02),
    Iso11992_4(0x03),
    Iso27145_2(0x04),
}

open class DTCStatusMask(
    val testFailed: Boolean = true,
    val testFailedThisOperationCycle: Boolean = false,
    val pendingDtc: Boolean = false,
    val confirmedDtc: Boolean = true,
    val testNotCompletedSinceLastClear: Boolean = false,
    val testFailedSinceLastClear: Boolean = false,
    val testNotCompletedThisOperationCycle: Boolean = false,
    val warningIndicatorRequested: Boolean = false,
) {
    companion object {
        fun parse(buffer: ByteBuffer): DTCStatusMask {
            val data = buffer.get()
            val bs = BitSet.valueOf(byteArrayOf(data))
            return DTCStatusMask(
                testFailed = bs[0],
                testFailedThisOperationCycle = bs[1],
                pendingDtc = bs[2],
                confirmedDtc = bs[3],
                testNotCompletedSinceLastClear = bs[4],
                testFailedSinceLastClear = bs[5],
                testNotCompletedThisOperationCycle = bs[6],
                warningIndicatorRequested = bs[7],
            )
        }
    }

    val asByteArray: ByteArray
        get() {
            val bs = BitSet(8)
            bs[0] = testFailed
            bs[1] = testFailedThisOperationCycle
            bs[2] = pendingDtc
            bs[3] = confirmedDtc
            bs[4] = testNotCompletedSinceLastClear
            bs[5] = testFailedSinceLastClear
            bs[6] = testNotCompletedThisOperationCycle
            bs[7] = warningIndicatorRequested
            return bs.paddedByteArray(8)
        }

    val asByte: Byte
        get() = asByteArray[0]

    fun matches(request: DTCStatusMask) = (this.asByte and request.asByte) != 0.toByte()
}

class DTCSnapshotParameter(
    val recordNumber: Byte,
    val records: List<DTCSnapshotRecord> = emptyList(),
) {
    val asByteArray: ByteArray
        get() {
            return byteArrayOf(recordNumber) +
                byteArrayOf(records.size.toUByte().toByte()) +
                records.map { it.asByteArray }.concat()
        }
}

interface DTCSnapshotRecord {
    // must return 2 byte dataIdentifier, followed by snapshotData
    val asByteArray: ByteArray
}

interface DTCExtendedDataRecord {
    val asByteArray: ByteArray
    val recordNumber: Byte
}

class DTCAndStatusRecord(
    val dtc: Int = 0, // 24 bit
    val status: DTCStatusMask = DTCStatusMask(),
) {
    val asByteArray: ByteArray
        get() {
            return dtc.to24BitByteArray() + status.asByteArray
        }
}

class ExtendedDataRecord(
    val recordNumber: Byte,
    val recordData: DTCExtendedDataRecord,
) {
    val asByteArray: ByteArray
        get() {
            return byteArrayOf(recordNumber) + recordData.asByteArray
        }
}
