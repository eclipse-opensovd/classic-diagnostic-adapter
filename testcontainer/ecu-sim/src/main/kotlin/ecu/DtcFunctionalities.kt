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

import ecu.DTCAndStatusRecord
import ecu.DTCFormatIdentifier
import ecu.DTCSnapshotParameter
import ecu.DTCStatusMask
import ecu.ExtendedDataRecord
import ecu.FaultMemory
import ecu.dtcFaults
import utils.concat
import utils.get24BitInt
import utils.messagePayload
import utils.to24BitByteArray
import utils.toByteArray
import java.nio.ByteBuffer

private val AllAvailableStatusMask =
    DTCStatusMask(
        testFailed = true,
        testFailedThisOperationCycle = true,
        pendingDtc = true,
        confirmedDtc = true,
        testNotCompletedSinceLastClear = true,
        testFailedSinceLastClear = true,
        testNotCompletedThisOperationCycle = true,
        warningIndicatorRequested = true,
    )

fun RequestsData.addDtcRequests() {
    request("14 []", "ClearDiagnosticInformation") {
        val payload = messagePayload()
        val dtcCode = payload.get24BitInt()
        val memory =
            if (payload.hasRemaining()) {
                payload.get()
            } else {
                null
            }
        // ISO-14229-1, D.1
        // 0xFFFFFF means delete all groups
        val cleanupAll = dtcCode == 0xFFFFFF
        FaultMemory.entries
            .filter { memory == null || it.memory == memory }
            .forEach { entry ->
                val dtcFaults = ecu.dtcFaults(entry)
                if (cleanupAll) {
                    dtcFaults.clear()
                    ecu.logger.info("Removed all DTCs for memory ${entry.memory}")
                } else {
                    if (dtcFaults.remove(dtcCode) != null) {
                        ecu.logger.info("DTC ${dtcCode.toString(16)} removed")
                    } else {
                        ecu.logger.info("DTC ${dtcCode.toString(16)} couldn't be removed (not present)")
                    }
                }
            }
        ack()
    }

    request("19 01 []", "ReadDTCInformation_NumberByStatusMask") {
        val statusMask = DTCStatusMask.parse(messagePayload())
        val faults = ecu.dtcFaults(FaultMemory.Standard).values.filter { it.status.matches(statusMask) }
        val response =
            ReadDtcNumberOfDTCByStatusMaskResponse(
                availabilityStatusMask = AllAvailableStatusMask,
                dtcCount = faults.size.toUShort(),
            )
        ack(response.asByteArray)
    }

    request("19 02 []", "ReadDTCInformation_DTCByStatusMask") {
        val request = DTCStatusMask.parse(messagePayload())
        val faults = ecu.dtcFaults(FaultMemory.Standard).values.filter { it.status.matches(request) }
        ecu.logger.info("Reporting ${faults.size} DTCs for status mask: ${request.asByte.toString(16)}")

        val response =
            ReadDtcDTCByStatusMaskResponse(
                // all fields are available
                availabilityStatusMask = AllAvailableStatusMask,
                records = faults.map { it.toDTCAndStatusRecord() },
            )

        ack(response.asByteArray)
    }

    request("19 04 []", "ReadDTCInformation_ReportDTCSnapshotRecordByDTCNbr") {
        val request = ReadDtcDTCWithSnapshotRecordByDTCNbrRequest.parse(messagePayload())

        val fault = ecu.dtcFaults(FaultMemory.Standard)[request.dtc]
        if (fault == null) {
            nrc(NrcError.RequestOutOfRange)
        } else {
            val response =
                ReadDtcDTCWithSnapshotRecordByDTCNbrResponse(
                    dtc = fault.id,
                    status = fault.status,
                    parameters = fault.snapshots,
                )
            ack(response.asByteArray)
        }
    }

    request("19 06 []", "ReadDTCInformation_ReportDTCExtendedDataByDTCNbr") {
        val request = ReadDtcReportDTCExtendedDataByDTCNbrRequest.parse(messagePayload())
        val fault = ecu.dtcFaults(FaultMemory.Standard)[request.dtc]
        if (fault == null) {
            nrc(NrcError.RequestOutOfRange)
        } else {
            val response =
                ReadDtcReportDTCExtendedDataByDTCNbrResponse(
                    dtc = fault.id,
                    statusMask = fault.status,
                    extendedDataRecords =
                        fault.extendedData.map {
                            ExtendedDataRecord(
                                recordNumber = it.recordNumber,
                                recordData = it,
                            )
                        },
                )
            ack(response.asByteArray)
        }
    }
}

class ReadDtcDTCByStatusMaskResponse(
    val availabilityStatusMask: DTCStatusMask,
    val records: List<DTCAndStatusRecord> = emptyList(),
) {
    val asByteArray: ByteArray
        get() {
            return availabilityStatusMask.asByteArray + records.map { it.asByteArray }.concat()
        }
}

class ReadDtcNumberOfDTCByStatusMaskResponse(
    val availabilityStatusMask: DTCStatusMask,
    val dtcFormatIdentifier: DTCFormatIdentifier = DTCFormatIdentifier.Iso14229_1,
    val dtcCount: UShort = 0u,
) {
    val asByteArray: ByteArray
        get() {
            return availabilityStatusMask.asByteArray + byteArrayOf(dtcFormatIdentifier.data) + dtcCount.toByteArray()
        }
}

class ReadDtcDTCWithSnapshotRecordByDTCNbrRequest(
    val dtc: Int, // 24 bit
    val recordNumber: Byte,
) {
    companion object {
        fun parse(buffer: ByteBuffer): ReadDtcDTCWithSnapshotRecordByDTCNbrRequest {
            val dtc = buffer.get24BitInt()
            val recordNumber = buffer.get()
            return ReadDtcDTCWithSnapshotRecordByDTCNbrRequest(
                dtc = dtc,
                recordNumber = recordNumber,
            )
        }
    }
}

class ReadDtcDTCWithSnapshotRecordByDTCNbrResponse(
    val dtc: Int, // 24 bit
    val status: DTCStatusMask,
    val parameters: List<DTCSnapshotParameter>,
) {
    val asByteArray: ByteArray
        get() {
            return dtc.to24BitByteArray() + status.asByteArray + parameters.map { it.asByteArray }.concat()
        }
}

class ReadDtcReportDTCExtendedDataByDTCNbrRequest(
    val dtc: Int, // 24 bit
    val recordNumber: Byte,
) {
    companion object {
        fun parse(buffer: ByteBuffer): ReadDtcReportDTCExtendedDataByDTCNbrRequest {
            val dtc = buffer.get24BitInt()
            val recordNumber = buffer.get()
            return ReadDtcReportDTCExtendedDataByDTCNbrRequest(
                dtc = dtc,
                recordNumber = recordNumber,
            )
        }
    }
}

class ReadDtcReportDTCExtendedDataByDTCNbrResponse(
    val dtc: Int,
    val statusMask: DTCStatusMask,
    val extendedDataRecords: List<ExtendedDataRecord> = emptyList(),
) {
    val asByteArray: ByteArray
        get() {
            return dtc.to24BitByteArray() + statusMask.asByteArray + extendedDataRecords.map { it.asByteArray }.concat()
        }
}
