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

package webserver

import ecu.DTCStatusMask
import ecu.DTCStatusMask.Companion.parse
import ecu.DtcFault
import kotlinx.serialization.Serializable
import library.toHexString
import utils.dtcToId
import java.nio.ByteBuffer

@Serializable
class DTCStatusMaskDto(
    var testFailed: Boolean?,
    var testFailedThisOperationCycle: Boolean?,
    var pendingDtc: Boolean?,
    var confirmedDtc: Boolean?,
    var testNotCompletedSinceLastClear: Boolean?,
    var testFailedSinceLastClear: Boolean?,
    var testNotCompletedThisOperationCycle: Boolean?,
    var warningIndicatorRequested: Boolean?,
)

fun statusMaskFromDto(
    status: DTCStatusMaskDto?,
    statusMask: String?,
): DTCStatusMask =
    if (statusMask != null) {
        parse(ByteBuffer.wrap(byteArrayOf(statusMask.toUByte(16).toByte())))
    } else {
        DTCStatusMask(
            testFailed = status?.testFailed ?: true,
            testFailedThisOperationCycle = status?.testFailedThisOperationCycle ?: false,
            pendingDtc = status?.pendingDtc ?: false,
            confirmedDtc = status?.confirmedDtc ?: true,
            testNotCompletedSinceLastClear = status?.testNotCompletedSinceLastClear ?: false,
            testFailedSinceLastClear = status?.testFailedSinceLastClear ?: false,
            testNotCompletedThisOperationCycle = status?.testNotCompletedThisOperationCycle ?: false,
            warningIndicatorRequested = status?.warningIndicatorRequested ?: false,
        )
    }

fun DTCStatusMask.toDto() =
    DTCStatusMaskDto(
        testFailed = testFailed,
        testFailedThisOperationCycle = testFailedThisOperationCycle,
        pendingDtc = pendingDtc,
        confirmedDtc = confirmedDtc,
        testNotCompletedSinceLastClear = testNotCompletedSinceLastClear,
        testFailedSinceLastClear = testFailedSinceLastClear,
        testNotCompletedThisOperationCycle = testNotCompletedThisOperationCycle,
        warningIndicatorRequested = warningIndicatorRequested,
    )

@Serializable
class DtcFaultDto(
    var id: String?,
    var status: DTCStatusMaskDto?,
    var statusMask: String?,
    var emissionsRelated: Boolean?,
)

fun dtcFaultFromDto(dto: DtcFaultDto): DtcFault =
    DtcFault(
        id = dto.id!!.dtcToId(),
        status = statusMaskFromDto(dto.status, dto.statusMask),
        emissionsRelated = dto.emissionsRelated ?: false,
        // TODO set snapshot and extendedData
    )

fun DtcFault.toDto(): DtcFaultDto =
    DtcFaultDto(
        id = id.toString(16),
        status = status.toDto(),
        statusMask = status.asByteArray.toHexString(),
        emissionsRelated = emissionsRelated,
    )
