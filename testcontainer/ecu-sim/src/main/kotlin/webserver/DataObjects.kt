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

@file:OptIn(ExperimentalUuidApi::class)

package webserver

import ecu.Authentication
import ecu.CommunicationControlType
import ecu.DataBlock
import ecu.DataBlockType
import ecu.DataTransferDownload
import ecu.DtcSettingType
import ecu.EcuState
import ecu.MajorMinorPatch
import ecu.SecurityAccess
import ecu.SessionState
import ecu.Variant
import kotlinx.serialization.Serializable
import library.toHexString
import utils.toMajorMinorPatch
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@Serializable
data class EcuStateDto(
    val variant: Variant? = null,
    val sessionState: SessionState? = null,
    val securityAccess: SecurityAccess? = null,
    var authentication: Authentication? = null,
    val bootSoftwareVersions: List<MajorMinorPatch>? = null,
    val applicationSoftwareVersions: List<MajorMinorPatch>? = null,
    val vin: String? = null,
    val hardResetForSeconds: Int? = null,
    val maxNumberOfBlockLength: Int? = null,
    val blocks: List<DataBlockDto>? = null,
    val communicationControlType: CommunicationControlType? = null,
    val temporalEraId: Int? = null,
    val dtcSettingType: DtcSettingType? = null,
)

fun EcuState.updateWith(dto: EcuStateDto) {
    this.variant = dto.variant ?: this.variant
    this.sessionState = dto.sessionState ?: this.sessionState
    this.securityAccess = dto.securityAccess ?: this.securityAccess
    this.authentication = dto.authentication ?: this.authentication
    this.vin = dto.vin ?: this.vin
    this.maxNumberOfBlockLength = dto.maxNumberOfBlockLength ?: this.maxNumberOfBlockLength
    this.dtcSettingType = dto.dtcSettingType ?: this.dtcSettingType
}

fun EcuState.toDto() =
    EcuStateDto(
        variant = this.variant,
        sessionState = this.sessionState,
        securityAccess = this.securityAccess,
        authentication = this.authentication,
        vin = this.vin,
        hardResetForSeconds = this.hardResetForSeconds,
        maxNumberOfBlockLength = this.maxNumberOfBlockLength,
        blocks = this.blocks.map { it.toDto() },
        communicationControlType = this.communicationControlType,
        temporalEraId = this.temporalEraId,
        dtcSettingType = this.dtcSettingType,
    )

@Serializable
data class DataTransferDownloadDto(
    val addressAndLengthIdentifier: UByte,
    val memoryAddress: String,
    val memorySize: String,
    val isActive: Boolean,
    val dataTransferCount: Int,
    val checksum: String?,
)

fun DataTransferDownload.toDto() =
    DataTransferDownloadDto(
        addressAndLengthIdentifier = this.addressAndLengthIdentifier.toUByte(),
        memoryAddress = this.memoryAddress.toHexString(),
        memorySize = this.memorySize.toHexString(),
        isActive = this.isActive,
        dataTransferCount = this.dataTransferCount,
        checksum = if (!this.isActive) this.checksum?.toHexString() else null,
    )

@Serializable
data class DataBlockDto(
    val id: Uuid,
    val type: DataBlockType,
    val softwareVersion: String?,
    val partNumber: String?,
)

fun DataBlock.toDto() =
    DataBlockDto(
        id = id,
        type = type,
        softwareVersion = softwareVersion.asString,
        partNumber = partNumber,
    )

fun DataBlock.updateWith(dto: DataBlockDto) {
    this.softwareVersion = dto.softwareVersion?.toMajorMinorPatch() ?: this.softwareVersion
    this.partNumber = dto.partNumber ?: this.partNumber
}
