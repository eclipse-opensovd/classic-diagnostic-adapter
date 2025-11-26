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

@file:OptIn(ExperimentalUuidApi::class)

package ecu

import NrcException
import RequestResponseData
import kotlinx.serialization.Serializable
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@Serializable
data class EcuState(
    var variant: Variant = Variant.APPLICATION,
    var variantPattern: VariantPattern =
        VariantPattern(boot = "FF 00 00", application = "00 01 01", application2 = "00 10 10", application3 = "00 11 11"),
    var sessionState: SessionState = SessionState.DEFAULT,
    var securityAccess: SecurityAccess = SecurityAccess.LOCKED,
    var authentication: Authentication = Authentication.UNAUTHENTICATED,
    val blocks: List<DataBlock> =
        listOf(
            DataBlock(
                id = Uuid.parse("11000000-0000-0000-0000-000000000000"),
                type = DataBlockType.BOOT,
                softwareVersion = MajorMinorPatch(1.toByte(), 2.toByte(), 3.toByte()),
                partNumber = "1100000000",
            ),
            DataBlock(
                id = Uuid.parse("12000000-0000-0000-0000-000000000000"),
                type = DataBlockType.CODE,
                softwareVersion = MajorMinorPatch(2.toByte(), 3.toByte(), 4.toByte()),
                partNumber = "1200000000",
            ),
            DataBlock(
                id = Uuid.parse("13000000-0000-0000-0000-000000000000"),
                type = DataBlockType.DATA,
                softwareVersion = MajorMinorPatch(3.toByte(), 4.toByte(), 5.toByte()),
                partNumber = "1300000000",
            ),
        ),
    var vin: String = System.getenv("OVERRIDE_VIN") ?: "SCEDT26T8BD005261",
    var hardResetForSeconds: Int = 0,
    var maxNumberOfBlockLength: Int = 65535,
)

@Serializable
data class VariantPattern(
    val boot: String,
    val application: String,
    val application2: String,
    val application3: String,
)

@Serializable
data class DataBlock(
    val id: Uuid,
    val type: DataBlockType,
    var softwareVersion: MajorMinorPatch,
    var partNumber: String,
)

@Serializable
class MajorMinorPatch(
    val major: Byte,
    val minor: Byte,
    val patch: Byte,
) {
    val asByteArray: ByteArray
        get() =
            byteArrayOf(this.major, this.minor, this.patch)

    val asString: String
        get() =
            String.format("%02d.%02d.%02d", this.major.toUByte().toInt(), this.minor.toUByte().toInt(), this.patch.toUByte().toInt())
}

@Serializable
class YearMonthDayBCD(
    val year: Byte,
    val month: Byte,
    val day: Byte,
) {
    val asByteArray: ByteArray
        get() =
            byteArrayOf(year, month, day)
}

fun RequestResponseData.ensureEcuModeIn(vararg modes: Variant) {
    val ecuState = ecu.ecuState()
    if (!modes.contains(ecuState.variant)) {
        throw NrcException(NrcError.RequestOutOfRange)
    }
}

fun RequestResponseData.ensureSessionIn(vararg session: SessionState) {
    val ecuState = ecu.ecuState()
    if (!session.contains(ecuState.sessionState)) {
        throw NrcException(NrcError.RequestOutOfRange)
    }
}

fun RequestResponseData.ensureSecurityAccessIn(vararg securityAccess: SecurityAccess) {
    val ecuState = ecu.ecuState()
    if (!securityAccess.contains(ecuState.securityAccess)) {
        throw NrcException(NrcError.SecurityAccessDenied)
    }
}
