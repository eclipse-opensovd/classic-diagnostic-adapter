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

package ecu

import RequestsData
import library.decodeHex
import utils.combine
import java.text.SimpleDateFormat
import java.time.ZoneOffset
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.toJavaInstant

class SoftwareIdentifierResponse(vararg val softwareVersionIdentifier: MajorMinorPatch) {
    val asByteArray: ByteArray
        get() = byteArrayOf(softwareVersionIdentifier.size.toByte()) +
                softwareVersionIdentifier.map { it.asByteArray }.combine()

}


@OptIn(ExperimentalTime::class)
fun RequestsData.addDiagnosticRequests() {
    request("22 F1 00", name = "Identification_Read") {
        val ecuState = ecu.ecuState()
        val identification = when (ecuState.variant) {
            Variant.BOOT -> ecuState.variantPattern.boot.decodeHex()
            Variant.APPLICATION -> ecuState.variantPattern.application.decodeHex()
            Variant.APPLICATION2 -> ecuState.variantPattern.application2.decodeHex()
            Variant.APPLICATION3 -> ecuState.variantPattern.application3.decodeHex()
        }
        ack(identification)
    }

    request("22 F1 80", name = "BootSoftwareIdentificationDataIdentifier_Read") {
        val ecuState = ecu.ecuState()
        val bootBlockVersions = ecuState.blocks.filter { it.type == DataBlockType.BOOT }.map { it.softwareVersion }
        val response = SoftwareIdentifierResponse(*bootBlockVersions.toTypedArray())
        ack(response.asByteArray)
    }

    request("22 F1 81", name = "ApplicationSoftwareIdentificationDataIdentifier_Read") {
        val ecuState = ecu.ecuState()
        val appBlockVersions = ecuState.blocks.filter { it.type == DataBlockType.CODE }.map { it.softwareVersion }
        val response = SoftwareIdentifierResponse(*appBlockVersions.toTypedArray())
        ack(response.asByteArray)
    }

    request("22 F1 82", name = "ApplicationDataIdentificationDataIdentifier_Read") {
        val ecuState = ecu.ecuState()
        val appBlockVersions = ecuState.blocks.filter { it.type == DataBlockType.DATA }.map { it.softwareVersion }
        val response = SoftwareIdentifierResponse(*appBlockVersions.toTypedArray())
        ack(response.asByteArray)
    }

    request("22 F1 83", name = "BootSoftwareFingerprintDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 84", name = "ApplicationSoftwareFingerprintDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 85", name = "ApplicationDataFingerprintDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 86", name = "ActiveDiagnosticSessionDataIdentifier_Read") {
        val ecuState = ecu.ecuState()
        ack(byteArrayOf(ecuState.sessionState.value))
    }

    request("22 F1 87", name = "VehicleManufacturerSparePartNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 88", name = "VehicleManufacturerECUSoftwareNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 89", name = "VehicleManufacturerECUSoftwareVersionNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8A", name = "SystemSupplierIdentifierDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8B", name = "ECUManufacturingDateDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8C", name = "ECUSerialNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8D", name = "SupportedFunctionalUnitsDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8E", name = "VehicleManufacturerKitAssemblyPartNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 8F", name = "RegulationXSoftwareIdentificationNumbers_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 90", name = "VINDataIdentifier_Read") {
        val ecuState = ecu.ecuState()
        ack(ecuState.vin.encodeToByteArray())
    }

    request("22 F1 91", name = "VehicleManufacturerECUHardwareNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 92", name = "SystemSupplierECUHardwareNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 93", name = "SystemSupplierECUHardwareVersionNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 94", name = "SystemSupplierECUSoftwareNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 95", name = "SystemSupplierECUSoftwareVersionNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 96", name = "ExhaustRegulationOrTypeApprovalNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 97", name = "SystemNameOrEngineTypeDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 98", name = "RepairShopCodeOrTesterSerialNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 99", name = "ProgrammingDateDataIdentifier_Read") {
        val date = Clock.System.now().toJavaInstant().atZone(ZoneOffset.UTC)
        // get last 2 digits of year - signed byte will cause issues in 2080... we can live with that
        val year = (date.year % (date.year / 1000)).toByte()
        val month = date.month.value.toByte()
        val day = date.dayOfMonth.toByte()
        ack(YearMonthDayBCD(year, month, day).asByteArray)
    }

    request("22 F1 9A", name = "CalibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 9B", name = "CalibrationDateDataIdentifier_Read") {
        val date = Clock.System.now().toJavaInstant().atZone(ZoneOffset.UTC)
        val sdf = SimpleDateFormat("yyyy-MM-dd")
        ack(sdf.format(date).encodeToByteArray())
    }

    request("22 F1 9C", name = "CalibrationEquipmentSoftwareNumberDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 9D", name = "ECUInstallationDataDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 9E", name = "ODXFileDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 F1 9F", name = "EntityDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("22 FF 00", name = "UDSVersionDataIdentifier_Read") {
        nrc(NrcError.RequestOutOfRange)
    }

    request("3E 00", name = "TesterPresent", loglevel = LogLevel.TRACE) {
        ack()
    }

    request("3E 80", name = "TesterPresent_SuppressResponse", loglevel = LogLevel.TRACE) {
    }
}
