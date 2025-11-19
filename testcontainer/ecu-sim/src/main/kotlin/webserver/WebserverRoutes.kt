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

package webserver

import SimEcu
import ecu.FaultMemory
import ecu.dataTransfersDownload
import ecu.dtcFaults
import ecu.ecuState
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import library.toHexString
import networkInstances
import org.slf4j.MDC
import utils.dtcToId
import utils.toUuid
import kotlin.uuid.ExperimentalUuidApi

fun findByEcuName(ecuName: String): SimEcu? {
    networkInstances().forEach { network ->
        val ecu = network.findEcuByName(ecuName, true)
        if (ecu != null) {
            return ecu
        }
    }
    throw NotFoundException()
}

fun findByEcuName(call: ApplicationCall): SimEcu? {
    val ecuName = call.parameters["ecu"].orEmpty()
    return findByEcuName(ecuName)
}

fun Route.addStateRoutes() {
    post("/reset") {
        MDC.clear()
        networkInstances().forEach { network ->
            network.reset()
        }
        call.respond(HttpStatusCode.NoContent)
    }

    get("/{ecu}/state") {
        MDC.clear()
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        call.respond(HttpStatusCode.OK, ecu.ecuState().toDto())
    }

    put("/{ecu}/state") {
        MDC.clear()
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        val updateDto = call.receive<EcuStateDto>()
        val ecuState = ecu.ecuState()
        ecuState.updateWith(updateDto)
        call.respond(HttpStatusCode.OK, ecu.ecuState().toDto())
    }

    put("/{ecu}/state/blocks/{blockId}") {
        MDC.clear()
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        val blockId = call.parameters["blockId"]?.toUuid() ?: throw NotFoundException()
        val updateDto = call.receive<DataBlockDto>()
        val ecuState = ecu.ecuState()
        val block = ecuState.blocks.firstOrNull { block -> block.id == blockId } ?: throw NotFoundException()
        block.updateWith(updateDto)
        call.respond(HttpStatusCode.OK, ecu.ecuState().toDto())
    }
}

fun Route.addFlashTransferRoutes() {
    get("/{ecu}/datatransfers/downloads") {
        MDC.clear()
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        val transfers = ecu.dataTransfersDownload()
        call.respond(HttpStatusCode.OK, mapOf("transfers" to transfers.map { it.toDto() }))
    }
}

fun SimEcu.recordedData() =
    this.storedProperty { mutableListOf<String>() }

fun Route.addRecordingRoutes() {
    post("/{ecu}/record") {
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        ecu.addOrReplaceEcuInterceptor("RECORDER", alsoCallWhenEcuIsBusy = true) {
            val recordedData by ecu.recordedData()
            recordedData.add(this.message.toHexString(separator = ""))
            false
        }
        call.respond(HttpStatusCode.NoContent)
    }

    delete("/{ecu}/record") {
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        ecu.removeInterceptor("RECORDER")
        val recordedData by ecu.recordedData()
        call.respond(HttpStatusCode.OK, recordedData)
    }

    get("/{ecu}/record") {
        val ecu = findByEcuName(call.parameters["ecu"]!!) ?: throw NotFoundException()
        val recordedData by ecu.recordedData()
        call.respond(HttpStatusCode.OK, recordedData)
    }
}

fun Route.addDtcFaultsRoutes() {
    get("/{ecu}/dtc") {
        call.respond(mapOf("items" to FaultMemory.entries.map { mapOf("name" to it.name) }))
    }

    get("/{ecu}/dtc/{faultMemory}") {
        val ecu = findByEcuName(call) ?: return@get
        val dtcFaults = ecu.dtcFaultsByApplicationCall(call) ?: return@get
        val response = dtcFaults.values.map { it.toDto() }
        ecu.logger.info("Retrieving DTCs from ${call.parameters["faultMemory"].orEmpty()}")
        call.respond(response)
    }

    put("/{ecu}/dtc/{faultMemory}") {
        val ecu = findByEcuName(call) ?: return@put
        val dtcFaults = ecu.dtcFaultsByApplicationCall(call) ?: return@put
        val dto = call.receive<DtcFaultDto>()
        val dtcFault = dtcFaultFromDto(dto)
        dtcFaults[dtcFault.id] = dtcFault
        ecu.logger.info("Adding DTC ${dtcFault.id.toString(16)} with status ${dtcFault.status.asByte.toString(16)} to ${call.parameters["faultMemory"].orEmpty()}")
        call.respond(HttpStatusCode.Created, mapOf("message" to "DTC was created"))
    }

    delete("/{ecu}/dtc/{faultMemory}/{faultId}") {
        val ecu = findByEcuName(call) ?: return@delete
        val faultId = call.parameters["faultId"]!!.dtcToId()
        val dtcFaults = ecu.dtcFaultsByApplicationCall(call) ?: return@delete
        ecu.logger.info("Removing DTC ${faultId}} from ${call.parameters["faultMemory"].orEmpty()}")
        dtcFaults.remove(faultId)
        call.respond(HttpStatusCode.OK, mapOf("message" to "DTCs were deleted"))
    }

    delete("/{ecu}/dtc/{faultMemory}") {
        val ecu = findByEcuName(call) ?: return@delete
        val dtcFaults = ecu.dtcFaultsByApplicationCall(call) ?: return@delete
        dtcFaults.clear()
        ecu.logger.info("Removing all DTCs from ${call.parameters["faultMemory"].orEmpty()}")
        call.respond(HttpStatusCode.OK, mapOf("message" to "DTCs were deleted"))
    }
}

private suspend fun SimEcu.dtcFaultsByApplicationCall(call: ApplicationCall) =
    try {
        this.dtcFaults(FaultMemory.byName(call.parameters["faultMemory"].orEmpty()))
    } catch (_: Exception) {
        call.respond(
            HttpStatusCode.BadRequest,
            mapOf("message" to "Fault memory ${call.parameters["faultMemory"].orEmpty()} doesn't exist")
        )
        null
    }
