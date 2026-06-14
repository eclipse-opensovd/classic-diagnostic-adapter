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

import ecu.addCanEcu
import ecu.addDoipEntity
import ecu.addSimCanEcu
import ecu.canNetwork
import webserver.startEmbeddedWebserver

fun main() {
    println("OpenSOVD CDA ECU-SIM")

    val functionalAddress = 0xffff.toShort()
    val doipPort = System.getenv("SIM_DOIP_PORT")?.toInt() ?: 13400
    val portRest = System.getenv("SIM_REST_PORT")?.toInt() ?: 8181
    val networkInterfaceEnv = System.getenv("SIM_NETWORK_INTERFACE") ?: "0.0.0.0"
    val simCanHub = System.getenv("SIM_CAN_HUB")
    val simCanHubAddress = System.getenv("SIM_CAN_HUB_ADDRESS") ?: "127.0.0.1"
    val simCanHubPort = System.getenv("SIM_CAN_HUB_PORT")?.toInt() ?: 19800

    network {
        networkInterface = networkInterfaceEnv
        networkMode = NetworkMode.AUTO
        localPort = doipPort

        println("DoIP Local Address: $networkInterface:$localPort")
        println("DoIP Broadcast Address: $broadcastAddress")
        println("Webserver Port: $portRest")

        addDoipEntity(
            name = "FLXC1000",
            logicalAddress = 0x1000,
            functionalAddress = functionalAddress,
        ) {
            addCanEcu(
                name = "TMC1001",
                logicalAddress = 0x1001,
            )
        }

        addDoipEntity(
            name = "FSNR2000",
            logicalAddress = 0x2000,
            functionalAddress = functionalAddress,
        ) {
        }

        addDoipEntity(
            name = "TMCC3000",
            logicalAddress = 0x3000,
            functionalAddress = functionalAddress,
        ) {
        }

        addDoipEntity(
            name = "HOVR4000",
            logicalAddress = 0x4000,
            functionalAddress = functionalAddress,
        ) {
        }

        addDoipEntity(
            name = "JGWT5000",
            logicalAddress = 0x5000,
            functionalAddress = functionalAddress,
        ) {
        }
    }
    start()

    if (!simCanHub.isNullOrBlank()) {
        val (hubAddress, hubPort) = parseHubEndpoint(simCanHub, simCanHubAddress, simCanHubPort)
        println("CAN frame hub listening on $hubAddress:$hubPort")
        canNetwork(hubAddress, hubPort) {
            // Each example ECU gets a distinct (rxId, txId) pair so the
            // dispatcher can route incoming frames to the right SimEcu
            // instance. The integration test config (`[[can.ecu_mappings]]`
            // in runtime.rs) mirrors this assignment.
            addSimCanEcu("FLXC1000", rxId = 0x700, txId = 0x708)
            addSimCanEcu("TMC1001", rxId = 0x710, txId = 0x718)
            addSimCanEcu("FSNR2000", rxId = 0x720, txId = 0x728)
            addSimCanEcu("TMCC3000", rxId = 0x730, txId = 0x738)
            addSimCanEcu("HOVR4000", rxId = 0x740, txId = 0x748)
            addSimCanEcu("JGWT5000", rxId = 0x750, txId = 0x758)
        }
    }

    startEmbeddedWebserver(port = portRest)
}

private fun parseHubEndpoint(
    envValue: String,
    defaultAddress: String,
    defaultPort: Int,
): Pair<String, Int> {
    if (envValue.contains(":")) {
        val parts = envValue.split(":", limit = 2)
        val port = parts[1].toIntOrNull() ?: defaultPort
        return parts[0] to port
    }
    val port = envValue.toIntOrNull() ?: defaultPort
    return defaultAddress to port
}
