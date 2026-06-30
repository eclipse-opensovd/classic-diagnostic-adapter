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
import library.can.socketcand.SocketcandTransport
import webserver.startEmbeddedWebserver

fun main() {
    println("OpenSOVD CDA ECU-SIM")

    val functionalAddress = 0xffff.toShort()
    val doipPort = System.getenv("SIM_DOIP_PORT")?.toInt() ?: 13400
    val portRest = System.getenv("SIM_REST_PORT")?.toInt() ?: 8181
    val networkInterfaceEnv = System.getenv("SIM_NETWORK_INTERFACE") ?: "0.0.0.0"
    // CAN is enabled when a socketcand host is configured; the simulator then
    // reaches the shared CAN bus through a socketcand daemon over TCP.
    val socketcandHost = System.getenv("SIM_CAN_SOCKETCAND_HOST")?.takeIf { it.isNotBlank() }
    val socketcandPort = System.getenv("SIM_CAN_SOCKETCAND_PORT")?.toInt() ?: 29536
    val socketcandBus = System.getenv("SIM_CAN_SOCKETCAND_BUS") ?: "vcan0"

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

    if (socketcandHost != null) {
        println("CAN via socketcand at $socketcandHost:$socketcandPort bus $socketcandBus")
        canNetwork({
            SocketcandTransport(
                host = socketcandHost,
                port = socketcandPort,
                busName = socketcandBus,
                reconnect = true,
            )
        }) {
            // Each example ECU gets a distinct (rxId, txId) pair so the right
            // SimEcu instance answers on the bus. The integration test config
            // (`[[can.ecu_mappings]]` in runtime.rs) mirrors this assignment.
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
