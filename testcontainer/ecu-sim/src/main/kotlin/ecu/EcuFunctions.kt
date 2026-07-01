/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

import DoipEntityData
import DoipEntityDataHandler
import NetworkingData
import RequestsData
import addDtcRequests
import can.CanNetworking
import can.CanNetworks
import library.can.CanTransport
import networkInstances

private fun generateDefaultEcuState() = EcuState()

fun NetworkingData.addDoipEntity(
    name: String,
    logicalAddress: Short,
    functionalAddress: Short,
    eid: ByteArray? = null,
    gid: ByteArray? = null,
    initialEcuState: EcuState? = null,
    block: DoipEntityDataHandler = {},
) {
    doipEntity(name) {
        val ecuState = initialEcuState ?: generateDefaultEcuState()

        this.logicalAddress = logicalAddress
        this.functionalAddress = functionalAddress
        this.vin = ecuState.vin
        eid?.let { this.eid = it }
        gid?.let { this.gid = it }
        setInitialState(ecuState)

        addAllFunctionality()

        block.invoke(this)
    }
}

fun DoipEntityData.addCanEcu(
    name: String,
    logicalAddress: Short,
    functionalAddress: Short = this.functionalAddress,
    initialEcuState: EcuState? = null,
) {
    ecu(name) {
        val ecuState = initialEcuState ?: EcuState()

        this.logicalAddress = logicalAddress
        this.functionalAddress = functionalAddress
        setInitialState(ecuState)

        addAllFunctionality()
    }
}

/**
 * Attach an existing [SimEcu] (defined in the `network { ... }` DoIP block) to a
 * [CanNetworking] so the *same* ECU instance is reachable over both DoIP and
 * CAN. Sharing one instance is what makes the REST control plane work across
 * transports: an interceptor or state change applied via `findByEcuName` (which
 * resolves the DoIP-side instance) is observed by CAN traffic too, because there
 * is only one [SimEcu] behind the name.
 *
 * The ECU must already exist; define it with [addDoipEntity] / [addCanEcu] in
 * the `network { ... }` block before calling this.
 */
fun CanNetworking.addSimCanEcu(
    name: String,
    rxId: Int,
    txId: Int,
) {
    val ecu =
        networkInstances().firstNotNullOfOrNull { it.findEcuByName(name, true) }
            ?: error(
                "No ECU named '$name' found in the DoIP network; define it in the " +
                    "network { ... } block before attaching it to a CAN network",
            )
    addEcu(
        name = name,
        ecu = ecu,
        rxId = rxId,
        txId = txId,
    )
}

fun RequestsData.addAllFunctionality() {
    addSessionRequests()
    addResetRequests()
    addRoutineRequests()
    addSecurityAccessRequests()
    addCommunicationControlRequests()
    addDtcSettingRequests()
    addAuthenticationRequests()
    addDiagnosticRequests()
    addFlashRequests()
    addDtcRequests()
}

/**
 * Top-level builder for a CAN network. Mirrors the DSL's `network { ... }`
 * but operates on a [CanNetworking] instead of [NetworkingData].
 *
 * [transportFactory] creates the raw-frame [CanTransport] the network's ISO-TP
 * endpoints run on (e.g. a `SocketcandTransport`); it is invoked once, on
 * [CanNetworking.start]. Multiple CAN networks are supported (one process-global
 * registry per `CanNetworks`); the integration tests use a single network.
 */
fun canNetwork(
    transportFactory: () -> CanTransport,
    block: CanNetworking.() -> Unit,
): CanNetworking {
    val net = CanNetworking(transportFactory)
    net.block()
    CanNetworks.add(net)
    net.start()
    return net
}
