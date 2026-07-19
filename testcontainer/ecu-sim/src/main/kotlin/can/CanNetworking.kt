/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

package can

import SimEcu
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import library.UdsMessage
import library.can.CanTransport
import library.can.CanUdsMessage
import library.can.isotp.IsoTpEndpoint
import library.can.isotp.IsoTpOptions
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Serves existing [SimEcu] instances over UDS/ISO-TP on a single CAN bus,
 * using the doip-sim-ecu-dsl CAN library (PR#164): one [IsoTpEndpoint] per ECU
 * on a shared [CanTransport] (here socketcand).
 *
 * The ECUs are the *same* instances as the DoIP entities defined in the
 * `network { ... }` block - looked up by name via [addSimCanEcu] - so anything
 * the REST control plane changes (state, interceptors, `/reset`) is observed on
 * both the DoIP and the CAN path, because there is only one [SimEcu] behind a
 * given name. ISO-TP segmentation/reassembly and the raw-frame transport are
 * provided entirely by the library; this class only wires endpoints to ECUs and
 * dispatches reassembled requests through `SimEcu.onIncomingUdsMessage`.
 */
class CanNetworking(
    private val transportFactory: () -> CanTransport,
) {
    private val log = LoggerFactory.getLogger(CanNetworking::class.java)
    private val started = AtomicBoolean(false)
    private val ecusByName = ConcurrentHashMap<String, CanEcu>()
    private val endpoints = mutableListOf<IsoTpEndpoint>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var transport: CanTransport? = null

    private data class CanEcu(
        val name: String,
        val ecu: SimEcu,
        val rxId: Int,
        val txId: Int,
    )

    fun addEcu(
        name: String,
        ecu: SimEcu,
        rxId: Int,
        txId: Int,
    ) {
        require(!started.get()) { "Cannot add ECUs after start()" }
        require(ecusByName[name] == null) { "ECU '$name' already registered on this network" }
        ecusByName[name] = CanEcu(name, ecu, rxId, txId)
    }

    fun start() {
        if (!started.compareAndSet(false, true)) return
        val transport = transportFactory()
        this.transport = transport

        // Attach the endpoints before connecting the transport, so no frame
        // received right after connecting can be lost.
        ecusByName.values.forEach { canEcu ->
            lateinit var endpoint: IsoTpEndpoint
            endpoint =
                IsoTpEndpoint(
                    transport = transport,
                    physicalRxId = canEcu.rxId,
                    functionalRxId = null,
                    txId = canEcu.txId,
                    options = IsoTpOptions(),
                ) { payload, functional ->
                    dispatchRequest(canEcu, endpoint, payload, functional)
                }
            endpoint.start(scope)
            endpoints.add(endpoint)
            log.info(
                "ECU '{}' listening on 0x{} (responding on 0x{})",
                canEcu.name,
                canEcu.rxId.toString(16),
                canEcu.txId.toString(16),
            )
        }

        // Connect the transport in the background rather than blocking the
        // caller: the simulator's HTTP control server must come up regardless of
        // whether socketcand is reachable yet (in docker the daemon may still be
        // starting). `SocketcandTransport.start` only auto-reconnects *after* a
        // successful initial connect, so retry that initial connect here until
        // the daemon is up; the endpoints are already subscribed to the frame
        // flow, so nothing is lost.
        scope.launch {
            var attempt = 0
            while (isActive) {
                try {
                    transport.start(scope)
                    log.info("CAN network connected via {}", transport.name)
                    break
                } catch (e: Exception) {
                    attempt++
                    log.warn(
                        "CAN transport '{}' initial connect failed (attempt {}), retrying: {}",
                        transport.name,
                        attempt,
                        e.message,
                    )
                    delay(minOf(5000L, 500L * attempt))
                }
            }
        }
    }

    /**
     * The [IsoTpEndpoint] handler runs on the endpoint's frame-processing
     * coroutine and must not block, so the (blocking) DSL handler chain is run
     * on a separate coroutine. It uses the scope's [Dispatchers.IO] (not
     * [Dispatchers.Default]): `CanUdsMessage.respond` performs the ISO-TP
     * transmission via a blocking `runBlocking`, and a multi-frame response
     * blocks its thread until flow control arrives - on the small Default pool
     * concurrent operations would starve it (and the simulator's HTTP server).
     * The response is written back through [IsoTpEndpoint.outputChannel] by
     * [CanUdsMessage.respond], which emits raw UDS (no DoIP framing).
     */
    private fun dispatchRequest(
        canEcu: CanEcu,
        endpoint: IsoTpEndpoint,
        payload: ByteArray,
        functional: Boolean,
    ) {
        val request =
            CanUdsMessage(
                targetAddressType = if (functional) UdsMessage.FUNCTIONAL else UdsMessage.PHYSICAL,
                message = payload,
                output = endpoint.outputChannel,
                requestCanId = canEcu.rxId,
                responseCanId = canEcu.txId,
            )
        scope.launch {
            try {
                canEcu.ecu.onIncomingUdsMessage(request)
            } catch (e: Exception) {
                log.error("ECU '${canEcu.name}' handler threw", e)
            }
        }
    }

    /**
     * The CAN ECUs share their [SimEcu] with the DoIP entities, which are reset
     * via the DoIP `networkInstances()`; the ISO-TP endpoints keep no
     * cross-message state that needs clearing here.
     */
    fun reset() = Unit

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        endpoints.forEach { it.stop() }
        endpoints.clear()
        transport?.close()
        transport = null
        scope.cancel()
    }

    fun findEcuByName(
        name: String,
        ignoreCase: Boolean = true,
    ): SimEcu? = ecusByName.values.firstOrNull { name.equals(it.name, ignoreCase) }?.ecu

    fun isStarted(): Boolean = started.get()
}

/**
 * Global registry of all [CanNetworking] instances, mirroring the
 * `doip-sim-ecu-dsl` `networkInstances()` global.
 */
object CanNetworks {
    private val networks: MutableList<CanNetworking> = mutableListOf()

    fun add(network: CanNetworking) = synchronized(networks) { networks.add(network) }

    fun all(): List<CanNetworking> = synchronized(networks) { networks.toList() }

    fun findEcuByName(
        name: String,
        ignoreCase: Boolean = true,
    ): SimEcu? = all().firstNotNullOfOrNull { it.findEcuByName(name, ignoreCase) }
}
