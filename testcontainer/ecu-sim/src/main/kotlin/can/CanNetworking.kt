/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

package can

import SimEcu
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A CAN network, holding one or more [CanEcuConnection]s sharing a single
 * [CanFrameHub].
 *
 * This is the transport-agnostic counterpart to the DoIP `NetworkingData` /
 * `SimDoipNetworking` pair. It does *not* use `doip-sim-ecu-dsl`'s
 * `NetworkingData` because the DSL is hard-wired to UDP/TCP. Instead, it
 * constructs `SimEcu` instances directly from `EcuData` and re-uses the
 * DSL's request matcher / handler chain via `SimEcu.onIncomingUdsMessage`.
 */
class CanNetworking(
    val listenAddress: String,
    val port: Int,
) {
    private val log = LoggerFactory.getLogger(CanNetworking::class.java)
    private val started = AtomicBoolean(false)
    private val ecusByName = ConcurrentHashMap<String, CanEcuConnection>()

    val hub: CanFrameHub = CanFrameHub(listenAddress, port)
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    var dispatcherJob: Job? = null
        private set

    fun addEcu(
        name: String,
        ecu: SimEcu,
        rxId: Int,
        txId: Int,
    ): CanEcuConnection {
        require(!started.get()) { "Cannot add ECUs after start()" }
        require(ecusByName[name] == null) { "ECU '$name' already registered on this network" }
        val connection =
            CanEcuConnection(
                name = name,
                ecu = ecu,
                rxId = rxId,
                txId = txId,
                hub = hub,
                scope = scope,
            )
        ecusByName[name] = connection
        return connection
    }

    fun start() {
        if (!started.compareAndSet(false, true)) return
        hub.start()
        log.info("CanNetworking dispatcher starting, ECUs: {}", ecusByName.keys)
        dispatcherJob =
            scope.launch {
                try {
                    while (isActive) {
                        val next = hub.receive() ?: break
                        val frame = next.frame
                        val conn =
                            ecusByName.values.firstOrNull { it.rxId == frame.canId }
                        if (conn == null) {
                            log.debug("No ECU for arbitration id 0x{:X}", frame.canId)
                            continue
                        }
                        try {
                            conn.onCanFrame(frame)
                        } catch (e: Exception) {
                            log.warn("Connection '{}' failed to process frame: {}", conn.name, e.message)
                        }
                    }
                } catch (e: Exception) {
                    if (isActive) log.error("CAN dispatcher failed", e)
                }
            }
    }

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        dispatcherJob?.cancel()
        hub.stop()
        scope.cancel()
    }

    fun findEcuByName(
        name: String,
        ignoreCase: Boolean = true,
    ): SimEcu? = ecusByName.values.firstOrNull { name.equals(it.name, ignoreCase) }?.ecu

    fun connections(): Collection<CanEcuConnection> = ecusByName.values.toList()

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
