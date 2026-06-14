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
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import library.OutputChannel
import library.UdsMessage
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Strip the DoIP `DiagMessage` framing from a `DoipTcpDiagMessage.asByteArray`
 * payload, returning only the inner UDS bytes.
 *
 * The DoIP header is big-endian, per ISO 13400-2 and the doip-sim-ecu-dsl 0.22
 * implementation (`library/Utils.kt`'s `doipMessage` writes a default-order,
 * i.e. big-endian, `ByteBuffer`). `DoipTcpDiagMessage` layout:
 *  - bytes 0..1   version (0x02, 0xFD)
 *  - bytes 2..3   payload type (BE u16; 0x8001 = DiagMessage)
 *  - bytes 4..7   payload length (BE u32; covers source + target + UDS)
 *  - bytes 8..9   source address
 *  - bytes 10..11 target address
 *  - bytes 12..   UDS payload
 */
internal fun extractUdsFromDoipDiagMessage(doipBytes: ByteArray): ByteArray {
    if (doipBytes.size < 12) {
        // Not a DiagMessage (e.g. zero-length buffer); pass through.
        return doipBytes
    }
    val bb = ByteBuffer.wrap(doipBytes).order(ByteOrder.BIG_ENDIAN)
    bb.position(2)
    val payloadType = bb.short.toInt() and 0xFFFF
    if (payloadType != 0x8001) {
        // Not a DiagMessage (e.g. PosAck, NegAck); pass through.
        return doipBytes
    }
    bb.position(4)
    val payloadLength = bb.int
    val udsOffset = 12
    val udsLength = payloadLength - 4 // subtract 2+2 for source/target addresses
    if (udsLength <= 0 || udsOffset + udsLength > doipBytes.size) {
        return doipBytes
    }
    return doipBytes.copyOfRange(udsOffset, udsOffset + udsLength)
}

/**
 * Binds an [IsotpMachine] to a [SimEcu] so that incoming CAN frames demuxed
 * by arbitration ID are translated into UDS requests, dispatched through the
 * existing doip-sim-ecu-dsl handler chain, and the resulting response is
 * transmitted back on the bus.
 *
 * Each [CanEcuConnection] represents a single logical ECU. Multiple ECUs can
 * be registered on the same [CanFrameHub], each with its own `(rxId, txId)`
 * pair.
 */
class CanEcuConnection(
    val name: String,
    val ecu: SimEcu,
    val rxId: Int,
    val txId: Int,
    private val hub: CanFrameHub,
    private val scope: CoroutineScope,
) {
    private val log = LoggerFactory.getLogger("CanEcuConnection($name)")

    val machine: IsotpMachine =
        IsotpMachine(
            rxId = rxId,
            txId = txId,
        )

    // Responses are funnelled through one unbounded channel drained by a single
    // per-connection consumer (started in init), so the ISO-TP transmit path is
    // serialized even though responses can be produced from different worker
    // threads. This avoids racing on the transmit state from concurrent requests.
    private val pendingResponses: Channel<ByteArray> = Channel(Channel.UNLIMITED)

    @Volatile
    var lastUdsRequestAt: Long = 0
        private set

    @Volatile
    var lastUdsResponseAt: Long = 0
        private set

    init {
        machine.onUdsRequest = { udsBytes ->
            handleUdsRequest(udsBytes)
        }
        scope.launch(Dispatchers.Default) {
            try {
                for (uds in pendingResponses) {
                    transmitUdsResponse(uds)
                }
            } catch (e: Exception) {
                log.error("UDS transmit loop terminated", e)
            }
        }
    }

    /**
     * Feed a single CAN frame addressed to this ECU. The frame's arbitration
     * ID must equal [rxId]. Returns a list of CAN frames the connection wants
     * to transmit in immediate response (typically a Flow Control frame).
     */
    suspend fun onCanFrame(frame: CanFrame): List<CanFrame> {
        val responseFrames = machine.onCanFrame(frame)
        for (f in responseFrames) {
            hub.broadcast(f)
        }
        return responseFrames
    }

    private fun handleUdsRequest(udsBytes: ByteArray) {
        lastUdsRequestAt = System.currentTimeMillis()
        log.debug(
            "UDS request: {}",
            udsBytes.joinToString(" ") { String.format("%02X", it.toInt() and 0xFF) },
        )

        val outputChannel =
            object : OutputChannel {
                override suspend fun writeFully(data: ByteArray) {
                    val uds = extractUdsFromDoipDiagMessage(data)
                    lastUdsResponseAt = System.currentTimeMillis()
                    // UNLIMITED channel: trySend never fails while it is open.
                    pendingResponses.trySend(uds)
                }

                override suspend fun flush() = Unit
            }

        val udsMessage =
            UdsMessage(
                sourceAddress = 0,
                targetAddress = 0,
                targetAddressType = UdsMessage.PHYSICAL,
                targetAddressPhysical = 0,
                message = udsBytes,
                output = outputChannel,
            )

        // Fire-and-forget on a worker dispatcher; the DSL handler is blocking.
        scope.launch(Dispatchers.Default) {
            try {
                ecu.onIncomingUdsMessage(udsMessage)
            } catch (e: Exception) {
                log.error("ECU handler threw", e)
            }
        }
    }

    private suspend fun transmitUdsResponse(udsBytes: ByteArray) {
        val frames = machine.sendUds(udsBytes)
        for (f in frames) {
            hub.broadcast(f)
        }
        // If the response is multi-frame, send CFs spaced by STmin.
        while (true) {
            val state = machine.currentTxState()
            if (state != TxState.SendingCf && state != TxState.WaitingForFc) break
            if (state == TxState.SendingCf) {
                delay(machine.requestedStmin().toLong())
                val cfs = machine.nextTxFrames()
                for (f in cfs) {
                    hub.broadcast(f)
                }
            } else {
                // Waiting for FC; poll briefly.
                delay(20)
            }
        }
        log.debug(
            "UDS response transmitted: {}",
            udsBytes.joinToString(" ") { String.format("%02X", it.toInt() and 0xFF) },
        )
    }
}
