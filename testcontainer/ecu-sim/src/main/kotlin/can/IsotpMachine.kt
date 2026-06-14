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

import org.slf4j.LoggerFactory
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Minimal ISO 15765-2 (ISO-TP) transport layer for use over the [CanFrameHub].
 *
 * Each [IsotpMachine] represents one ECU's transport endpoint, identified by a
 * pair of CAN arbitration IDs: the RX ID on which the tester sends, and the
 * TX ID on which the ECU replies.
 *
 * The machine supports:
 *  - Single Frame (SF) up to 7 bytes of payload.
 *  - First Frame / Consecutive Frame / Flow Control with up to 4095 bytes of
 *    payload (the maximum for classic CAN, no CAN-FD extension).
 *  - 11-bit standard arbitration IDs only.
 *  - STmin enforcement between outgoing consecutive frames.
 *  - Block Size flow control: 0 = no limit, otherwise the number of CFs
 *    between Flow Control frames.
 *  - Optional frame padding with 0xCC (CDA's `IsotpChannelOptions::FRAME_PADDING`).
 *
 * Not supported:
 *  - 29-bit extended IDs.
 *  - CAN-FD (no separation between FF/CF padding rules and CAN-FD).
 *  - Mixed addressing (normal/fixed, etc.).
 *
 * Thread safety: each machine is single-threaded; the caller is expected to
 * funnel all frames through [onCanFrame] and not call [sendUds] from another
 * thread concurrently with itself. The transport is request/response, so this
 * matches reality.
 */
class IsotpMachine(
    val rxId: Int,
    val txId: Int,
    private val padByte: Byte = 0xCC.toByte(),
    private val stminMillis: Int = 10,
    private val blockSize: Int = 0,
    private val padEnabled: Boolean = true,
    private val maxPayloadBytes: Int = 4095,
) {
    private val log = LoggerFactory.getLogger("IsotpMachine(rx=$rxId,tx=$txId)")
    private val lock = ReentrantLock()

    private var rxState: RxState = RxState.Idle
    private var txState: TxState = TxState.Idle

    // Receiver state
    private var rxBuffer: ByteArray = ByteArray(0)
    private var rxExpectedLength: Int = 0
    private var rxNextSn: Int = 0
    private var rxBufferOffset: Int = 0

    // Sender state
    private var txBuffer: ByteArray = ByteArray(0)
    private var txBytesSent: Int = 0
    private var txNextSn: Int = 0
    private var txFramesThisBlock: Int = 0

    /** A complete UDS request was received. */
    var onUdsRequest: ((ByteArray) -> Unit)? = null

    /**
     * Feed a single CAN frame from the bus (demuxed by the caller to [rxId]).
     * Returns a list of CAN frames that should be transmitted in response
     * (typically a Flow Control frame and/or completion).
     */
    fun onCanFrame(frame: CanFrame): List<CanFrame> =
        lock.withLock {
            require(frame.canId == rxId) { "Frame canId ${frame.canId} != rxId $rxId" }
            require(frame.dlc in 1..8) { "Bad DLC ${frame.dlc}" }
            val first = frame.data[0].toInt() and 0xFF
            val pciType = (first ushr 4) and 0x0F
            when (pciType) {
                PCI_SF -> handleSingleFrame(frame)
                PCI_FF -> handleFirstFrame(frame)
                PCI_CF -> handleConsecutiveFrame(frame)
                PCI_FC -> handleFlowControl(frame)
                else -> {
                    log.warn("Unknown PCI type 0x{} in frame", pciType.toString(16))
                    emptyList()
                }
            }
        }

    /**
     * Send a UDS payload on the bus. Returns a list of CAN frames to transmit
     * (the caller is expected to interleave them with delays for STmin). The
     * first call returns the first frame; subsequent calls of [nextTxFrames]
     * emit consecutive frames.
     */
    fun sendUds(payload: ByteArray): List<CanFrame> =
        lock.withLock {
            require(txState == TxState.Idle) { "Transmitter is not idle (state=$txState)" }
            require(payload.isNotEmpty()) { "Empty payload" }
            require(payload.size <= maxPayloadBytes) { "Payload ${payload.size} > max $maxPayloadBytes" }
            txBuffer = payload
            txNextSn = 1
            txFramesThisBlock = 0

            if (payload.size <= 7) {
                // Single Frame
                txState = TxState.Idle
                listOf(buildSingleFrame(payload))
            } else {
                // First Frame. The FF carries the first 6 payload bytes, so the
                // transmit cursor must start there; otherwise the first
                // Consecutive Frame re-sends bytes 0..6 and the reconstructed
                // payload is corrupted (and truncated to the declared length).
                txState = TxState.WaitingForFc
                val firstFrame = buildFirstFrame(payload)
                txBytesSent = minOf(6, payload.size)
                listOf(firstFrame)
            }
        }

    /**
     * Continue sending the in-progress multi-frame transmission. Call this after
     * waiting STmin milliseconds. Returns the next batch of CF frames (typically
     * one), or empty if the transmission is complete or waiting for FC.
     */
    fun nextTxFrames(): List<CanFrame> =
        lock.withLock {
            if (txState != TxState.SendingCf) return emptyList()
            val total = txBuffer.size
            val remaining = total - txBytesSent
            if (remaining <= 0) {
                txState = TxState.Idle
                return emptyList()
            }
            val chunkSize = minOf(remaining, 7)
            val frame = buildConsecutiveFrame(txBuffer, txBytesSent, chunkSize)
            txBytesSent += chunkSize
            txNextSn = (txNextSn + 1) and 0x0F
            txFramesThisBlock += 1
            if (txBytesSent >= total) {
                txState = TxState.Idle
            } else if (blockSize > 0 && txFramesThisBlock >= blockSize) {
                // Pause and wait for another FC. The next batch will resume after FC.
                txState = TxState.WaitingForFc
                txFramesThisBlock = 0
            }
            listOf(frame)
        }

    fun currentTxState(): TxState = lock.withLock { txState }

    fun currentRxState(): RxState = lock.withLock { rxState }

    /** STmin in milliseconds, used by the caller to space consecutive frames. */
    fun requestedStmin(): Int = stminMillis

    fun reset() {
        lock.withLock {
            rxState = RxState.Idle
            txState = TxState.Idle
            rxBuffer = ByteArray(0)
            rxBufferOffset = 0
            txBuffer = ByteArray(0)
            txBytesSent = 0
            txNextSn = 1
            rxNextSn = 1
        }
    }

    // -- Receiver internals --

    private fun handleSingleFrame(frame: CanFrame): List<CanFrame> {
        val first = frame.data[0].toInt() and 0xFF
        val len = first and 0x0F
        // A low nibble of 0 with DLC >= 2 is the ISO-TP "escaped length" form
        // (byte 0 = 0x00, byte 1 = length 1..4095, for SF payloads > 7 bytes on
        // CAN-FD), which we do not support. A low nibble of 0 with DLC == 1 is a
        // legal zero-payload Single Frame and must still be delivered.
        if (len == 0 && frame.dlc >= 2) {
            log.warn("SF with escaped length not supported")
            return emptyList()
        }
        if (len > frame.dlc - 1) {
            log.warn("SF length $len > available data ${frame.dlc - 1}")
            return emptyList()
        }
        rxState = RxState.Idle
        val uds = frame.data.copyOfRange(1, 1 + len)
        onUdsRequest?.invoke(uds)
        return emptyList()
    }

    private fun handleFirstFrame(frame: CanFrame): List<CanFrame> {
        val first = frame.data[0].toInt() and 0xFF
        val second = frame.data[1].toInt() and 0xFF
        val len = ((first and 0x0F) shl 8) or second
        if (len <= 7) {
            // Should have been sent as SF
            log.warn("FF with length $len <= 7 (should be SF); ignoring")
            return emptyList()
        }
        if (len > maxPayloadBytes) {
            log.warn("FF length $len > max $maxPayloadBytes; sending FC.Overflow")
            rxState = RxState.Idle
            return listOf(buildFlowControl(FcFlag.Overflow))
        }
        rxState = RxState.ReceivingCf
        rxBuffer = ByteArray(len)
        rxBufferOffset = 0
        rxExpectedLength = len
        rxNextSn = 1
        // First 6 bytes of payload from the FF
        val firstChunk = minOf(6, len)
        System.arraycopy(frame.data, 2, rxBuffer, 0, firstChunk)
        rxBufferOffset = firstChunk
        return listOf(buildFlowControl(FcFlag.ContinueToSend))
    }

    private fun handleConsecutiveFrame(frame: CanFrame): List<CanFrame> {
        if (rxState != RxState.ReceivingCf) {
            log.debug("CF received while not in ReceivingCf (state=$rxState); ignoring")
            return emptyList()
        }
        val first = frame.data[0].toInt() and 0xFF
        val sn = first and 0x0F
        if (sn != rxNextSn) {
            log.warn("CF sequence number mismatch: expected $rxNextSn, got $sn; resetting")
            rxState = RxState.Idle
            return emptyList()
        }
        val remaining = rxExpectedLength - rxBufferOffset
        val chunkSize = minOf(remaining, 7)
        System.arraycopy(frame.data, 1, rxBuffer, rxBufferOffset, chunkSize)
        rxBufferOffset += chunkSize
        rxNextSn = (rxNextSn + 1) and 0x0F
        if (rxBufferOffset >= rxExpectedLength) {
            rxState = RxState.Idle
            val uds = rxBuffer
            rxBuffer = ByteArray(0)
            onUdsRequest?.invoke(uds)
        }
        return emptyList()
    }

    private fun handleFlowControl(frame: CanFrame): List<CanFrame> {
        if (txState != TxState.WaitingForFc) {
            log.debug("FC received while not WaitingForFc (state=$txState); ignoring")
            return emptyList()
        }
        val first = frame.data[0].toInt() and 0xFF
        val flag = first and 0x0F
        when (flag) {
            FcFlag.ContinueToSend.value -> {
                txState = TxState.SendingCf
                txFramesThisBlock = 0
            }
            FcFlag.Wait.value -> {
                // Stay in WaitingForFc; tester will send another FC. We don't
                // need to do anything; the next FF/CF send will be retried
                // when the tester resumes.
            }
            FcFlag.Overflow.value -> {
                log.warn("Tester reported FC.Overflow; aborting transmission")
                txState = TxState.Idle
            }
            else -> {
                log.warn("Unknown FC flag $flag; aborting transmission")
                txState = TxState.Idle
            }
        }
        return emptyList()
    }

    // -- Frame builders --
    //
    // We always emit 8 data bytes on the wire. The `dlc` field on the frame
    // tells the receiver how many bytes are meaningful; bytes [dlc..8] are
    // padding and ignored. When `padEnabled` is set, the padding bytes are
    // 0xCC (matching CDA's `IsotpChannelOptions::FRAME_PADDING`).

    private fun buildSingleFrame(payload: ByteArray): CanFrame {
        val len = payload.size
        val data = ByteArray(8)
        data[0] = (PCI_SF shl 4 or (len and 0x0F)).toByte()
        System.arraycopy(payload, 0, data, 1, len)
        if (padEnabled) {
            for (i in (1 + len) until 8) data[i] = padByte
        }
        return CanFrame(txId, dlc = 1 + len, data = data)
    }

    private fun buildFirstFrame(payload: ByteArray): CanFrame {
        val len = payload.size
        val data = ByteArray(8)
        data[0] = (PCI_FF shl 4 or ((len ushr 8) and 0x0F)).toByte()
        data[1] = (len and 0xFF).toByte()
        val firstChunk = minOf(6, len)
        System.arraycopy(payload, 0, data, 2, firstChunk)
        if (padEnabled) {
            for (i in (2 + firstChunk) until 8) data[i] = padByte
        }
        return CanFrame(txId, dlc = 2 + firstChunk, data = data)
    }

    private fun buildConsecutiveFrame(
        payload: ByteArray,
        offset: Int,
        len: Int,
    ): CanFrame {
        val data = ByteArray(8)
        data[0] = (PCI_CF shl 4 or (txNextSn and 0x0F)).toByte()
        System.arraycopy(payload, offset, data, 1, len)
        if (padEnabled) {
            for (i in (1 + len) until 8) data[i] = padByte
        }
        return CanFrame(txId, dlc = 1 + len, data = data)
    }

    private fun buildFlowControl(flag: FcFlag): CanFrame {
        val data = ByteArray(8)
        data[0] = (PCI_FC shl 4 or (flag.value and 0x0F)).toByte()
        data[1] = blockSize.toByte()
        data[2] = stminMillis.coerceIn(0, 127).toByte()
        if (padEnabled) {
            for (i in 3 until 8) data[i] = padByte
        }
        return CanFrame(txId, dlc = 3, data = data)
    }

    companion object {
        const val PCI_SF: Int = 0x0
        const val PCI_FF: Int = 0x1
        const val PCI_CF: Int = 0x2
        const val PCI_FC: Int = 0x3

        enum class FcFlag(
            val value: Int,
        ) {
            ContinueToSend(0x0),
            Wait(0x1),
            Overflow(0x2),
        }
    }
}

enum class RxState { Idle, ReceivingCf }

enum class TxState { Idle, WaitingForFc, SendingCf }
