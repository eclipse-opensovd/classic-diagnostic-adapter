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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * TCP frame hub for CAN bus simulation.
 *
 * One process-global instance per listen address. Accepts arbitrary TCP clients
 * (e.g. CDA's `tokio-socketcan-isotp` TCP backend) and broadcasts each received
 * frame to all *other* attached peers (no echo to sender), matching the
 * semantics of `tokio-socketcan-isotp`'s hub.
 *
 * Wire format: see [CanFrame].
 */
class CanFrameHub(
    private val listenAddress: String = "127.0.0.1",
    private val port: Int,
) {
    private val log = LoggerFactory.getLogger(CanFrameHub::class.java)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var serverSocket: ServerSocket? = null
    private val peers = ConcurrentHashMap<PeerId, Peer>()
    private val peerIdGen = AtomicInteger()
    private val _events = MutableSharedFlow<HubEvent>(extraBufferCapacity = 256)
    val events: SharedFlow<HubEvent> = _events.asSharedFlow()

    @Volatile
    var isRunning: Boolean = false
        private set

    /**
     * Start accepting TCP connections. Returns when the listener is bound.
     */
    fun start() {
        if (isRunning) return
        val ss = ServerSocket()
        ss.bind(InetSocketAddress(listenAddress, port))
        serverSocket = ss
        isRunning = true
        log.info("CAN frame hub listening on {}:{}", listenAddress, ss.localPort)

        scope.launch {
            try {
                while (isActive) {
                    val socket = ss.accept()
                    val peer = Peer(PeerId(peerIdGen.incrementAndGet()), socket)
                    peers[peer.id] = peer
                    _events.tryEmit(HubEvent.PeerConnected(peer.id, socket.remoteSocketAddress.toString()))
                    log.info("CAN hub peer connected: id={} from={}", peer.id, socket.remoteSocketAddress)
                    scope.launch { runPeer(peer) }
                }
            } catch (e: SocketException) {
                if (isRunning) log.error("CAN hub accept loop failed", e)
            } finally {
                isRunning = false
            }
        }
    }

    /**
     * Send [frame] to every connected peer. A peer whose outbox is full has the
     * frame dropped (and logged); the broadcast itself never fails. Peers are
     * removed only by [disconnectPeer] when their socket closes, not here.
     */
    suspend fun broadcast(frame: CanFrame) {
        val bytes = frame.encode()
        // Snapshot the peer list so a concurrent disconnectPeer cannot disturb
        // this iteration (ConcurrentHashMap iteration is weakly consistent).
        peers.values.toList().forEach { peer ->
            val ok = peer.outbox.trySend(bytes).isSuccess
            if (!ok) {
                log.warn("Outbox full for peer {}, dropping frame", peer.id)
            }
        }
        _events.tryEmit(HubEvent.FrameBroadcast(frame))
    }

    /**
     * Non-blocking poll: returns the next frame from any peer, or null if none
     * is currently available.
     */
    fun poll(): HubFrame? {
        for (peer in peers.values) {
            val frame = peer.inbox.tryReceive().getOrNull() ?: continue
            return HubFrame(peer.id, frame)
        }
        return null
    }

    /**
     * Block until a frame is received from any peer, or return null if the hub stops.
     */
    suspend fun receive(): HubFrame? {
        while (scope.isActive) {
            poll()?.let { return it }
            delay(2)
        }
        return null
    }

    fun stop() {
        if (!isRunning) return
        isRunning = false
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            log.debug("Error closing server socket: {}", e.message)
        }
        peers.values.toList().forEach { disconnectPeer(it.id) }
        scope.cancel()
    }

    val boundPort: Int
        get() = serverSocket?.localPort ?: port

    fun peerCount(): Int = peers.size

    private suspend fun runPeer(peer: Peer) {
        val sendThread =
            Thread({
                val out = DataOutputStream(peer.socket.getOutputStream())
                try {
                    runBlocking {
                        for (frameBytes in peer.outbox) {
                            out.write(frameBytes)
                            out.flush()
                        }
                    }
                } catch (_: Exception) {
                    // socket closed
                }
            }, "can-hub-send-${peer.id.value}").apply {
                isDaemon = true
                start()
            }

        try {
            val input = DataInputStream(peer.socket.getInputStream())
            while (scope.isActive && !peer.socket.isClosed) {
                val buf = ByteArray(CanFrame.WIRE_SIZE)
                try {
                    input.readFully(buf)
                } catch (e: EOFException) {
                    break
                } catch (e: IOException) {
                    if (isRunning) log.debug("Peer {} read error: {}", peer.id, e.message)
                    break
                }
                val frame = CanFrame.decode(buf)
                _events.tryEmit(HubEvent.FrameReceived(peer.id, frame))
                val ok = peer.inbox.trySend(frame).isSuccess
                if (!ok) {
                    log.warn("Inbox full for peer {}, dropping frame", peer.id)
                }
            }
        } catch (e: Exception) {
            if (isRunning) log.warn("Peer {} loop failed: {}", peer.id, e.message)
        } finally {
            // Closing the outbox in disconnectPeer is what ends the send loop's
            // `for (frameBytes in peer.outbox)`; Thread.interrupt() would not,
            // since runBlocking over a Channel does not observe interruption.
            disconnectPeer(peer.id)
        }
    }

    private fun disconnectPeer(id: PeerId) {
        val peer = peers.remove(id) ?: return
        try {
            peer.socket.close()
        } catch (_: Exception) {
            // ignore
        }
        peer.outbox.close()
        peer.inbox.close()
        _events.tryEmit(HubEvent.PeerDisconnected(id))
        log.info("CAN hub peer disconnected: id={}", id)
    }

    private class Peer(
        val id: PeerId,
        val socket: Socket,
    ) {
        val outbox: Channel<ByteArray> = Channel(capacity = 1024)
        val inbox: Channel<CanFrame> = Channel(capacity = 1024)
    }
}

@JvmInline
value class PeerId(
    val value: Int,
)

data class HubFrame(
    val fromPeer: PeerId,
    val frame: CanFrame,
)

sealed interface HubEvent {
    data class PeerConnected(
        val id: PeerId,
        val remote: String,
    ) : HubEvent

    data class PeerDisconnected(
        val id: PeerId,
    ) : HubEvent

    data class FrameReceived(
        val id: PeerId,
        val frame: CanFrame,
    ) : HubEvent

    data class FrameBroadcast(
        val frame: CanFrame,
    ) : HubEvent
}
