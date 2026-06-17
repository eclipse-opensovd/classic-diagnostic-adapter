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

import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.NotFoundException
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import org.slf4j.MDC

/**
 * Ktor routes exposing the CAN network's status and a small admin surface
 * (frame injection). These are read by integration tests to verify the hub
 * is up before launching CDA.
 */
fun Route.addCanRoutes() {
    get("/can/status") {
        MDC.clear()
        val networks =
            CanNetworks.all().map { net ->
                CanNetworkStatusDto(
                    listenAddress = net.listenAddress,
                    port = net.hub.boundPort,
                    started = net.isStarted(),
                    peerCount = net.hub.peerCount(),
                    ecus =
                        net.connections().map { conn ->
                            CanEcuStatusDto(
                                name = conn.name,
                                rxId = "0x%X".format(conn.rxId),
                                txId = "0x%X".format(conn.txId),
                                lastUdsRequestAt = conn.lastUdsRequestAt,
                                lastUdsResponseAt = conn.lastUdsResponseAt,
                            )
                        },
                )
            }
        call.respond(CanStatusResponseDto(networks = networks))
    }

    post("/can/inject") {
        MDC.clear()
        val dto = call.receive<InjectFrameDto>()
        val data =
            dto.dataHex
                .chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        require(data.size <= 8) { "data must be at most 8 bytes" }
        val net = CanNetworks.all().firstOrNull() ?: throw NotFoundException("No CAN networks")
        val frame = CanFrame.build(dto.canId, data)
        net.hub.broadcast(frame)
        call.respond(HttpStatusCode.Accepted, InjectAckDto(message = "Frame broadcast"))
    }
}

@Serializable
data class InjectFrameDto(
    val canId: Int,
    val dataHex: String,
)

@Serializable
data class InjectAckDto(
    val message: String,
)

@Serializable
data class CanEcuStatusDto(
    val name: String,
    val rxId: String,
    val txId: String,
    val lastUdsRequestAt: Long,
    val lastUdsResponseAt: Long,
)

@Serializable
data class CanNetworkStatusDto(
    val listenAddress: String,
    val port: Int,
    val started: Boolean,
    val peerCount: Int,
    val ecus: List<CanEcuStatusDto>,
)

@Serializable
data class CanStatusResponseDto(
    val networks: List<CanNetworkStatusDto>,
)
