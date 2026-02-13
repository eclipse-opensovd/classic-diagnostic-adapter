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

package webserver

import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.pluginOrNull
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.HttpMethodRouteSelector
import io.ktor.server.routing.RoutingRoot
import io.ktor.server.routing.get
import io.ktor.server.routing.getAllRoutes
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.MDC
import webserver.token.addJwtAuthServerMockRoutes
import kotlin.system.exitProcess

fun startEmbeddedWebserver(port: Int) {
    embeddedServer(
        factory = CIO,
        port = port,
        module = Application::appModule,
    ).start(
        wait = true,
    )
}

@OptIn(ExperimentalSerializationApi::class)
fun Application.appModule() {
    install(ContentNegotiation) {
        json(
            Json {
                prettyPrint = true
                isLenient = true
                encodeDefaults = true
                ignoreUnknownKeys = true
                explicitNulls = false
            },
        )
    }
    routing {
        get("/") {
            MDC.clear()
            val routes =
                this.call.application
                    .pluginOrNull(RoutingRoot)
                    ?.getAllRoutes()
            val items =
                routes?.map {
                    mapOf(
                        "path" to it.parent?.toString(),
                        "method" to (it.selector as? HttpMethodRouteSelector)?.method?.value,
                    )
                } ?: emptyList()
            call.respond(
                mapOf(
                    "items" to items,
                ),
            )
        }

        addStateRoutes()
        addFlashTransferRoutes()
        addRecordingRoutes()
        addDtcFaultsRoutes()
        addJwtAuthServerMockRoutes()

        post("/shutdown") {
            call.respond(HttpStatusCode.OK)
            exitProcess(0)
        }
    }
}
