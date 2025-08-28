package webserver

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.MDC
import webserver.token.addJwtAuthServerMockRoutes
import kotlin.system.exitProcess

fun startEmbeddedWebserver(port: Int) {
    embeddedServer(
        factory = CIO,
        port = port,
        module = Application::appModule
    ).start(
        wait = true
    )
}

@OptIn(ExperimentalSerializationApi::class)
fun Application.appModule() {
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            encodeDefaults = true
            ignoreUnknownKeys = true
            explicitNulls = false
        })
    }
    routing {
        get("/") {
            MDC.clear()
            val routes = this.call.application.pluginOrNull(RoutingRoot)?.getAllRoutes()
            val items = routes?.map {
                mapOf(
                    "path" to it.parent?.toString(),
                    "method" to (it.selector as? HttpMethodRouteSelector)?.method?.value
                )
            } ?: emptyList()
            call.respond(
                mapOf(
                    "items" to items
                )
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
