import ecu.addCanEcu
import ecu.addDoipEntity
import webserver.startEmbeddedWebserver

fun main() {
    println("OpenSOVD CDA ECU-SIM")

    val functionalAddress = 0xef00.toShort()
    val doipPort = System.getenv("SIM_DOIP_PORT")?.toInt() ?: 13400
    val portRest = System.getenv("SIM_REST_PORT")?.toInt() ?: 8181
    val networkInterfaceEnv = System.getenv("SIM_NETWORK_INTERFACE") ?: "0.0.0.0"

    network {
        networkInterface = networkInterfaceEnv
        networkMode = NetworkMode.AUTO
        localPort = doipPort

        println("DoIP Local Address: $networkInterface:$localPort")
        println("DoIP Broadcast Address: $broadcastAddress")
        println("Webserver Port: $portRest")

        addDoipEntity(
            name = "GW1000",
            logicalAddress = 0x1000,
            functionalAddress = functionalAddress,
        ) {
            addCanEcu(
                name = "ECU1001",
                logicalAddress = 0x1001,
            )
            addCanEcu(
                name = "ECU1002",
                logicalAddress = 0x1002,
            )
        }

        addDoipEntity(
            name = "GW2000",
            logicalAddress = 0x2000,
            functionalAddress = functionalAddress,
        ) {
            addCanEcu(
                name = "ECU2001",
                logicalAddress = 0x2001,
            )
        }
    }
    start()
    startEmbeddedWebserver(port = portRest)
}
