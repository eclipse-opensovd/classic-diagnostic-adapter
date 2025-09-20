import ecu.addCanEcu
import ecu.addDoipEntity
import webserver.startEmbeddedWebserver

fun main() {
    println("OpenSOVD CDA ECU-SIM")

    val functionalAddress = 0xffff.toShort()
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
            name = "FLXC1000",
            logicalAddress = 0x1000,
            functionalAddress = functionalAddress,
        ) {
            addCanEcu(
                name = "TMC1001",
                logicalAddress = 0x1001,
            )
        }

        addDoipEntity(
            name = "FSNR2000",
            logicalAddress = 0x2000,
            functionalAddress = functionalAddress,
        ) {
        }
    }
    start()
    startEmbeddedWebserver(port = portRest)
}
