rootProject.name = "ecu-sim"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            version("kotlinVersion", "2.2.10")
            version("ktorVersion", "3.2.3")
            version("shadow", "8.1.1")

            library("ktor-serialization", "io.ktor", "ktor-serialization-kotlinx-json").versionRef("ktorVersion")
            library("ktor-server-core", "io.ktor", "ktor-server-core").versionRef("ktorVersion")
            library("ktor-server-cio", "io.ktor", "ktor-server-cio").versionRef("ktorVersion")
            library(
                "ktor-serialization-kotlinx-json", "io.ktor", "ktor-serialization-kotlinx-json"
            ).versionRef("ktorVersion")
            library(
                "ktor-server-content-negotiation",
                "io.ktor",
                "ktor-server-content-negotiation"
            ).versionRef("ktorVersion")

            library("doip-sim-dsl", "io.github.doip-sim-ecu:doip-sim-ecu-dsl:0.22.0")
            library("logback-classic", "ch.qos.logback:logback-classic:1.5.18")
            library("auth0-jwt", "com.auth0:java-jwt:4.5.0")
            library("google-guava", "com.google.guava:guava:33.4.8-jre")
        }
    }
}
