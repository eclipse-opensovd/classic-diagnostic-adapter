import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.gradle.kotlin.dsl.withType

plugins {
    kotlin("jvm") version libs.versions.kotlinVersion
    kotlin("plugin.allopen") version libs.versions.kotlinVersion
    kotlin("plugin.serialization") version libs.versions.kotlinVersion
    id("com.github.johnrengelman.shadow") version libs.versions.shadow
    application
}

group = "org.eclipse.opensovd.ecu-sim"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))

    implementation(libs.doip.sim.dsl)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.serialization)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.ktor.server.content.negotiation)

    implementation(libs.logback.classic)
    implementation(libs.auth0.jwt)
    implementation(libs.google.guava)
}

tasks.withType(ShadowJar::class).configureEach {
    this.archiveBaseName = "ecu-sim"
    this.archiveVersion = ""
}

application {
    mainClass.set("MainKt")
    // For debugging coroutine behaviour, add "-Dkotlinx.coroutines.debug"
    applicationDefaultJvmArgs = listOf("-Djava.net.preferIPv4Stack=true")
}

tasks {
    application {
        mainClass.set("MainKt")
    }
}

allOpen {
    annotation("kotlinx.serialization.Serializable")
}

kotlin {
    jvmToolchain(21)
}
