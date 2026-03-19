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

rootProject.name = "ecu-sim"

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            version("kotlinVersion", "2.2.10")
            version("ktorVersion", "3.2.3")
            version("shadow", "8.1.1")
            version("ktlint", "14.0.1")

            library("ktor-serialization", "io.ktor", "ktor-serialization-kotlinx-json").versionRef("ktorVersion")
            library("ktor-server-core", "io.ktor", "ktor-server-core").versionRef("ktorVersion")
            library("ktor-server-cio", "io.ktor", "ktor-server-cio").versionRef("ktorVersion")
            library(
                "ktor-serialization-kotlinx-json",
                "io.ktor",
                "ktor-serialization-kotlinx-json",
            ).versionRef("ktorVersion")
            library(
                "ktor-server-content-negotiation",
                "io.ktor",
                "ktor-server-content-negotiation",
            ).versionRef("ktorVersion")

            library("doip-sim-dsl", "io.github.doip-sim-ecu:doip-sim-ecu-dsl:0.22.0")
            library("logback-classic", "ch.qos.logback:logback-classic:1.5.18")
            library("auth0-jwt", "com.auth0:java-jwt:4.5.0")
            library("google-guava", "com.google.guava:guava:33.4.8-jre")
        }
    }
}
