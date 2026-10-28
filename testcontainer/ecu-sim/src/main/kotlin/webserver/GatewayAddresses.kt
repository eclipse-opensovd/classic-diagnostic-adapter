/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package webserver

import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Makes single DoIP gateways unreachable by removing their IP address from the network interface.
 *
 * The doip-sim-ecu-dsl library binds each DoIP entity to one IP address of the interface (with
 * `USE_MULTIPLE_IPS=true`, every entity has its own `/32` address). A gateway is addressed by its IP,
 * which a tester knows from the persisted topology (`network_address`). `ip address del` makes the
 * gateway unreachable and silences its UDP announcements. The listening sockets stay bound, so
 * `ip address add` makes the gateway reachable again without any restart.
 */
object GatewayAddresses {
    private val ipv4 = Regex("""\d{1,3}(?:\.\d{1,3}){3}""")

    /** Addresses that are currently stopped, with the CIDR to restore. */
    private val stopped = ConcurrentHashMap<String, String>()

    class GatewayAddressException(
        message: String,
    ) : RuntimeException(message)

    @Synchronized
    fun stop(ip: String) {
        if (stopped.containsKey(ip)) {
            return
        }
        val cidr = secondaryAddress(ip)
        run("ip", "address", "del", cidr, "dev", networkInterface())
        stopped[ip] = cidr
    }

    @Synchronized
    fun start(ip: String) {
        val cidr = stopped[ip] ?: return
        run("ip", "address", "add", cidr, "dev", networkInterface())
        stopped.remove(ip)
    }

    private fun networkInterface(): String {
        val iface = System.getenv("SIM_NETWORK_INTERFACE").orEmpty()
        if (iface.isBlank() || iface == "0.0.0.0") {
            throw GatewayAddressException("SIM_NETWORK_INTERFACE must name an interface to stop gateways")
        }
        return iface
    }

    /**
     * The CIDR of [ip] on the interface. Only a single-address secondary IP (as added for
     * USE_MULTIPLE_IPS) may be removed: deleting a primary address would also drop all secondary
     * addresses of its subnet.
     */
    private fun secondaryAddress(ip: String): String {
        if (!ipv4.matches(ip)) {
            throw GatewayAddressException("'$ip' is not an IPv4 address")
        }
        val output = run("ip", "-o", "-4", "address", "show", "dev", networkInterface())
        val cidr =
            output
                .lineSequence()
                .mapNotNull { Regex("""inet (\Q$ip\E/(\d+))""").find(it) }
                .firstOrNull()
        if (cidr == null) {
            throw GatewayAddressException("IP address $ip is not configured on ${networkInterface()}")
        }
        if (cidr.groupValues[2] != "32") {
            throw GatewayAddressException("IP address $ip is not a secondary /32 address, refusing to remove it")
        }
        return cidr.groupValues[1]
    }

    /** Runs the command; the output goes to a file, so the timeout applies even to a command that never ends. */
    private fun run(vararg command: String): String {
        val outputFile = File.createTempFile("ecu-sim-ip", ".log")
        try {
            val process =
                ProcessBuilder(*command)
                    .redirectErrorStream(true)
                    .redirectOutput(outputFile)
                    .start()
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                throw GatewayAddressException("'${command.joinToString(" ")}' timed out")
            }
            val output = outputFile.readText()
            if (process.exitValue() != 0) {
                throw GatewayAddressException("'${command.joinToString(" ")}' failed: ${output.trim()}")
            }
            return output
        } finally {
            outputFile.delete()
        }
    }
}
