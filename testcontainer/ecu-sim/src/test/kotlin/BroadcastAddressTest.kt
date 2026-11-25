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

import kotlin.test.Test
import kotlin.test.assertEquals

class BroadcastAddressTest {
    @Test
    fun `unset override preserves the library default`() {
        val network = NetworkingData()

        network.configureBroadcastAddress(null)

        assertEquals("255.255.255.255", network.broadcastAddress)
    }

    @Test
    fun `unset override does not replace an existing address`() {
        val network = NetworkingData().apply { broadcastAddress = "192.0.2.255" }

        network.configureBroadcastAddress(null)

        assertEquals("192.0.2.255", network.broadcastAddress)
    }

    @Test
    fun `configured address overrides the library default`() {
        val network = NetworkingData()

        network.configureBroadcastAddress("192.168.7.255")

        assertEquals("192.168.7.255", network.broadcastAddress)
    }
}
