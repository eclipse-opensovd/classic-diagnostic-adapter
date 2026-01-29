/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

package ecu

import kotlinx.serialization.Serializable

@Serializable
enum class Variant {
    BOOT,
    APPLICATION,
    APPLICATION2,
    APPLICATION3,
}

@Serializable
enum class SessionState(
    val value: Byte,
) {
    DEFAULT(0x01),
    PROGRAMMING(0x02),
    EXTENDED(0x03),
    SAFETY(0x04),
    CUSTOM(0x23),
}

@Serializable
enum class SecurityAccess(
    val level: Byte,
) {
    LOCKED(0),
    LEVEL_03(3),
    LEVEL_05(5),
    LEVEL_07(7),
    ;

    companion object {
        fun parse(level: Byte) = entries.firstOrNull { it.level == level }
    }
}

@Serializable
enum class Authentication {
    UNAUTHENTICATED,
    AFTER_MARKET,
    AFTER_SALES,
    DEVELOPMENT,
}

@Serializable
enum class DataBlockType {
    BOOT,
    CODE,
    DATA,
}

@Serializable
enum class CommunicationControlType(
    val value: Byte,
) {
    ENABLE_RX_AND_TX(0x00),
    ENABLE_RX_AND_DISABLE_TX(0x01),
    DISABLE_RX_AND_ENABLE_TX(0x02),
    DISABLE_RX_AND_TX(0x03),
    ENABLE_RX_AND_DISABLE_TX_WITH_ENHANCED_ADDRESS_INFORMATION(0x04),
    ENABLE_RX_AND_TX_WITH_ENHANCED_ADDRESS_INFORMATION(0x05),
    TEMPORAL_SYNC(0x88.toByte()), // Non standard value, used for testing.
    ;

    companion object {
        fun parse(value: Byte) = entries.firstOrNull { it.value == value }
    }
}

@Serializable
enum class DtcSettingType(
    val value: Byte,
) {
    ON(0x01),
    OFF(0x02),
    TIME_TRAVEL_DTCS_ON(0x42),
    ;

    companion object {
        fun parse(value: Byte) = entries.firstOrNull { it.value == value }
    }
}
