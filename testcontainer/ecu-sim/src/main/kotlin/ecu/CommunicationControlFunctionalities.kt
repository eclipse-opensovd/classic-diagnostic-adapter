/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

import NrcError
import RequestsData
import utils.toInt

fun RequestsData.addCommunicationControlRequests() {
    // 28 00 01 - Enable RX and TX
    request("28 00 01", name = "CommunicationControl_EnableRxAndTx") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType = CommunicationControlType.ENABLE_RX_AND_TX
        ecuState.temporalEraId = null
        ack()
    }

    // 28 01 01 - Enable RX and Disable TX
    request("28 01 01", name = "CommunicationControl_EnableRxAndDisableTx") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType = CommunicationControlType.ENABLE_RX_AND_DISABLE_TX
        ecuState.temporalEraId = null
        ack()
    }

    // 28 02 01 - Disable RX and Enable TX
    request("28 02 01", name = "CommunicationControl_DisableRxAndEnableTx") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType = CommunicationControlType.DISABLE_RX_AND_ENABLE_TX
        ecuState.temporalEraId = null
        ack()
    }

    // 28 03 01 - Disable RX and TX
    request("28 03 01", name = "CommunicationControl_DisableRxAndTx") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType = CommunicationControlType.DISABLE_RX_AND_TX
        ecuState.temporalEraId = null
        ack()
    }

    // 28 04 01 - Enable RX and Disable TX with Enhanced Address Information
    request("28 04 01", name = "CommunicationControl_EnableRxAndDisableTxWithEnhancedAddressInformation") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType =
            CommunicationControlType.ENABLE_RX_AND_DISABLE_TX_WITH_ENHANCED_ADDRESS_INFORMATION
        ecuState.temporalEraId = null
        ack()
    }

    // 28 05 01 - Enable RX and TX with Enhanced Address Information
    request("28 05 01", name = "CommunicationControl_EnableRxAndTxWithEnhancedAddressInformation") {
        val ecuState = ecu.ecuState()
        ecuState.communicationControlType = CommunicationControlType.ENABLE_RX_AND_TX_WITH_ENHANCED_ADDRESS_INFORMATION
        ecuState.temporalEraId = null
        ack()
    }

    // 28 88 01 [temporalEraId] - Temporal Sync (custom vendor-specific)
    // Expects 4 additional bytes for the 32-bit signed integer temporalEraId
    request("28 88 01 []", name = "CommunicationControl_TemporalSync") {
        val ecuState = ecu.ecuState()

        // Verify we have the temporalEraId parameter (8 bytes after the 3-byte header)
        if (message.size < 7) {
            nrc(NrcError.IncorrectMessageLengthOrInvalidFormat)
            return@request
        }

        // Extract the 64-bit signed integer from bytes 3-10
        val temporalEraIdBytes = message.sliceArray(3..6)
        val temporalEraId = temporalEraIdBytes.toInt()

        ecuState.communicationControlType = CommunicationControlType.TEMPORAL_SYNC
        ecuState.temporalEraId = temporalEraId

        ecu.logger.info("TemporalSync: Set temporalEraId to 0x${temporalEraId.toString(16).uppercase()}")

        ack()
    }
}
