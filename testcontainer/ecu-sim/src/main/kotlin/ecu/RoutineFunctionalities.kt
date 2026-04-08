/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

package ecu

import RequestsData
import library.ExperimentalDoipDslApi

@OptIn(ExperimentalDoipDslApi::class)
fun RequestsData.addRoutineRequests() {
    // 31 01 10 01 — SelfTest Start (synchronous, no Stop or RequestResults)
    request("31 01 10 01", name = "SelfTest_Start") {
        ack()
    }

    // 31 01 10 02 — CalibrateSensors Start (asynchronous)
    request("31 01 10 02", name = "CalibrateSensors_Start") {
        val ecuState = ecu.ecuState()
        ecuState.runningCalibration = true
        ack()
    }

    // 31 02 10 02 — CalibrateSensors Stop
    request("31 02 10 02", name = "CalibrateSensors_Stop") {
        val ecuState = ecu.ecuState()
        ecuState.runningCalibration = false
        ack()
    }

    // 31 03 10 02 — CalibrateSensors RequestResults
    // Returns 0x00 while calibration is still running, 0x01 when completed (stopped).
    request("31 03 10 02", name = "CalibrateSensors_RequestResults") {
        val ecuState = ecu.ecuState()
        val result: Byte = if (ecuState.runningCalibration) 0x00 else 0x01
        ack(byteArrayOf(result))
    }
}
