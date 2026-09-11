/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

import RequestsData
import kotlinx.serialization.Serializable
import library.ExperimentalDoipDslApi

@Serializable
data class TimeCircuitsStats(
    var runningTimeCircuits: Boolean = false,
    var timeCircuitsPercent: Byte = 0,
    var timeCircuitsStep: Byte = 0,
)

@OptIn(ExperimentalDoipDslApi::class)
fun RequestsData.addRoutineRequests() {
    // 31 01 10 01 - SelfTest Start (synchronous, no Stop or RequestResults)
    request("31 01 10 01", name = "SelfTest_Start") {
        ack()
    }

    // 31 01 10 02 - CalibrateSensors Start (asynchronous)
    request("31 01 10 02", name = "CalibrateSensors_Start") {
        val runningCalibration = routineData { true }
        runningCalibration.data = true
        ack()
    }

    // 31 02 10 02 - CalibrateSensors Stop
    request("31 02 10 02", name = "CalibrateSensors_Stop") {
        resetRoutineData()
        ack()
    }

    // 31 03 10 02 - CalibrateSensors RequestResults
    // Returns 0x00 while calibration is still running, 0x01 when completed (stopped).
    request("31 03 10 02", name = "CalibrateSensors_RequestResults") {
        val runningCalibration = routineData { false }
        val result: Byte = if (runningCalibration.data) 0x00 else 0x01
        ack(byteArrayOf(result))
    }

    // 31 81 03 01 [float64] - Engage_Safety_Squints Start (functional, suppress positive response)
    request("31 81 03 01 []", name = "Engage_Safety_Squints_Start_Func") {
        ack()
    }

    // 31 82 03 01 - Engage_Safety_Squints Stop (functional, suppress positive response)
    request("31 82 03 01", name = "Engage_Safety_Squints_Stop_Func") {
        ack()
    }

    // 31 01 10 03 [] - TimeCircuits Start (asynchronous, TABLE-KEY/TABLE-STRUCT on travelMethod)
    //   travelMethod (byte index 4): 0x01 ManualEntry -> destinationYear(u16) destinationMonth(u8) destinationDay(u8)
    //                                0x02 PresetDestination -> presetId(u8)
    //                                default PresentDay -> no extra bytes
    request("31 01 10 03 []", name = "TimeCircuits_Start") {
        val state = routineData { TimeCircuitsStats(true, 0, 0) }
        state.data.runningTimeCircuits = true
        state.data.timeCircuitsPercent = 0
        state.data.timeCircuitsStep = 0
        ack()
    }

    // 31 02 10 03 - TimeCircuits Stop
    request("31 02 10 03", name = "TimeCircuits_Stop") {
        resetRoutineData()
        ack()
    }

    // 31 03 10 03 - TimeCircuits RequestResults
    // Each call advances progress by 25% and one step (Idle -> Accelerating ->
    // TemporalDisplacement -> Arrived). The optional trailing message is only
    // populated once Arrived.
    request("31 03 10 03", name = "TimeCircuits_RequestResults") {
        val state = routineData { TimeCircuitsStats() }
        val currentPercent = state.data.timeCircuitsPercent.toInt()
        if (currentPercent < 100 && state.data.runningTimeCircuits) {
            val newPercent = (currentPercent + 25).coerceAtMost(100)
            state.data.timeCircuitsPercent = newPercent.toByte()
            state.data.timeCircuitsStep = (newPercent / 25).coerceAtMost(3).toByte()
        }

        val message =
            if (state.data.timeCircuitsStep >= 3 && state.data.runningTimeCircuits) {
                "Great Scott! We made it!".toByteArray(Charsets.ISO_8859_1)
            } else {
                ByteArray(0)
            }

        ack(byteArrayOf(state.data.timeCircuitsPercent, state.data.timeCircuitsStep) + message)
    }
}
