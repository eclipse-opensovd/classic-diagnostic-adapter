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

import NrcException
import RequestResponseData
import RequestsData
import SimEcu
import kotlin.collections.set

private val initialStateByEcu: MutableMap<String, EcuState> = mutableMapOf()

fun RequestsData.setInitialState(state: EcuState) {
    initialStateByEcu[this.name] = state
}

fun SimEcu.ecuState(): EcuState {
    val ecuState by this.storedProperty { initialStateByEcu[this.name]?.copy() ?: EcuState() }
    return ecuState
}

data class RoutineData<T>(
    var data: T,
)

@Suppress("UNCHECKED_CAST")
fun <T> SimEcu.routineData(
    routineName: String,
    init: (() -> T)? = null,
): RoutineData<T> {
    val routineData by this.storedProperty { hashMapOf<String, RoutineData<Any>>() }
    if (routineData[routineName] == null) {
        if (init == null) {
            throw NrcException(NrcError.RequestSequenceError)
        }
        routineData[routineName] = RoutineData(init.invoke() as Any)
    }
    return routineData[routineName] as RoutineData<T>
}

fun RequestResponseData.baseServiceName(): String =
    this.caller.name!!
        .replace("_Start", "")
        .replace("_RequestResults", "")
        .replace("_Stop", "")
        .replace("_Write_Dump", "")
        .replace("_Read_Dump", "")
        .replace("_Read", "")
        .replace("_Write", "")

fun <T> RequestResponseData.routineData(init: (() -> T)? = null): RoutineData<T> = ecu.routineData(baseServiceName(), init)

fun SimEcu.resetRoutineData(routineName: String) {
    val routineData by this.storedProperty { hashMapOf<String, RoutineData<Any>>() }
    routineData.remove(routineName)
}

fun RequestResponseData.resetRoutineData() = ecu.resetRoutineData(baseServiceName())

fun SimEcu.dataTransfersDownload(): MutableList<DataTransferDownload> {
    val dataTransfers by this.storedProperty { mutableListOf<DataTransferDownload>() }
    return dataTransfers
}

fun SimEcu.dtcFaults(faultMemory: FaultMemory = FaultMemory.Standard): MutableMap<Int, DtcFault> =
    when (faultMemory) {
        FaultMemory.Standard -> {
            val dtcFaults: MutableMap<Int, DtcFault> by this.storedProperty { mutableMapOf() }
            dtcFaults
        }

        FaultMemory.Development -> {
            val dtcFaultsDevelopment: MutableMap<Int, DtcFault> by this.storedProperty { mutableMapOf() }
            dtcFaultsDevelopment
        }
    }
