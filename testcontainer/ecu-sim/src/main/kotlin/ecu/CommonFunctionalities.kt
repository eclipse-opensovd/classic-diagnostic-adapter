package ecu

import RequestsData
import SimEcu

private val initialStateByEcu: MutableMap<String, EcuState> = mutableMapOf()

fun RequestsData.setInitialState(state: EcuState) {
    initialStateByEcu[this.name] = state
}

fun SimEcu.ecuState(): EcuState {
    val ecuState by this.storedProperty { initialStateByEcu[this.name]?.copy() ?: EcuState() }
    return ecuState
}

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
