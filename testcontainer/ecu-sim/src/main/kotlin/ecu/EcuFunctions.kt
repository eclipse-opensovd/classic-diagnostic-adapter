package ecu

import DoipEntityData
import DoipEntityDataHandler
import NetworkingData
import RequestsData
import addDtcRequests

private fun generateDefaultEcuState() =
    EcuState()

fun NetworkingData.addDoipEntity(
    name: String,
    logicalAddress: Short,
    functionalAddress: Short,
    eid: ByteArray? = null,
    gid: ByteArray? = null,
    initialEcuState: EcuState? = null,
    block: DoipEntityDataHandler = {}
) {
    doipEntity(name) {
        val ecuState = initialEcuState ?: generateDefaultEcuState()

        this.logicalAddress = logicalAddress
        this.functionalAddress = functionalAddress
        this.vin = ecuState.vin
        eid?.let { this.eid = it }
        gid?.let { this.gid = it }
        setInitialState(ecuState)

        addAllFunctionality()

        block.invoke(this)
    }
}

fun DoipEntityData.addCanEcu(
    name: String,
    logicalAddress: Short,
    functionalAddress: Short = this.functionalAddress,
    initialEcuState: EcuState? = null,
) {
    ecu(name) {
        val ecuState = initialEcuState ?: EcuState()

        this.logicalAddress = logicalAddress
        this.functionalAddress = functionalAddress
        setInitialState(ecuState)

        addAllFunctionality()
    }
}

fun RequestsData.addAllFunctionality() {
    addSessionRequests()
    addResetRequests()
    addSecurityAccessRequests()
    addAuthenticationRequests()
    addDiagnosticRequests()
    addFlashRequests()
    addDtcRequests()
}
