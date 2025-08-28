package ecu

import RequestsData
import library.ExperimentalDoipDslApi
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalDoipDslApi::class)
fun RequestsData.addResetRequests() {
    request("11 01", name = "HardReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION

        if (ecuState.hardResetForSeconds > 0) {
            hardResetEntityFor(ecuState.hardResetForSeconds.seconds)
        }
        disableS3Timeout()

        ack()
    }

    request("11 02", name = "KeyOffOnReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION
        disableS3Timeout()
        ack()
    }

    request("11 03", name = "SoftReset") {
        val ecuState = ecu.ecuState()
        ecuState.securityAccess = SecurityAccess.LOCKED
        ecuState.sessionState = SessionState.DEFAULT
        ecuState.variant = Variant.APPLICATION
        disableS3Timeout()
        ack()
    }
}
