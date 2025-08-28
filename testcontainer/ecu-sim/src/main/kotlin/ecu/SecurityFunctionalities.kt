package ecu

import NrcError
import RequestsData
import java.util.*

fun RequestsData.addSecurityAccessRequests() {
    request("27 []", name = "RequestSeed_SendKey") {
        val ecuState = ecu.ecuState()

        val subFunction = message[1]
        if (subFunction % 2 == 1) {
            // Request Seed
            val level = SecurityAccess.parse(subFunction)
            if (level == null) {
                nrc(NrcError.RequestOutOfRange)
            } else {
                // Create seed and fill with random data
                val generatedSeed = ByteArray(8)
                Random().nextBytes(generatedSeed)

                var seed by ecu.storedProperty { ByteArray(0) }
                seed = generatedSeed

                ack(byteArrayOf((level.level + 1).toByte(), *seed))
            }
        } else {
            // Send key
            val level = SecurityAccess.parse(
                level = (subFunction - 1).toByte()
            )
            if (level == null) {
                nrc(NrcError.RequestOutOfRange)
            } else {
                val data = this.message.copyOfRange(2, this.message.size - 1)
                var seed by ecu.storedProperty { ByteArray(0) }

                if (seed.size == 8) {
                    // Use a super secure algorithm
                    val rot13 = seed.map { it.toUByte().plus(13u).toByte() }.toByteArray()
                    if (data.contentEquals(rot13)) {
                        ecuState.securityAccess = level
                        @Suppress("AssignedValueIsNeverRead")
                        seed = ByteArray(0)
                        ack()
                    } else {
                        nrc(NrcError.InvalidKey)
                    }
                } else {
                    nrc(NrcError.RequestSequenceError)
                }
            }
        }

    }
}
