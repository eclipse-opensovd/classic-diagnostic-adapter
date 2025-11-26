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

import NrcError
import NrcException
import RequestsData
import utils.messagePayload
import utils.toByteArray
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.experimental.and

private val EMPTY_ARRAY = ByteArray(0)

class RequestDownloadRequest(
    val dataFormatIdentifier: Byte, // high nibble = compressionMethod, low nibble = encryptingMethod
    val addressAndLengthIdentifier: Byte,
    val memoryAddress: ByteArray,
    val memorySize: ByteArray,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(dataFormatIdentifier, addressAndLengthIdentifier) + memoryAddress + memorySize

    companion object {
        fun parse(data: ByteBuffer): RequestDownloadRequest {
            val dataFormatIdentifier = data.get()

            val addressAndLengthFormatIdentifier = data.get()
            val memAddressLength =
                addressAndLengthFormatIdentifier
                    .and(0xF0.toByte())
                    .toInt()
                    .shr(4)
                    .and(0x0F)
            val memoryAddress = ByteArray(memAddressLength)
            data.get(memoryAddress)
            val memSizeLength = addressAndLengthFormatIdentifier.and(0x0F.toByte()).toInt().and(0x0F)
            val memorySize = ByteArray(memSizeLength)

            return RequestDownloadRequest(
                dataFormatIdentifier = dataFormatIdentifier,
                addressAndLengthIdentifier = addressAndLengthFormatIdentifier,
                memoryAddress = memoryAddress,
                memorySize = memorySize,
            )
        }
    }
}

class RequestDownloadResponse(
    val type: IdentifierType,
    val maxNumberOfBlockLength: ULong,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(type.lengthInBytes.toByte()) + maxNumberOfBlockLength.toByteArray(type.lengthInBytes)

    enum class IdentifierType(
        val lengthInBytes: Int,
    ) {
        UINT16(2),
        UINT32(4),
        UINT64(8),
    }
}

class TransferDataResponse(
    val blockSequenceCounter: Byte,
    val data: ByteArray = EMPTY_ARRAY,
) {
    val asByteArray: ByteArray
        get() = byteArrayOf(blockSequenceCounter) + data
}

class DataTransferDownload(
    val addressAndLengthIdentifier: Byte,
    val memoryAddress: ByteArray,
    val memorySize: ByteArray,
) {
    val isActive: Boolean
        get() =
            state == DataTransferState.IN_PROGRESS

    var checksum: ByteArray? = null
    var dataTransferCount: Int = 0

    private var state = DataTransferState.IN_PROGRESS
    private var lastBlockSequenceCounter: Int = 0 // first transfer has to start with 1

    private val checksumCalculator: MessageDigest = MessageDigest.getInstance("SHA1")

    fun addDataTransfer(
        blockSequenceCounter: Int,
        data: ByteBuffer,
    ) {
        if (state != DataTransferState.IN_PROGRESS) {
            throw NrcException(NrcError.RequestSequenceError)
        } else if ((blockSequenceCounter % 256) != ((lastBlockSequenceCounter + 1) % 256)) {
            throw NrcException(NrcError.WrongBlockSequenceCounter)
        }
        checksumCalculator.update(data)
        dataTransferCount += 1
    }

    fun finish() {
        state = DataTransferState.FINISHED
        checksum = checksumCalculator.digest()
    }

    enum class DataTransferState {
        IN_PROGRESS,
        FINISHED,
    }
}

fun RequestsData.addFlashRequests() {
    request("34 []", "RequestDownload") {
        ensureEcuModeIn(Variant.BOOT)
        ensureSessionIn(SessionState.PROGRAMMING)
        ensureSecurityAccessIn(SecurityAccess.LEVEL_07)

        val ecuState = ecu.ecuState()

        val dataTransfers = ecu.dataTransfersDownload()
        val request = RequestDownloadRequest.parse(messagePayload())

        if (dataTransfers.lastOrNull()?.isActive == true) {
            throw NrcException(NrcError.RequestSequenceError)
        }

        val dataTransfer =
            DataTransferDownload(
                addressAndLengthIdentifier = request.addressAndLengthIdentifier,
                memoryAddress = request.memoryAddress,
                memorySize = request.memorySize,
            )
        dataTransfers.add(dataTransfer)

        val response = RequestDownloadResponse(RequestDownloadResponse.IdentifierType.UINT32, ecuState.maxNumberOfBlockLength.toULong())
        ack(response.asByteArray)
    }

    request("36 []", "TransferData") {
        ensureEcuModeIn(Variant.BOOT)
        ensureSessionIn(SessionState.PROGRAMMING)
        ensureSecurityAccessIn(SecurityAccess.LEVEL_07)

        val dataTransfers = ecu.dataTransfersDownload()
        val currentTransfer = dataTransfers.lastOrNull() ?: throw NrcException(NrcError.RequestSequenceError)

        val data = messagePayload()
        val blockSequenceCounter = data.get()

        currentTransfer.addDataTransfer(
            blockSequenceCounter = blockSequenceCounter.toUByte().toInt(),
            data = data,
        )

        val response =
            TransferDataResponse(
                blockSequenceCounter = blockSequenceCounter,
            )

        ack(response.asByteArray)
    }

    request("37 []", "RequestTransferExit") {
        ensureEcuModeIn(Variant.BOOT)
        ensureSessionIn(SessionState.PROGRAMMING)
        ensureSecurityAccessIn(SecurityAccess.LEVEL_07)

        val dataTransfers = ecu.dataTransfersDownload()
        val currentTransfer = dataTransfers.lastOrNull() ?: throw NrcException(NrcError.RequestSequenceError)
        currentTransfer.finish()

        ack()
    }

    request("31 01 FF 00", "EraseMemory_Start") {
        ensureEcuModeIn(Variant.BOOT)
        ensureSessionIn(SessionState.PROGRAMMING)
        ensureSecurityAccessIn(SecurityAccess.LEVEL_07)

        val dataTransfers = ecu.dataTransfersDownload()
        dataTransfers.clear()

        // TODO response needs to be defined by ECU/our ODX

        ack()
    }

    request("31 01 FF 01", "CheckProgrammingDependencies_Start") {
        // TODO response needs to be defined by ECU/our ODX
        ack()
    }
}
