package com.example.digitalkey.u.model

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * DK Message framing helper (matches screenshot)
 *
 * Frame format:
 * [ messageHeader (1 byte) | payloadHeader (1 byte) | length (2 bytes, big-endian) | data (N bytes) ]
 */
data class DkMessage(
    val messageHeader: Byte,
    val payloadHeader: Byte,
    val payload: ByteArray
) {
    fun toByteArray(): ByteArray {
        val buf = ByteBuffer.allocate(1 + 1 + 2 + payload.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(messageHeader)
        buf.put(payloadHeader)
        buf.putShort(payload.size.toShort())
        buf.put(payload)
        return buf.array()
    }

    companion object {
        /**
         * Try to parse a DkMessage from a byte array starting at offset 0.
         * If incomplete returns null. If complete returns the message and number of bytes consumed.
         */
        fun tryParse(buffer: ByteArray): Pair<DkMessage?, Int> {
            if (buffer.size < 4) return Pair(null, 0)
            val bb = ByteBuffer.wrap(buffer).order(ByteOrder.BIG_ENDIAN)
            val msgHdr = bb.get()
            val payloadHdr = bb.get()
            val length = bb.short.toInt() and 0xFFFF
            if (bb.remaining() < length) return Pair(null, 0)
            val payload = ByteArray(length)
            bb.get(payload)
            val consumed = 4 + length
            return Pair(DkMessage(msgHdr, payloadHdr, payload), consumed)
        }
    }
}
