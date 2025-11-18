package com.wnc.createaccount.utils

import java.nio.ByteBuffer

object Spake2EngineMock {
    data class Handshake(val msg1: ByteArray, val msg2ExpectedPrefix: ByteArray)

    fun start(ownerPassword: String): Handshake {
// DO NOT USE IN PRODUCTION.
        val pwBytes = ownerPassword.encodeToByteArray()
        val msg1 = ByteBuffer.allocate(
            4 +
                    pwBytes.size
        ).putInt(pwBytes.size).put(pwBytes).array()
        val expect = byteArrayOf(0x53, 0x50, 0x41, 0x4B, 0x45) // "SPAKE"
        return Handshake(msg1, expect)
    }

    fun verify(peerMsg2: ByteArray, expectedPrefix: ByteArray): Boolean =
        peerMsg2.take(expectedPrefix.size).toByteArray().contentEquals(expectedPrefix)
}