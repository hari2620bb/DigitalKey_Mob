package com.wnc.createaccount.ui

// assemble.kt
//Build DigitalKey from parsed TLVs

import java.nio.charset.StandardCharsets
import com.squareup.moshi.Moshi
import com.wnc.createaccount.models.DeviceConfig
import com.wnc.createaccount.models.DigitalKey
import com.wnc.createaccount.models.EndpointCreation
import com.wnc.createaccount.models.MailboxMapping
//
//fun buildDigitalKeyFromTlv(decryptedData: ByteArray): DigitalKey {
//    //val topLevel = parseTlvStream(decryptedData)
//    val topLevel = parseTlvStreamOrdered(decryptedData).toMap()
//
//    val endpointBytes = topLevel[0x7F4A] // Endpoint creation TLV value
//    val vehicleCert = topLevel[0x7F4B]
//    val intermediateCert = topLevel[0x7F4C]
//    val mailboxMappingRaw = topLevel[0x7F4D]
//    val deviceConfigRaw = topLevel[0x7F4E]
//
//    var endpoint: EndpointCreation? = null
//    endpointBytes?.let { epVal ->
//        // parse nested fields inside 7F4A
//        val ep = parseNestedTlv(epVal)
//        val epCreation = EndpointCreation(
//            endpointConfigRaw = ep[0x7F27],
//            vehicleIdentifier = ep[0x4D],
//            endpointIdentifier = ep[0x5F20]?.let { extractPrintableString(it) },
//            instanceCaIdentifier = ep[0x42]?.let { extractPrintableString(it) },
//            flags47 = ep[0x46]?.let { it[0].toInt() and 0xFF },
//            flags48 = ep[0x47]?.let { it[0].toInt() and 0xFF },
//            protocolVersion = ep[0x5C],
//            vehiclePk = ep[0x5B],
//            notBefore = ep[0x51],
//            notAfter = ep[0x52],
//            authorizedPKs = ep[0x49]?.let { parseAuthorizedPKs(it) },
//            confidentialMailboxSize = ep[0x4A]?.let { ( (it[0].toInt() and 0xFF) shl 8 ) or (it[1].toInt() and 0xFF) },
//            privateMailboxSize = ep[0x4B]?.let { ( (it[0].toInt() and 0xFF) shl 8 ) or (it[1].toInt() and 0xFF) },
//            keySlots = ep[0x4E],
//            counterLimit = ep[0x57]?.let { ((it[0].toInt() and 0xFF) shl 24) or ((it[1].toInt() and 0xFF) shl 16) or ((it[2].toInt() and 0xFF) shl 8) or (it[3].toInt() and 0xFF) }
//        )
//        endpoint = epCreation
//    }
//
//    val mailbox = mailboxMappingRaw?.let { MailboxMapping(raw = it) }
//    val deviceCfg = deviceConfigRaw?.let { DeviceConfig(raw = it) }
//
//    val dk = DigitalKey(
//        endpointCreation = endpoint,
//        vehicleCertDer = vehicleCert,
//        intermediateCertDer = intermediateCert,
//        mailboxMapping = mailbox,
//        deviceConfig = deviceCfg
//    )
//
//    return dk
//}
//
//fun extractPrintableString(derBytes: ByteArray): String {
//    // If DER-encoded PrintableString, you can attempt a naive extraction:
//    // Common DER: tag + len + bytes. If already only the PrintableString content, return that.
//    // Simple approach: if first byte is 0x13 (PrintableString) or 0x16 (IA5String) parse length:
//    if (derBytes.isEmpty()) return ""
//    var cursor = 0
//    val tag = derBytes[0].toInt() and 0xFF
//    if (tag == 0x13 || tag == 0x16) {
//        cursor++
//        val len = derBytes[cursor].toInt() and 0xFF
//        cursor++
//        return String(derBytes, cursor, len, StandardCharsets.US_ASCII)
//    }
//    return String(derBytes, StandardCharsets.US_ASCII)
//}
//
//fun parseAuthorizedPKs(bytes: ByteArray): List<ByteArray> {
//    // authorized_PK[] could be a sequence of 65-byte public keys each prefixed with 0x04
//    val list = mutableListOf<ByteArray>()
//    var i = 0
//    while (i < bytes.size) {
//        if (bytes[i] == 0x04.toByte() && i + 65 <= bytes.size) {
//            list.add(bytes.sliceArray(i until i + 65))
//            i += 65
//        } else {
//            // fallback: try to split by 65
//            val remaining = bytes.size - i
//            val toTake = if (remaining >= 65) 65 else remaining
//            list.add(bytes.sliceArray(i until i + toTake))
//            i += toTake
//        }
//    }
//    return list
//}
