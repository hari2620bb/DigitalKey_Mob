package com.wnc.createaccount.ui

//import java.io.ByteArrayOutputStream
//fun parseTlvStream(bytes: ByteArray): Map<Int, ByteArray> {
//    val out = mutableMapOf<Int, ByteArray>()
//    var i = 0
//    while (i < bytes.size) {
//        var tag = bytes[i].toInt() and 0xFF
//        i++
//        if ((tag and 0x1F) == 0x1F && i < bytes.size) {
//            val next = bytes[i].toInt() and 0xFF
//            tag = (tag shl 8) or next
//            i++
//        }
//
//        if (i >= bytes.size) break
//        val len = bytes[i].toInt() and 0xFF
//        i++
//        if (i + len > bytes.size) break
//
//        val value = bytes.sliceArray(i until i + len)
//        out[tag] = value
//        i += len
//    }
//    return out
//}
//
//fun parseTlvStreamOrdered(bytes: ByteArray): List<Pair<Int, ByteArray>> {
//    val out = mutableListOf<Pair<Int, ByteArray>>()
//    var i = 0
//    while (i < bytes.size) {
//        // parse tag (support multi-byte tag)
//        var tag = bytes[i].toInt() and 0xFF
//        i++
//        if ((tag and 0x1F) == 0x1F) { // long tag form
//            var more = true
//            var tagVal = tag
//            while (more && i < bytes.size) {
//                val b = bytes[i].toInt() and 0xFF
//                tagVal = (tagVal shl 8) or b
//                i++
//                more = (b and 0x80) != 0x80 // high bit set = more bytes follow (for multi-byte tag)
//                // Note: many TLVs use one extra byte only; this handles generic multi-byte
//            }
//            tag = tagVal
//        }
//
//        if (i >= bytes.size) break
//
//        // parse length (support long form)
//        val lenByte = bytes[i].toInt() and 0xFF
//        i++
//        var length = 0
//        if (lenByte and 0x80 == 0) {
//            // short form
//            length = lenByte
//        } else {
//            // long form: number of length bytes = lenByte & 0x7F
//            val numLenBytes = lenByte and 0x7F
//            if (numLenBytes == 0 || numLenBytes > 4) break // defensive
//            if (i + numLenBytes > bytes.size) break
//            length = 0
//            for (k in 0 until numLenBytes) {
//                length = (length shl 8) or (bytes[i].toInt() and 0xFF)
//                i++
//            }
//        }
//
//        if (i + length > bytes.size) break
//        val value = bytes.sliceArray(i until i + length)
//        out.add(tag to value)
//        i += length
//    }
//    return out
//}
//
//
////fun parseNestedTlv(value: ByteArray): Map<Int, ByteArray> = parseTlvStream(value)
//fun parseNestedTlv(bytes: ByteArray): Map<Int, ByteArray> {
//    val list = parseTlvStreamOrdered(bytes)
//    return list.toMap()
//}
//
//
//fun reconstructFullBufferFromMap(tlvMap: Map<Int, ByteArray>): ByteArray {
//    val baos = ByteArrayOutputStream()
//    tlvMap.forEach { (tag, value) ->
//        if (tag > 0xFF) baos.write((tag shr 8) and 0xFF)
//        baos.write(tag and 0xFF)
//        baos.write(value.size)
//        baos.write(value)
//    }
//    return baos.toByteArray()
//}
