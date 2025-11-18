package com.wnc.createaccount.models

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class EndpointCreation(
    val endpointConfigRaw: ByteArray?,               // 7F27 TLV raw
    val vehicleIdentifier: ByteArray?,               // 4D (8 bytes)
    val endpointIdentifier: String?,                 // 5F20 DER PrintableString
    val instanceCaIdentifier: String?,               // 42 DER PrintableString
    val flags47: Int?,                               // 46
    val flags48: Int?,                               // 47
    val protocolVersion: ByteArray?,                 // 5C (2)
    val vehiclePk: ByteArray?,                       // 5B (65 bytes with 04)
    val notBefore: ByteArray?,                       // 51 GeneralizedTime DER
    val notAfter: ByteArray?,                        // 52
    val authorizedPKs: List<ByteArray>?,             // 49 optional
    val confidentialMailboxSize: Int?,               // 4A optional
    val privateMailboxSize: Int?,                    // 4B optional
    val keySlots: ByteArray?,                        // 4E optional
    val counterLimit: Int?                           // 57 optional
    )
