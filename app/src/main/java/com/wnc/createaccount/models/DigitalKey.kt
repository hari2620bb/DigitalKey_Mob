package com.wnc.createaccount.models

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DigitalKey(
    val endpointCreation: EndpointCreation?,
    val vehicleCertDer: ByteArray?,
    val intermediateCertDer: ByteArray?,
    val mailboxMapping: MailboxMapping?,
    val deviceConfig: DeviceConfig?,
    val receivedAtMs: Long = System.currentTimeMillis()
)
