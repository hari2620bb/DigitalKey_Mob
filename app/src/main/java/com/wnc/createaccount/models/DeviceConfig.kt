package com.wnc.createaccount.models

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DeviceConfig(
    val raw: ByteArray?
    // Optionally parse D7..D9 fields etc.
)
