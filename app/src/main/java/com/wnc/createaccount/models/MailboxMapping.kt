package com.wnc.createaccount.models

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class MailboxMapping(val raw: ByteArray?
// Optionally parse D0..C7 fields into properties
)
