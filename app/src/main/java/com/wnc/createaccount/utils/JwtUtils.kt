package com.wnc.createaccount.util

import android.util.Base64
import org.json.JSONObject

object JwtUtils {
    fun decodePayload(jwt: String): JSONObject? {
        val parts = jwt.split(".")
        if (parts.size < 2) return null
        return try {
            val bytes = Base64.decode(
                parts[1],
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
            JSONObject(String(bytes))
        } catch (_: Exception) {
            null
        }
    }
}
