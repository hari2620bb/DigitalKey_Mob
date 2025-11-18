package com.wnc.createaccount.util

import android.content.Context

object PairingStore {
    private const val PREF = "pairing_prefs"
    private const val KEY_CONNECTED = "is_connected"
    private const val KEY_PENDING   = "is_pending"

    fun setPending(ctx: Context, value: Boolean) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_PENDING, value).apply()

    fun setConnected(ctx: Context, value: Boolean) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_CONNECTED, value).apply()

    fun isPending(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(KEY_PENDING, false)

    fun isConnected(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(KEY_CONNECTED, false)
}
