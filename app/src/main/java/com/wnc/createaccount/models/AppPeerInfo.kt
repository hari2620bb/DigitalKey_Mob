package com.example.digitalkey.u.model


import com.wnc.createaccount.utils.AppState

private const val INVALID_DEVICE_ID = -1

data class AppPeerInfo(
    var deviceId: Int = INVALID_DEVICE_ID,
    var appState: AppState = AppState.IDLE,
    var isBonded: Boolean = false,
    var customInfo: CustomInfo = CustomInfo(),
    var oobData: ByteArray? = null,
    var peerOobData: ByteArray? = null
)
