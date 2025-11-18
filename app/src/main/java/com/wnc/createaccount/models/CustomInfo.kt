package com.example.digitalkey.u.model

data class CustomInfo(
    var hDkService: Int = 0,
    var hPsmChannelChar: Int = 0,
    var hAntennaIdChar: Int = 0,
    var hTxPowerChar: Int = 0,
    var lePsmValue: Int = 0,
    var psmChannelId: Int = 0,
    var longTermKey: ByteArray? = null
)
