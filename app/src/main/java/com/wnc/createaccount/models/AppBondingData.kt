package com.example.digitalkey.u.model

private const val MC_ENCRYPTION_KEY_SIZE = 16

data class AppBondingData(
    var nvmIndex: Int = 0,
    var addrType: Int = 0,
    var aLtk: ByteArray = ByteArray(MC_ENCRYPTION_KEY_SIZE),
    var aIrk: ByteArray = ByteArray(MC_ENCRYPTION_KEY_SIZE),
    var deviceAddr: ByteArray = ByteArray(6)
)
