package com.wnc.createaccount.ui

import java.util.UUID

object DkUuids {
    // DK GATT service (0xFFF5)
    val SERVICE: UUID = UUID.fromString("0000FFF5-0000-1000-8000-00805F9B34FB")

    // Characteristic the phone reads to get the LE CoC SPSM/PSM (2 bytes, big-endian)
    val SPSM_CHAR: UUID = UUID.fromString("d3b5a130-9e23-4b3a-8be4-6b1ee5f980a3")

    // Optional extras used in your code (keep if your ECU exposes them)
    val ANTENNA_ID_CHAR: UUID = UUID.fromString("0000FFF7-0000-1000-8000-00805F9B34FB")
    val TX_POWER_CHAR:   UUID = UUID.fromString("00002A07-0000-1000-8000-00805F9B34FB")

    // CCCD
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
}
