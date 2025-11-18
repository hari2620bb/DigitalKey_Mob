package com.example.digitalkey.u.model

data class GattCharacteristicInfo(
    var handle: Int = 0,
    var maxValueLength: Int = 0,
    var value: ByteArray? = null
)
