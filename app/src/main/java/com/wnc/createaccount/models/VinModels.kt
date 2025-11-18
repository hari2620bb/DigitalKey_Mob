package com.wnc.createaccount.models

data class LinkVinRequest(
    val userId: String,
    val vin: String,
    val role: String = "owner"
)

data class LinkVinResponse(
    val status: Boolean,
    val error: Boolean,
    val statusCode: Int,
    val message: String
)

data class VinApiResponse(
    val status: Boolean,
    val statusCode: Int,
    val source: String?,
    val response: List<VehicleDto> = emptyList()
)

data class VehicleDto(
    val vehicle_id: Int,
    val vin: String,
    val make: String,
    val model: String,
    val year: Int,
    val image_url: String?,
    val created_at: String
)

data class VinDataItem(
    val vehicle_id: Int,
    val vin: String,
    val make: String,
    val model: String,
    val year: Int,
    val image_url: String?,
    val created_at: String?
)
data class VinDataResponse(
    val status: Boolean,
    val statusCode: Int,
    val source: String?,
    val response: List<VinDataItem> = emptyList()
)

data class UserVehicleItem(
    val user_id: String,
    val name: String?,
    val email: String?,
    val country_code: String?,
    val phone_number: String?,
    val vin: String,
    val model: String?,
    val year: Int?,
    val image_url: String?
)

data class UserVehiclesResponse(
    val status: Boolean,
    val error: Boolean,
    val statusCode: Int,
    val response: List<UserVehicleItem>
)


