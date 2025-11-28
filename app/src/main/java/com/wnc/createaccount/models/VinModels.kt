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

// Data class to send to backend
data class ShareFriendRequest(
    val name: String,
    val email: String
)

// Response from backend
data class ShareFriendResponse(
    val status: Boolean,
    val message: String,
    val statusCode: Int,
    val data: ResponseData?
)

data class ResponseData(
    val fieldCount: Int?,
    val affectedRows: Int?,
    val insertId: Int?,
    val info: String?,
    val serverStatus: Int?,
    val warningStatus: Int?,
    val changedRows: Int?
)

data class FriendsList(
    val id: Int,
    val user_id: String,
    val vehicle_id: String,
    val profile_img: String?,
    val owner_key_id: String,
    val certificate_reference: String,
    val key_type: String,
    val slot_identifier: String,
    val friends_device: String,
    val created_on: String,
    val expired_by: String,
    val certificate: String,
    val kts_signature: String,
    val immobilizer_token: String,
    val status: Int,
    val sharing_method: String,
    val user_name: String,
    val user_email: String
)

data class FriendsListResponse(
    val error: Boolean,
    val statusCode: Int,
    val data: List<FriendsList>
)

//Permissions Screen
data class FriendPermission(
    val id: Int,
    val permission_name: String
)

data class FriendPermissionResponse(
    val error: Boolean,
    val statusCode: Int,
    val data: List<FriendPermission>
)

data class SendFriendPermissionRequest(
    val vehicle_id: String,
    val key_type: String,
    val user_permissions: String
)

data class SendFriendPermissionResponse(
    val status: Boolean,
    val message: String,
    val statusCode: Int,
    val data: List<SendPermissionList>
)

data class SendPermissionList(
    val fieldCount: Int,
    val affectedRows: Int,
    val insertId: Int,
    val info: Int,
    val serverStatus: Int,
    val warningStatus: Int,
    val changedRows: Int

)

