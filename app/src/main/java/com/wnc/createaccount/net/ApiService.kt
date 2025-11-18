package com.wnc.createaccount.net

import com.wnc.createaccount.models.LinkVinRequest
import com.wnc.createaccount.models.LinkVinResponse
import com.wnc.createaccount.models.SignInRequest
import com.wnc.createaccount.models.SignInResponse
import com.wnc.createaccount.models.SignupRequest
import com.wnc.createaccount.models.SignupResponse
import com.wnc.createaccount.models.UserVehiclesResponse
import com.wnc.createaccount.models.VinApiResponse
import com.wnc.createaccount.models.VinDataResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path

interface ApiService {
    @POST("/profile/v1/sign-up")
    suspend fun signUp(@Body body: SignupRequest): Response<SignupResponse>

    @POST("/profile/v1/sign-in")
    suspend fun signIn(@Body body: SignInRequest): Response<SignInResponse>

    @GET("landing/v1/vin-data/{vin}")
    suspend fun getVinData(@Path("vin") vin: String): Response<VinApiResponse>

    @POST("landing/v1/link-vin-user")
    suspend fun linkVinUser(@Header("Authorization") auth: String,
                            @Body body: LinkVinRequest): Response<LinkVinResponse>

    @GET("landing/v1/vin-data/{vin}")
    suspend fun getVinData(
        @Header("Authorization") auth: String,
        @Path("vin") vin: String
    ): retrofit2.Response<VinDataResponse>

    @GET("landing/v1/users/{userId}")
    suspend fun getUserVehicles(
        @Header("Authorization") auth: String,
        @Path("userId") userId: String?
    ): Response<UserVehiclesResponse>

    @GET("landing/v1/user-vin/{userId}/{vin}")
    suspend fun getUserVin(
        @Header("Authorization") auth: String,
        @Path("userId") userId: String?,
        @Path("vin") vin: String
    ): retrofit2.Response<UserVehiclesResponse>
}
