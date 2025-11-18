package com.wnc.createaccount.data

import com.google.gson.Gson
import com.wnc.createaccount.models.SignupRequest
import com.wnc.createaccount.models.SignupResponse
import com.wnc.createaccount.net.ApiClient
import com.wnc.createaccount.net.ApiService
import okhttp3.ResponseBody

sealed class SignUpResult {
    data class Success(val data: SignupResponse): SignUpResult()
    data class Error(val code: Int?, val message: String): SignUpResult()
}

class SignUpRepository(
    private val api: ApiService = ApiClient.api,
    private val gson: Gson = Gson()
) {
    suspend fun signUp(req: SignupRequest): SignUpResult {
        return try {
            val resp = api.signUp(req)
            if (resp.isSuccessful) {
                resp.body()?.let { SignUpResult.Success(it) }
                    ?: SignUpResult.Error(resp.code(), "Empty response")
            } else {
                val msg = parseError(resp.errorBody()) ?: "HTTP ${resp.code()}"
                SignUpResult.Error(resp.code(), msg)
            }
        } catch (e: Exception) {
            SignUpResult.Error(null, e.localizedMessage ?: "Network error")
        }
    }

    private fun parseError(errorBody: ResponseBody?): String? = try {
        errorBody?.charStream()?.use { reader ->
            gson.fromJson(reader, SignupResponse::class.java)?.message
        }
    } catch (_: Exception) { null }
}
