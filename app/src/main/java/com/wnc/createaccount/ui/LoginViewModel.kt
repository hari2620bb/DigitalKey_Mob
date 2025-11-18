package com.wnc.createaccount.ui

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wnc.createaccount.net.ApiClient
import com.wnc.createaccount.models.SignInRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject
import retrofit2.HttpException

data class LoginUiState(
    val loading: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    val token: String? = null
)

class LoginViewModel : ViewModel() {
    companion object { private const val TAG = "LoginVM" }

    val ui = MutableStateFlow(LoginUiState())

    fun signIn(email: String, password: String) {
        viewModelScope.launch {
            ui.update { it.copy(loading = true, errorMessage = null, successMessage = null) }
            try {
                Log.d(TAG, "signIn request: $email")
                val resp = ApiClient.api.signIn(SignInRequest(email, password))
                if (resp.isSuccessful) {
                    val body = resp.body()
                    if (body?.status == true) {
                        val token = body.data?.token
                        Log.i(TAG, "signIn success, token present=${!token.isNullOrBlank()}")
                        ui.update {
                            it.copy(
                                loading = false,
                                successMessage = body.message,
                                token = token
                            )
                        }
                    } else {
                        ui.update {
                            it.copy(
                                loading = false,
                                errorMessage = body?.message ?: "Login failed."
                            )
                        }
                    }
                } else {
                    val errorText = resp.errorBody()?.string()
                    val msg = try {
                        JSONObject(errorText ?: "").optString("message").ifBlank { "Login failed (${resp.code()})" }
                    } catch (_: Exception) {
                        "Login failed (${resp.code()})"
                    }
                    Log.w(TAG, "HTTP error ${resp.code()}: $msg")
                    ui.update { it.copy(loading = false, errorMessage = msg) }
                }
            } catch (e: HttpException) {
                Log.e(TAG, "HttpException ${e.code()}", e)
                ui.update { it.copy(loading = false, errorMessage = "Network error (${e.code()})") }
            } catch (e: Exception) {
                Log.e(TAG, "Exception during signIn", e)
                ui.update { it.copy(loading = false, errorMessage = "Something went wrong") }
            }
        }
    }
}
