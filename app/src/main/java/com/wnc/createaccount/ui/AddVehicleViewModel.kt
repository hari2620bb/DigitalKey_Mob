package com.wnc.createaccount.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wnc.createaccount.net.ApiClient
import com.wnc.createaccount.models.LinkVinRequest
import com.wnc.createaccount.models.LinkVinResponse
import com.wnc.createaccount.models.UserVehicleItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class LinkVinUiState(
    val loading: Boolean = false,
    val successMessage: String? = null,
    val errorMessage: String? = null,
    val existingVehicles: List<UserVehicleItem> = emptyList()   // ⬅️ NEW
)

class AddVehicleViewModel : ViewModel() {
    private val _ui = MutableStateFlow(LinkVinUiState())
    val ui: StateFlow<LinkVinUiState> = _ui

    fun loadUserVehicles(authToken: String, userId: String) {
        _ui.update { it.copy(loading = true, errorMessage = null) }
        viewModelScope.launch {
            try {
                val resp = ApiClient.api.getUserVehicles("Bearer $authToken", userId)
                if (resp.isSuccessful) {
                    val body = resp.body()
                    val list = body?.response ?: emptyList()
                    _ui.update { it.copy(loading = false, existingVehicles = list) }
                } else {
                    _ui.update { it.copy(loading = false) } // keep silent; UI can still link
                }
            } catch (_: Exception) {
                _ui.update { it.copy(loading = false) } // keep silent; UI can still link
            }
        }
    }

    fun linkVin(userId: String, vin: String, role: String = "owner", authToken: String) {
        _ui.value = _ui.value.copy(loading = true, errorMessage = null, successMessage = null)
        viewModelScope.launch {
            try {
                val resp = ApiClient.api.linkVinUser("Bearer $authToken", LinkVinRequest(userId, vin, role))
                if (resp.isSuccessful) {
                    val body: LinkVinResponse? = resp.body()
                    if (body?.status == true && body.statusCode in 200..299) {
                        _ui.update { it.copy(loading = false, successMessage = body.message) }
                    } else {
                        _ui.update { it.copy(loading = false, errorMessage = body?.message ?: "Link VIN failed.") }
                    }
                } else {
                    val msg = resp.errorBody()?.string()
                        ?.let { runCatching { org.json.JSONObject(it).optString("message") }.getOrNull() }
                        ?.ifBlank { null } ?: "Link VIN failed (${resp.code()})"
                    _ui.update { it.copy(loading = false, errorMessage = msg) }
                }
            } catch (e: retrofit2.HttpException) {
                _ui.update { it.copy(loading = false, errorMessage = "Network error (${e.code()})") }
            } catch (_: Exception) {
                _ui.update { it.copy(loading = false, errorMessage = "Something went wrong") }
            }
        }
    }
}
