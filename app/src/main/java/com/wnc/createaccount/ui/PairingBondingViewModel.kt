package com.wnc.createaccount.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wnc.createaccount.models.VinDataItem
import com.wnc.createaccount.net.ApiClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import retrofit2.HttpException

data class VinUiState(
    val loading: Boolean = false,
    val data: VinDataItem? = null,
    val error: String? = null
)

class PairingBondingViewModel : ViewModel() {
    private val _ui = MutableStateFlow(VinUiState())
    val ui: StateFlow<VinUiState> = _ui

    fun loadVin(authToken: String, vin: String) {
        _ui.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            try {
                val resp = ApiClient.api.getVinData("Bearer $authToken", vin)
                if (resp.isSuccessful) {
                    val body = resp.body()
                    val item = body?.response?.firstOrNull()
                    _ui.update { it.copy(loading = false, data = item, error = null) }
                } else {
                    _ui.update { it.copy(loading = false, error = "VIN lookup failed (${resp.code()})") }
                }
            } catch (e: HttpException) {
                _ui.update { it.copy(loading = false, error = "Network error (${e.code()})") }
            } catch (_: Exception) {
                _ui.update { it.copy(loading = false, error = "Something went wrong") }
            }
        }
    }
}
