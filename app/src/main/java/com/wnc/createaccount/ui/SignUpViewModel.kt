package com.wnc.createaccount.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wnc.createaccount.data.SignUpRepository
import com.wnc.createaccount.data.SignUpResult
import com.wnc.createaccount.models.SignupRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class SignUpUiState(
    val loading: Boolean = false,
    val successMessage: String? = null,
    val errorMessage: String? = null
)

class SignUpViewModel(
    private val repo: SignUpRepository = SignUpRepository()
) : ViewModel() {

    private val _ui = MutableStateFlow(SignUpUiState())
    val ui: StateFlow<SignUpUiState> = _ui

    fun submit(
        name: String,
        countryCode: String,
        phone: String,
        email: String,
        password: String,
        onSuccess: (String?) -> Unit,
        onError: (String?) -> Unit
    ) {
        _ui.value = SignUpUiState(loading = true)
        viewModelScope.launch {
            when (val result = repo.signUp(
                SignupRequest(name, countryCode, phone, email, password)
            )) {
                is SignUpResult.Success -> {
                    _ui.value = SignUpUiState(loading = false, successMessage = result.data.message)
                    onSuccess(result.data.message)
                }
                is SignUpResult.Error -> {
                    _ui.value = SignUpUiState(loading = false, errorMessage = result.message)
                    onError(result.message)
                }
            }
        }
    }

}
