package com.wnc.createaccount.models

data class SignupRequest(
    val name: String,
    val country_code: String,
    val phone_number: String,
    val email: String,
    val password: String
)
