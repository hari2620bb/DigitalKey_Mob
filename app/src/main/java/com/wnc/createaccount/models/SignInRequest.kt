package com.wnc.createaccount.models

data class SignInRequest(
    val email: String,
    val password: String
)

data class SignInResponse(
    val status: Boolean,
    val message: String,
    val statusCode: Int,
    val data: TokenWrapper?
)

data class TokenWrapper(
    val token: String
)