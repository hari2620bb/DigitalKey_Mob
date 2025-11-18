package com.wnc.createaccount.ui

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.util.Patterns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.wnc.createaccount.MainActivity
import com.wnc.createaccount.R
import com.wnc.createaccount.util.JwtUtils
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class LoginFragment : Fragment() {

    companion object { private const val TAG = "LoginFragment" }

    private val vm: LoginViewModel by activityViewModels()
    private var loginCollectJob: Job? = null  // short-lived collector per click

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_login, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        Log.i(TAG, "onViewCreated()")

        val tilEmail = view.findViewById<TextInputLayout>(R.id.til_email)
        val tilPassword = view.findViewById<TextInputLayout>(R.id.til_password)
        val etEmail = view.findViewById<TextInputEditText>(R.id.et_email)
        val etPassword = view.findViewById<TextInputEditText>(R.id.et_password)
        val btnSignIn = view.findViewById<MaterialButton>(R.id.btn_sign_in)
        val tvSignUp = view.findViewById<TextView>(R.id.tv_signup)

        fun setBusy(busy: Boolean) {
            btnSignIn.isEnabled = !busy
            btnSignIn.alpha = if (busy) 0.6f else 1f
            btnSignIn.text = if (busy) "Signing in…" else "Sign In"
        }

        // Navigate to SignUpFragment
        tvSignUp.setOnClickListener {
            Log.i(TAG, "SignUp tapped → navigating to SignUpFragment")
            (requireActivity() as MainActivity).openSignUpFragment()
        }

        btnSignIn.setOnClickListener {
            val email = etEmail.text?.toString()?.trim().orEmpty()
            val password = etPassword.text?.toString().orEmpty()

            var ok = true
            if (email.isBlank() || !Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                tilEmail.error = "Enter a valid email"
                ok = false
            } else tilEmail.error = null

            if (password.length < 8) {
                tilPassword.error = "Password must be at least 8 characters"
                ok = false
            } else tilPassword.error = null

            if (!ok) {
                Log.w(TAG, "Validation failed")
                return@setOnClickListener
            }

            Log.i(TAG, "Submitting login for $email")
            setBusy(true)

            // fire the request
            vm.signIn(email, password)

            // cancel any previous short-lived collector for prior clicks
            loginCollectJob?.cancel()

            // collect ONLY for this attempt; cancel after success/error
            loginCollectJob = viewLifecycleOwner.lifecycleScope.launch {
                vm.ui.collect { s ->
                    Log.d(TAG, "State: loading=${s.loading}, success=${s.successMessage}, error=${s.errorMessage}")

                    if (!s.loading) {
                        setBusy(false)
                    }

                    s.errorMessage?.let { msg ->
                        Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
                        Log.e(TAG, "Login error: $msg")
                        this.cancel() // stop collecting after handling terminal state
                    }

                    s.successMessage?.let { msg ->
                        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
                        Log.i(TAG, "Login success: $msg")

                        s.token?.let { token ->
                            saveAuth(token) // save token + claims, incl. userId
                            Log.d(TAG, "Auth saved to SharedPreferences")
                        }

                        (requireActivity() as MainActivity).openAddVehicleFragment()
                        this.cancel() // stop collecting after navigation
                    }
                }
            }
        }
    }

    private fun saveAuth(token: String) {
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val payload = JwtUtils.decodePayload(token)
        val userId = payload?.optString("userId")?.takeIf { it.isNotBlank() }
        val email  = payload?.optString("email")
        val name   = payload?.optString("name")
        val phone  = payload?.optString("phone_number")
        val ccode  = payload?.optString("country_code")
        val iat    = payload?.optLong("iat") ?: 0L
        val exp    = payload?.optLong("exp") ?: 0L

        sp.edit()
            .putString("jwt", token)
            .putString("userId", userId)
            .putString("email", email)
            .putString("name", name)
            .putString("phone_number", phone)
            .putString("country_code", ccode)
            .putLong("iat", iat)
            .putLong("exp", exp)
            .apply()

        if (userId == null) {
            Log.w(TAG, "JWT saved but userId missing in payload")
        } else {
            Log.d(TAG, "Saved userId=$userId, exp=$exp")
        }
    }
}
