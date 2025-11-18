package com.wnc.createaccount.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.wnc.createaccount.MainActivity
import com.wnc.createaccount.databinding.FragmentSignUpBinding

class SignUpFragment : Fragment() {

    private val vm: SignUpViewModel by activityViewModels()
    private var _binding: FragmentSignUpBinding? = null
    private val binding get() = _binding!!  // Safe property delegate

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        // ✅ Correct binding inflation
        _binding = FragmentSignUpBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val tvCountryCode = "+91"

        binding.btnCreateAccount.setOnClickListener {
            val name = binding.etName.text?.toString()?.trim().orEmpty()
            val phone = binding.etPhone.text?.toString()?.trim().orEmpty()
            val email = binding.etEmail.text?.toString()?.trim().orEmpty()
            val password = binding.etPassword.text?.toString().orEmpty()

            // Input validation
            when {
                name.isEmpty() -> { binding.etName.error = "Required"; return@setOnClickListener }
                phone.isEmpty() -> { binding.etPhone.error = "Required"; return@setOnClickListener }
                email.isEmpty() -> { binding.etEmail.error = "Required"; return@setOnClickListener }
                password.isEmpty() -> { binding.etPassword.error = "Required"; return@setOnClickListener }
            }

            setBusy(true)
            vm.submit(
                name, tvCountryCode, phone, email, password,
                onSuccess = { msg ->
                    setBusy(false)
                    Toast.makeText(
                        requireContext(),
                        msg ?: "Account created successfully!",
                        Toast.LENGTH_LONG
                    ).show()
                    (requireActivity() as MainActivity).openLoginFragment()
                },
                onError = { err ->
                    setBusy(false)
                    Toast.makeText(
                        requireContext(),
                        err ?: "Failed to create account.",
                        Toast.LENGTH_LONG
                    ).show()
                }
            )
        }

        binding.tvLoginLink.setOnClickListener {
            (requireActivity() as MainActivity).openLoginFragment()
        }
    }

    private fun setBusy(busy: Boolean) {
        binding.btnCreateAccount.isEnabled = !busy
        binding.btnCreateAccount.alpha = if (busy) 0.6f else 1f
        binding.btnCreateAccount.text = if (busy) "Creating..." else "Create Account"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
