package com.wnc.createaccount

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.wnc.createaccount.databinding.FragmentProfileBinding

class ProfileFragment : Fragment() {

    private var _binding: FragmentProfileBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Same SharedPreferences used in LandingFragment
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val name = sp.getString("name", "User")
        val email = sp.getString("email", "user@example.com")

        // Header greeting
        binding.tvUserName.text = name ?: "User"

        // Profile card content
        binding.tvProfileName.text = name ?: "User"
        binding.tvProfileEmail.text = email ?: "user@example.com"

        // ---- Click Listeners ----

        // Logout
        binding.rowLogout.setOnClickListener {
            // Clear basic auth data (adjust as needed)
            sp.edit()
                .remove("jwt")
                .remove("userId")
                .remove("last_vin")
                .remove("last_vehicle_json")
                .remove("name")
                .remove("email")
                .apply()

            Toast.makeText(requireContext(), "Logged out", Toast.LENGTH_SHORT).show()

            // TODO: Navigate to SignUpFragment or LoginFragment if you want:
            // parentFragmentManager.beginTransaction()
            //     .replace(R.id.fragment_container, SignUpFragment())
            //     .addToBackStack(null)
            //     .commit()
        }

        // Change Email
        binding.rowChangeEmail.setOnClickListener {
            Toast.makeText(requireContext(), "Change Email clicked", Toast.LENGTH_SHORT).show()
            // TODO: open ChangeEmailFragment or show dialog
        }

        // Change Password
        binding.rowChangePassword.setOnClickListener {
            Toast.makeText(requireContext(), "Change Password clicked", Toast.LENGTH_SHORT).show()
            // TODO: open ChangePasswordFragment or show dialog
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}
