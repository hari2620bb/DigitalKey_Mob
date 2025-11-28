package com.wnc.createaccount

import android.content.Context
import android.os.Bundle
import android.text.TextUtils
import android.util.Patterns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.wnc.createaccount.databinding.FragmentShareBinding

class ShareFragment : Fragment() {

    private var _binding: FragmentShareBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentShareBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Get user name from same "auth" prefs used in LandingFragment
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val nameFromPrefs = sp.getString("name", null)

        // Header name
        if (!nameFromPrefs.isNullOrBlank()) {
            binding.tvUserName.text = nameFromPrefs
        }

        // Title (optional, but explicit)
        binding.tvShareTitle.text = "Share"

        // Submit button click
        binding.btnSubmit.setOnClickListener {
            handleSubmitClick()
        }

        // Permissions Switches (just to show some behavior)
        binding.swDoors.setOnCheckedChangeListener { _, isChecked ->
            toast(
                if (isChecked) "Doors permission enabled for this friend"
                else "Doors permission disabled for this friend"
            )
        }

        binding.swEngine.setOnCheckedChangeListener { _, isChecked ->
            toast(
                if (isChecked) "Engine permission enabled for this friend"
                else "Engine permission disabled for this friend"
            )
        }
    }

    private fun handleSubmitClick() {
        val friendName = binding.etFriendName.text?.toString()?.trim().orEmpty()
        val friendEmail = binding.etFriendEmail.text?.toString()?.trim().orEmpty()

        // Name validation
        if (friendName.isEmpty()) {
            binding.etFriendName.error = "Please enter friend's name"
            binding.etFriendName.requestFocus()
            return
        }

        // Email validation
        if (friendEmail.isEmpty()) {
            binding.etFriendEmail.error = "Please enter friend's email"
            binding.etFriendEmail.requestFocus()
            return
        }

        if (!isValidEmail(friendEmail)) {
            binding.etFriendEmail.error = "Please enter a valid email"
            binding.etFriendEmail.requestFocus()
            return
        }

        // TODO: call your backend here to share the digital key
        // Example:
        // viewLifecycleOwner.lifecycleScope.launch {
        //      ApiClient.api.shareKey("Bearer $jwt", userId, friendName, friendEmail, ...)
        // }

        toast("Digital key invite sent to $friendName <$friendEmail>")
    }

    private fun isValidEmail(email: String): Boolean {
        return !TextUtils.isEmpty(email) &&
                Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }

    private fun toast(msg: String) {
        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}
