package com.wnc.createaccount.ui

import android.content.Context
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.wnc.createaccount.MainActivity
import com.wnc.createaccount.R
import kotlinx.coroutines.launch
import java.util.Locale
import com.wnc.createaccount.util.PairingStore


class AddVehicleFragment : Fragment() {

    companion object {
        private const val TAG = "AddVehicleFragment"
        // VIN: 17 chars, excludes I,O,Q
        private val VIN_REGEX = Regex("^[A-HJ-NPR-Z0-9]{17}$", RegexOption.IGNORE_CASE)

        fun isValidVin(vin: String): Boolean {
            val normalized = vin.trim().uppercase()
            return VIN_REGEX.matches(normalized)
        }
    }

    private val vm: AddVehicleViewModel by viewModels()
    private var cachedExistingVins: Set<String> = emptySet()   // always UPPERCASE, non-null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        inflater.inflate(R.layout.fragment_add_vehicle, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)


        val etVin = view.findViewById<EditText>(R.id.et_vin)
        val btnScan = view.findViewById<MaterialButton>(R.id.btn_scan_vin)
        val btnSubmit = view.findViewById<MaterialButton>(R.id.btn_submit_vin)

        // 1) Resolve user & token right away, and load  existing vehicles
        val userId = resolveUserId(requireContext())
        val token  = resolveJwt(requireContext())
        if (!userId.isNullOrBlank() && !token.isNullOrBlank()) {
            vm.loadUserVehicles(authToken = token, userId = userId)
        }

        if (PairingStore.isConnected(requireContext())) {
            // optional toast for clarity
             Toast.makeText(requireContext(), "Already paired — opening Dashboard", Toast.LENGTH_SHORT).show()

            // If you have a helper in your activity:
            (requireActivity() as MainActivity).openLandingFragment()
            return
        }

        // VIN uppercase + show/hide submit
        etVin.addTextChangedListener(object : TextWatcher {
            private var editing = false
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (editing) return
                editing = true
                val up = s?.toString()?.uppercase(Locale.US).orEmpty()
                if (up != s?.toString()) {
                    etVin.setText(up)
                    etVin.setSelection(up.length)
                }
                btnSubmit.visibility = if (up.length == 17) View.VISIBLE else View.GONE
                editing = false
            }
        })

        btnScan.setOnClickListener {
            Toast.makeText(requireContext(), "Scan flow coming soon.", Toast.LENGTH_SHORT).show()
        }

        // Submit VIN → if already linked, skip POST; else link via API
        btnSubmit.setOnClickListener {
            val vin = etVin.text?.toString()?.trim()?.uppercase(Locale.US).orEmpty()
            if (!VIN_REGEX.matches(vin)) {
                etVin.error = "VIN must be 17 characters (no I, O, Q)"
                return@setOnClickListener
            }

            val uid = userId ?: run {
                Toast.makeText(requireContext(), "User not available. Please sign in again.", Toast.LENGTH_LONG).show()
                Log.w(TAG, "Missing userId — cannot link VIN")
                return@setOnClickListener
            }
            val jwt = token ?: run {
                Toast.makeText(requireContext(), "Session expired. Please sign in.", Toast.LENGTH_LONG).show()
                Log.w(TAG, "Missing jwt — cannot link VIN")
                return@setOnClickListener
            }

            // If this VIN already belongs to the user, treat as success (no POST)
            if (cachedExistingVins.contains(vin)) {
                persistLastVin(vin)
                Toast.makeText(requireContext(), "VIN already linked to your account.", Toast.LENGTH_LONG).show()
                (requireActivity() as MainActivity).openLandingFragment()
                return@setOnClickListener
            }

            setBusy(btnSubmit, true, "Submit")
            btnScan.isEnabled = false
            btnScan.alpha = 0.5f

            vm.linkVin(userId = uid, vin = vin, role = "owner", authToken = jwt)
        }

        // Observe state (existing VINs + link result)
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.ui.collect { s ->
                    // Loading state (for submit button only)
                    if (!s.loading) {
                        setBusy(btnSubmit, false, "Submit")
                        btnScan.isEnabled = true
                        btnScan.alpha = 1f
                    }

                    // 3a) Existing VINs → null-safe cache + optional prefill
                    if (s.existingVehicles.isNotEmpty()) {
                        cachedExistingVins = s.existingVehicles
                            .mapNotNull { it.vin?.trim()?.uppercase(Locale.US) } // ← null-safe
                            .toSet()

                        // Prefill with first non-null VIN if field empty (user just opened screen)
                        if (etVin.text?.isEmpty() == true) {
                            val firstVin = s.existingVehicles
                                .firstOrNull { !it.vin.isNullOrBlank() }
                                ?.vin?.trim()?.uppercase(Locale.US)
                            if (!firstVin.isNullOrEmpty()) {
                                etVin.setText(firstVin)
                                etVin.setSelection(firstVin.length)
                                Toast.makeText(
                                    requireContext(),
                                    "We found ${s.existingVehicles.size} vehicle(s) already linked. You can use the existing VIN or enter a new one.",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }
                    }

                    // 3b) Link result
                    s.errorMessage?.let {
                        Toast.makeText(requireContext(), it, Toast.LENGTH_LONG).show()
                        Log.e(TAG, "Link VIN error: $it")
                    }
                    s.successMessage?.let {
                        Toast.makeText(requireContext(), it, Toast.LENGTH_LONG).show()
                        Log.i(TAG, "Link VIN success: $it")
                        val vin = view.findViewById<EditText>(R.id.et_vin).text?.toString().orEmpty()
                        persistLastVin(vin)
                        (requireActivity() as MainActivity).openLandingFragment()
                    }
                }
            }
        }
    }

    private fun persistLastVin(vin: String) {
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        sp.edit().putString("last_vin", vin).apply()
    }

    private fun resolveUserId(context: Context): String? =
        context.getSharedPreferences("auth", Context.MODE_PRIVATE).getString("userId", null)

    private fun resolveJwt(context: Context): String? =
        context.getSharedPreferences("auth", Context.MODE_PRIVATE).getString("jwt", null)

    private fun setBusy(button: MaterialButton, busy: Boolean, idleText: String) {
        if (busy) {
            button.isEnabled = false
            button.alpha = 0.6f
            button.text = "Submitting…"
        } else {
            button.isEnabled = true
            button.alpha = 1f
            button.text = idleText
        }
    }
}
