package com.wnc.createaccount.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wnc.createaccount.util.PairingStore
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.wnc.createaccount.HomeFragment
import com.wnc.createaccount.KeyFragment
import com.wnc.createaccount.PairingActivity
import com.wnc.createaccount.ProfileFragment
import com.wnc.createaccount.R
import com.wnc.createaccount.ShareFragment
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

class PairingKeyExchangeFragment : Fragment() {

    companion object { private const val TAG = "PairingKeyExchangeFrag" }

    private val vm: PairingBondingViewModel by viewModels()
    private var successDialog: android.app.Dialog? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_pairing_key_exchange, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Pairing started
        PairingStore.setPending(requireContext(), false)
        PairingStore.setConnected(requireContext(), true)

        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val token = sp.getString("jwt", null)
        val vin   = sp.getString("last_vin", null)
        if (token.isNullOrBlank() || vin.isNullOrBlank()) {
            Toast.makeText(requireContext(), "Missing session or VIN. Please add a vehicle.", Toast.LENGTH_LONG).show()
            Log.w(TAG, "token or vin null. token=${!token.isNullOrBlank()} vin=$vin")
            return
        }

        view.findViewById<TextView?>(R.id.tvVin)?.text = vin

        vm.loadVin(token, vin)

        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.ui.collect { s ->
                    s.error?.let {
//                        PairingStore.setPending(requireContext(), false)    // <-- ADD (failure path)
//                        PairingStore.setConnected(requireContext(), false)   // <-- ADD
                        Toast.makeText(requireContext(), it, Toast.LENGTH_LONG).show()
                        Log.e(TAG, it)
                    }
                    s.data?.let { item ->
                        view.findViewById<TextView?>(R.id.tvVehicleName)?.text = item.make
                        view.findViewById<TextView?>(R.id.tvVehicleDetails)?.text =
                            "${item.make} ${item.model} · ${item.year}"

                        val json = JSONObject().apply {
                            put("vehicle_id", item.vehicle_id)
                            put("vin", item.vin)
                            put("make", item.make)
                            put("model", item.model)
                            put("year", item.year)
                            put("image_url", item.image_url)
                            put("created_at", item.created_at)
                        }.toString()
                        sp.edit().putString("last_vehicle_json", json).apply()
                    }
                }
            }
        }



        // ✅ Open the Pairing *Fragment* (not Activity)
//        view.findViewById<Button>(R.id.btnStartPairing)?.setOnClickListener {
//            parentFragmentManager.commit {
//                setReorderingAllowed(true)
//                replace(R.id.nav_host_fragment, PairingBondingKeyFragment())
//                addToBackStack("pairing-flow")
//            }
//
//            // when pairing completes in PairingBondingKeyFragment,
//            // call (from there) (requireActivity() as? YourCallback)?.onPairingSuccess()
//            // For now, if you want to show immediately for test:
//            showPairingSuccessDialog()
//        }
        lifecycleScope.launch {
            delay(3500)
            if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
                navigateToPairingBondingKey()
            }
        }
    }

    private fun navigateToPairingBondingKey() {
        if (!isAdded) return
        parentFragmentManager.commit {
            setReorderingAllowed(true)
            replace(R.id.fragment_container, PairingBondingKeyFragment())
            addToBackStack("pairing_bonding_key")
        }
    }


    /** Call this when the key-exchange/pairing succeeds */
    fun showPairingSuccessDialog() {
        if (!isAdded) return

        val act = requireActivity() // better for window attributes
        successDialog = android.app.Dialog(act).apply {
            requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
            setContentView(R.layout.fragment_success_dialog)
            setCancelable(true)
            setCanceledOnTouchOutside(false)

            window?.apply {
                setBackgroundDrawable(android.graphics.drawable.ColorDrawable(android.graphics.Color.TRANSPARENT))
                val lp = android.view.WindowManager.LayoutParams()
                lp.copyFrom(attributes)
                lp.width = (resources.displayMetrics.widthPixels * 0.9f).toInt()
                attributes = lp
            }

            // Make sure the ID matches your dialog layout
            findViewById<View?>(R.id.btnConfirmOtp)?.setOnClickListener {
                PairingStore.setPending(context, false)
                PairingStore.setConnected(context, true)
                dismiss()
                if (this@PairingKeyExchangeFragment.isAdded) navigateToLanding()
            }
        }

        successDialog?.show()

        // ✅ Auto-dismiss correctly after a short delay
        viewLifecycleOwner.lifecycleScope.launch {
            kotlinx.coroutines.delay(5500)
            if (isAdded) {
                // If it’s still showing, dismiss and navigate
                if (successDialog?.isShowing == true) {
                    PairingStore.setPending(requireContext(), false)   // <-- ADD
                    PairingStore.setConnected(requireContext(), true)  // <-- ADD
                    successDialog?.dismiss()
                }
                navigateToLanding()
            }
        }
    }

    /** Replace the current stack with LandingFragment so back doesn’t return here */
    private fun navigateToLanding() {
        // Find the container that currently hosts this fragment
        val containerId = (view?.parent as? ViewGroup)?.id ?: this.id

        val fm = requireActivity().supportFragmentManager
        fm.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
        fm.commit {
            setReorderingAllowed(true)
            replace(containerId, LandingFragment())
        }
    }


    override fun onDestroyView() {
        successDialog?.dismiss()
        successDialog = null
        super.onDestroyView()
    }
}


