package com.wnc.createaccount.ui

import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wnc.createaccount.R
import com.wnc.createaccount.util.PairingStore
import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlin.getValue


class PairingBondingKeyFragment : Fragment() {



    companion object {
        private const val TAG = "PairingBondingKeyFragment"
        private const val ARG_VIN = "arg_vin"



        fun newInstance(vin: String?): PairingBondingKeyFragment {
            val f = PairingBondingKeyFragment()
            f.arguments = Bundle().apply { putString(ARG_VIN, vin) }
            return f
        }
    }

    private val vm: PairingBondingViewModel by viewModels()
    private var successDialog: android.app.Dialog? = null

    private var vinArg: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vinArg = arguments?.getString(ARG_VIN)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_pairing_bonding_key, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        PairingStore.setPending(requireContext(), true)       // <-- ADD
        PairingStore.setConnected(requireContext(), false)    // <-- ADD

        // ---- Read saved auth + VIN ----
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val token = sp.getString("jwt", null)
        val vin   = sp.getString("last_vin", null)

        if (token.isNullOrBlank() || vin.isNullOrBlank()) {
            Toast.makeText(requireContext(), "Missing session or VIN. Please add a vehicle.", Toast.LENGTH_LONG).show()
            Log.w(TAG, "token or vin null. token=${!token.isNullOrBlank()} vin=$vin")
            return
        }

        // Optional header VIN
        view.findViewById<TextView?>(R.id.tvVin)?.text = vin

        // ---- Fetch VIN data ----
        vm.loadVin(token, vin)

        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.ui.collect { s ->
                    s.error?.let {
                        PairingStore.setPending(requireContext(), false)    // <-- ADD (failure path)
                        PairingStore.setConnected(requireContext(), false)   // <-- ADD
                        Toast.makeText(requireContext(), it, Toast.LENGTH_LONG).show()
                        Log.e(PairingBondingKeyFragment.Companion.TAG, it)
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


        val et1 = view.findViewById<EditText>(R.id.etOtp1)
        val et2 = view.findViewById<EditText>(R.id.etOtp2)
        val et3 = view.findViewById<EditText>(R.id.etOtp3)
        val et4 = view.findViewById<EditText>(R.id.etOtp4)
        val et5 = view.findViewById<EditText>(R.id.etOtp5)
        val et6 = view.findViewById<EditText>(R.id.etOtp6)
        val btn = view.findViewById<View>(R.id.btnConfirmOtp)

        // Optional UX: auto-advance between OTP boxes
        fun EditText.afterDigitMoveNext(next: EditText?) {
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    if (s?.length == 1) next?.requestFocus()
                }
                override fun afterTextChanged(s: Editable?) {}
            })
        }
        et1.afterDigitMoveNext(et2)
        et2.afterDigitMoveNext(et3)
        et3.afterDigitMoveNext(et4)
        et4.afterDigitMoveNext(et5)
        et5.afterDigitMoveNext(et6)

        btn.setOnClickListener {
            // Debounce to avoid double navigation
            it.isEnabled = false

            val otp = listOf(et1, et2, et3, et4, et5, et6)
                .joinToString("") { edt -> edt.text.toString().trim() }

            if (otp.length != 6) {
                Toast.makeText(requireContext(), "Enter 6-digit OTP", Toast.LENGTH_SHORT).show()
                it.isEnabled = true
                return@setOnClickListener
            }

            PairingStore.setPending(requireContext(), false)
            PairingStore.setConnected(requireContext(), true)

            // TODO: validate OTP with server here if needed.
            goToPairingKeyExchange(vinArg)
        }

    }
//    private fun onOtpSuccess() {
//        // pairing completed
//        PairingStore.setPending(requireContext(), false)
//        PairingStore.setConnected(requireContext(), true)
//
//        // Show success dialog then navigate to Landing
//        showPairingSuccessDialog()
//    }

    private fun goToPairingKeyExchange(vin: String?) {
        val appCtx = requireContext().applicationContext
        PairingStore.setPending(appCtx, false)
        PairingStore.setConnected(appCtx, true)

        // Show success dialog and then navigate to Landing
        showPairingSuccessDialog()
    }

    fun showPairingSuccessDialog() {
        if (!isAdded) return

        val act = requireActivity()
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

            // Button → just navigate (flags already set)
            findViewById<View?>(R.id.btnConfirmOtp)?.setOnClickListener {
                dismiss()
                if (this@PairingBondingKeyFragment.isAdded) navigateToLanding()
            }

            // Back/cancel → still go to Landing
            setOnCancelListener {
                if (this@PairingBondingKeyFragment.isAdded) navigateToLanding()
            }
            setOnDismissListener {
                if (this@PairingBondingKeyFragment.isAdded) navigateToLanding()
            }
        }

        successDialog?.show()

        // Auto-dismiss (optional)
        viewLifecycleOwner.lifecycleScope.launch {
            kotlinx.coroutines.delay(1500)
            if (isAdded && successDialog?.isShowing == true) {
                successDialog?.dismiss() // onDismiss navigates
            }
        }
    }

    private fun navigateToLanding() {
        if (!isAdded) return
        val fm = requireActivity().supportFragmentManager
        fm.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
        fm.commit {
            setReorderingAllowed(true)
            // Use your Activity’s stable container
            replace(R.id.fragment_container, LandingFragment())
        }
    }

    override fun onDestroyView() {
        successDialog?.dismiss()
        successDialog = null
        super.onDestroyView()
    }


}
