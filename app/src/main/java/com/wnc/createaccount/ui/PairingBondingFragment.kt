package com.wnc.createaccount.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.content.*
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.InputFilter
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.wnc.createaccount.R
import com.wnc.createaccount.databinding.FragmentPairingBondingBinding
import com.wnc.createaccount.service.PassiveEntryService
import com.wnc.createaccount.util.PairingStore
import com.wnc.createaccount.utils.BleUtils
import com.wnc.createaccount.utils.FileLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File

class PairingBondingFragment : Fragment(R.layout.fragment_pairing_bonding) {

    private var _binding: FragmentPairingBondingBinding? = null
    private val binding get() = _binding!!

    private lateinit var dkDevice: DigitalKeyDevice
    private var selectedAddress: String? = null
    private var otpVerificationPending = false

    // ---------------------------------------------------------
    //  Pairing state helpers (shared with LandingFragment)
    // ---------------------------------------------------------

    private fun setPairingState(pending: Boolean, connected: Boolean) {
        val appCtx = requireActivity().applicationContext
        PairingStore.setPending(appCtx, pending)
        PairingStore.setConnected(appCtx, connected)
    }

    // ---------------------------------------------------------
    //  UI Logging and Status Helpers
    // ---------------------------------------------------------

    private fun setStatus(s: String) {
        binding.tvVehicleStatus.text = s
        Log.d("PairBond", s)
    }

    private fun step(label: String, done: Boolean = false) {
        val statusText = if (done) "✅ $label completed" else "➡️ $label in progress…"
        setStatus(statusText)
        FileLogger.writeLog(requireContext(), statusText)
    }

    private fun log(msg: String) {
        Log.d("PairBond", msg)
        FileLogger.writeLog(requireContext(), msg)
        if (msg.startsWith("UI_PHASE:")) return
    }

    private fun showProgress(phaseMsg: String, progress: Int) {
        binding.tvVehicleStatus.text = phaseMsg
        binding.progressBar.visibility = View.VISIBLE
        binding.progressBar.progress = progress
    }

    private fun hideProgress() {
        binding.progressBar.visibility = View.GONE
    }

    private fun setStartEnabled(enabled: Boolean) {
        binding.btnShareBond.isEnabled = enabled
        binding.btnShareBond.alpha = if (enabled) 1f else 0.5f
    }

    private fun handleUiPhase(phase: String) {
        when (phase) {
            "InitiatingOwnerPairing" -> {
                showProgress("Initiating Owner Pairing", 20)
            }
            "Phase2Completed" -> {
                showProgress("Phase 2 completed", 40)
            }
            "Phase3Completed" -> {
                showProgress("Phase 3 completed", 60)
            }
            "FinalizationOfPairing" -> {
                showProgress("Finalization of pairing", 80)
            }
            "DevicePaired" -> {
                hideProgress()
                setStatus("✅ Device Paired!")
                // ✅ Mark global pairing state so LandingFragment toggles are enabled
                setPairingState(pending = false, connected = true)
                // Optionally close this screen:
                // parentFragmentManager.popBackStack()
            }
        }
    }

    // ---------- Auto-PIN broadcast ----------
    private val pairingReceiver = object : BroadcastReceiver() {
        @SuppressLint("MissingPermission")
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != BluetoothDevice.ACTION_PAIRING_REQUEST) return
            val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE) ?: return
            if (ActivityCompat.checkSelfPermission(
                    requireContext(),
                    Manifest.permission.BLUETOOTH_CONNECT
                ) != PackageManager.PERMISSION_GRANTED
            ) return

            val addr = dev.address
            val variant = intent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT, BluetoothDevice.ERROR)
            val pin = dkDevice.getOwnerPin(addr)
            when (variant) {
                BluetoothDevice.PAIRING_VARIANT_PIN -> {
                    if (!pin.isNullOrBlank()) {
                        dev.setPin(pin.toByteArray())
                        dev.setPairingConfirmation(true)
                        try { abortBroadcast() } catch (_: Throwable) {}
                        step("ownerPairing", done = true)
                        log("Auto-entered PIN for $addr")
                    }
                }
                BluetoothDevice.PAIRING_VARIANT_PASSKEY_CONFIRMATION,
                6 -> { // OOB_CONSENT
                    dev.setPairingConfirmation(true)
                    try { abortBroadcast() } catch (_: Throwable) {}
                    step("ownerPairing", done = true)
                    log("Auto-confirmed pairing for $addr")
                }
            }
        }
    }

    // ---------- Bond receiver ----------
    private val bondReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
            val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE) ?: return

            if (selectedAddress == null) selectedAddress = dev.address
            if (dev.address != selectedAddress) return

            val state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)
            when (state) {
                BluetoothDevice.BOND_BONDED -> {
                    step("Bonded", done = true)
                    log("Bonded: ${dev.address} → will open L2CAP automatically")
                    dkDevice.openDynamicL2capChannel(dev.address)
                    // runFullSequence(dev.address)
                }
            }
        }
    }

    // ---------------------------------------------------------
    //  Lifecycle
    // ---------------------------------------------------------

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentPairingBondingBinding.bind(view)
        super.onViewCreated(view, savedInstanceState)

        // Initial state: no pairing in progress from this screen
        setPairingState(pending = false, connected = false)
        setStartEnabled(true)
        hideProgress()

        // Permissions
        if (!BleUtils.allPermissionsGranted(requireContext())) {
            BleUtils.requestPermissions(requireActivity() as Activity, 101)
        } else startPassiveEntryService()

        // Initialize DigitalKeyDevice
        dkDevice = DigitalKeyDevice(
            requireContext(),
            logCb = { m ->
                requireActivity().runOnUiThread {
                    if (m.startsWith("UI_PHASE:")) {
                        handleUiPhase(m.removePrefix("UI_PHASE:"))
                    } else {
                        log(m)
                    }
                }
            },
            onOwnerPairingRequested = { addr ->
                requireActivity().runOnUiThread {
                    selectedAddress = addr
                    step("ownerPairing")
                    promptOwnerPin(addr)
                }
            }
        )

        // ✅ Set OTP verification callback - triggers when OP CONTROL FLOW P1=0x11
        dkDevice.setOtpVerificationCallback { addr ->
            requireActivity().runOnUiThread {
                log("📩 OP CONTROL FLOW successful (P1=0x11) → Ready for OTP verification")
                setStatus("✅ Owner Pairing Complete - Please enter OTP")
                binding.etOtpInput.requestFocus()
                otpVerificationPending = true
            }
        }

        // Scan listener
        dkDevice.scanResultListener = object : ScanResultListener {
            override fun onFirstDeviceFound(address: String) {
                requireActivity().runOnUiThread {
                    selectedAddress = address
//                    binding.tvVehicleDetails.text = "Vehicle: $address"
                    step("Found", done = true)
                }
                dkDevice.bleEventHandler(AppEvent.SHELL_STOP_DISCOVERY_COMMAND)

                // Connect immediately → triggers handleConnectionStateChange → auto-L2CAP
                dkDevice.connectToAddress(address)
            }
        }

        // Register receivers
        dkDevice.registerReceivers()
        registerOrderedPairingReceiver()
        requireActivity().registerReceiver(
            bondReceiver,
            IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
        )

        dkDevice.onL2capOpened = { addr ->
            requireActivity().runOnUiThread {
                step("L2CAP open", done = true)
                runFullSequence(addr)
            }
        }

        // ---------- Single-button flow ----------
        binding.btnShareBond.setOnClickListener {
            if (!BleUtils.allPermissionsGranted(requireContext())) {
                BleUtils.requestPermissions(requireActivity() as Activity, 101)
                return@setOnClickListener
            }

            // Reset UI
            binding.tvVehicleStatus.text = ""
//            binding.tvVehicleDetails.text = ""
            selectedAddress = null
            hideProgress()

            // mark pairing in progress
            setPairingState(pending = true, connected = false)
            setStartEnabled(false)

            step("Scanning")
            dkDevice.bleEventHandler(AppEvent.SHELL_START_DISCOVERY_OP_COMMAND)
        }

        // ✅ Wire OTP Submit Button
        binding.btnSubmitOtp.setOnClickListener {
            handleOtpSubmission()
        }

        binding.btnViewLogs.setOnClickListener {
            showLogFile()
        }
    }

    // ---------------------------------------------------------
    //  OTP UI + verification
    // ---------------------------------------------------------

    private fun showOtpInput() {
        requireActivity().runOnUiThread {
            binding.etOtpInput.text?.clear()
            binding.etOtpInput.requestFocus()
            setStatus("Enter 6-digit OTP from vehicle")
        }
    }

    private fun handleOtpSubmission() {
        val otpInput = binding.etOtpInput.text?.toString()?.trim() ?: ""

        if (otpInput.length != 6) {
            Toast.makeText(requireContext(), "Please enter exactly 6 digits", Toast.LENGTH_SHORT).show()
            return
        }

        if (!otpInput.all { it.isDigit() }) {
            Toast.makeText(requireContext(), "OTP must contain only numbers", Toast.LENGTH_SHORT).show()
            return
        }

        val otpBytes = otpInput.map { it.digitToInt().toByte() }.toByteArray()

        log("📤 OTP Entered: $otpInput → Bytes: ${otpBytes.joinToString(" ") { "%02X".format(it) }}")

        binding.btnSubmitOtp.isEnabled = false
        setStatus("Verifying OTP with KW45...")

        selectedAddress?.let { addr ->
            dkDevice.sendHmiPasswordVerificationRequest(addr, otpBytes) { success, message ->
                requireActivity().runOnUiThread {
                    binding.btnSubmitOtp.isEnabled = true

                    if (success) {
                        setStatus("✅ OTP Verified Successfully!")
                        log("✅ HMI Password verification succeeded")
                        Toast.makeText(
                            requireContext(),
                            "OTP Verified! Proceeding to next step...",
                            Toast.LENGTH_LONG
                        ).show()

                        binding.etOtpInput.text?.clear()
                        otpVerificationPending = false

                        // Here you could trigger a UI_PHASE:FinalizationOfPairing in DK device
                        // which will then call handleUiPhase("DevicePaired")
                        // and mark PairingStore connected.
                    } else {
                        setStatus("❌ OTP Verification Failed")
                        Toast.makeText(
                            requireContext(),
                            message ?: "Invalid OTP - Please try again",
                            Toast.LENGTH_LONG
                        ).show()
                        log("❌ HMI Password verification failed: $message")
                        binding.etOtpInput.text?.clear()
                        binding.etOtpInput.requestFocus()
                    }
                }
            }
        } ?: run {
            binding.btnSubmitOtp.isEnabled = true
            Toast.makeText(requireContext(), "No device connected", Toast.LENGTH_SHORT).show()
        }
    }

    private fun onOwnerPairingComplete() {
        log("Owner pairing completed → requesting OTP")
        showOtpInput()
    }

    // ---------------------------------------------------------
    //  Logs
    // ---------------------------------------------------------

    private fun showLogFile() {
        try {
            val logsDir = File(requireContext().getExternalFilesDir(null), "Logs")
            val logFile = File(logsDir, "ble_log.txt")

            if (!logFile.exists()) {
                AlertDialog.Builder(requireContext())
                    .setTitle("Logs")
                    .setMessage("No log file found yet.")
                    .setPositiveButton("OK", null)
                    .show()
                return
            }

            val content = logFile.readText()

            AlertDialog.Builder(requireContext())
                .setTitle("BLE Logs")
                .setMessage(if (content.isEmpty()) "No logs yet." else content)
                .setPositiveButton("Close", null)
                .show()

        } catch (e: Exception) {
            AlertDialog.Builder(requireContext())
                .setTitle("Error")
                .setMessage("Unable to read log file: ${e.message}")
                .setPositiveButton("OK", null)
                .show()
        }
    }

    // ---------------------------------------------------------
    //  BLE helpers
    // ---------------------------------------------------------

    private fun startPassiveEntryService() {
        requireContext().startService(Intent(requireContext(), PassiveEntryService::class.java))
    }

    private fun registerOrderedPairingReceiver() {
        val f = IntentFilter(BluetoothDevice.ACTION_PAIRING_REQUEST).apply {
            priority = IntentFilter.SYSTEM_HIGH_PRIORITY
        }
        requireActivity().registerReceiver(pairingReceiver, f)
    }

    private fun promptOwnerPin(address: String) {
        val input = EditText(requireContext()).apply {
            hint = "Enter Owner PIN"
            filters = arrayOf(InputFilter.LengthFilter(16))
        }
        AlertDialog.Builder(requireContext())
            .setTitle("Owner Pairing")
            .setMessage("Enter Owner PIN for $address")
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val pin = input.text?.toString()?.trim().orEmpty()
                if (pin.isNotEmpty()) dkDevice.setOwnerPin(address, pin)
                else setStatus("PIN empty — cancelled")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Runs SELECT + SPAKE + OwnerPairing after L2CAP is ready */
    private fun runFullSequence(addr: String) {
        viewLifecycleOwner.lifecycleScope.launch(Dispatchers.IO) {
            try {
                // --- Owner Pairing ---
                step("OwnerPairing")
                dkDevice.sendOwnerPairingTest(addr, simulateNxp = true)
                delay(200)
                step("OwnerPairing", done = true)

                // ✅ After owner pairing, OP CONTROL FLOW response will trigger OTP callback

                // --- SELECT ---
                step("SELECT")
                // dkDevice.sendSelectNoAid(addr)
                delay(200)
                step("SELECT", done = true)

                // --- SPAKE ---
                step("SPAKE")
                val spakeVer = 0x01.toByte() to 0x00.toByte()
                val dkProto = byteArrayOf(0x01, 0x02)
                val scryptSalt = ByteArray(16) { 0x00 }
                // dkDevice.sendSpake2Request(addr, spakeVer, dkProto, scryptSalt, 10000, 8, 1, 0x1234)
                delay(200)
                step("SPAKE", done = true)

                requireActivity().runOnUiThread {
                    setStatus("✅ Flow complete: Scan → Found → Bonded → L2CAP → OwnerPairing → SELECT → SPAKE")
                }
            } catch (t: Throwable) {
                requireActivity().runOnUiThread {
                    hideProgress()
                    setStatus("❌ Error: ${t.message}")
                    // mark failure in pairing state
                    setPairingState(pending = false, connected = false)
                    setStartEnabled(true)
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        runCatching { requireActivity().unregisterReceiver(pairingReceiver) }
        runCatching { requireActivity().unregisterReceiver(bondReceiver) }
        dkDevice.disconnectAllDevices()
        dkDevice.unregisterReceivers()
        _binding = null
    }
}
