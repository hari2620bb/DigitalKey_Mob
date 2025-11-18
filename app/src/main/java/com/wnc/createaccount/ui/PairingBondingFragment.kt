package com.wnc.createaccount.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.content.*
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Looper
import android.text.InputFilter
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
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
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

class PairingBondingFragment : Fragment(R.layout.fragment_pairing_bonding) {

    private var _binding: FragmentPairingBondingBinding? = null
    private val binding get() = _binding!!

    private lateinit var dkDevice: DigitalKeyDevice
    private var selectedAddress: String? = null

    // flag to avoid double navigation / cleanup
    private var flowCompleted = false

    // ---------- UI helper (always main thread safe) ----------
    private fun setStatusSafe(text: String) {
        Log.d("PairBond", text)

        if (!isAdded) return
        val tv = _binding?.tvVehicleStatus ?: return

        if (Looper.myLooper() == Looper.getMainLooper()) {
            tv.text = text
        } else {
            tv.post { _binding?.tvVehicleStatus?.text = text }
        }

        FileLogger.writeLog(requireContext(), text)
    }

    private fun step(label: String, done: Boolean = false) {
        val statusText = if (done) {
            "✅ $label completed"
        } else {
            "➡️ $label in progress…"
        }
        setStatusSafe(statusText)
    }

    private fun log(msg: String) {
        Log.d("PairBond", msg)
        FileLogger.writeLog(requireContext(), msg)

        val keywords = listOf(
            "Scanning", "Device found", "Bonded", "Paired",
            "L2CAP", "SPAKE", "SELECT", "Completed", "Flow"
        )

        if (keywords.any { msg.contains(it, ignoreCase = true) }) {
            setStatusSafe(msg)
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
                BluetoothDevice.BOND_BONDING -> {
                    PairingStore.setPending(requireContext(), true)
                    PairingStore.setConnected(requireContext(), false)
                    step("Bonding")
                }
                BluetoothDevice.BOND_BONDED -> {
                    step("Bonded", done = true)
                    log("Bonded: ${dev.address} → will open L2CAP automatically")
                    dkDevice.openDynamicL2capChannel(dev.address)
                }
            }
        }
    }

    // ---------- Lifecycle ----------
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        _binding = FragmentPairingBondingBinding.bind(view)
        super.onViewCreated(view, savedInstanceState)

        renderVehicleHeaderFromPrefs()

        PairingStore.setPending(requireContext(), false)
        PairingStore.setConnected(requireContext(), false)

        // Permissions
        if (!BleUtils.allPermissionsGranted(requireContext())) {
            BleUtils.requestPermissions(requireActivity() as Activity, 101)
        } else startPassiveEntryService()

        // Initialize DigitalKeyDevice
        dkDevice = DigitalKeyDevice(
            requireContext(),
            logCb = { m -> log(m) }, // no extra runOnUiThread, setStatusSafe already hops
            onOwnerPairingRequested = { addr ->
                requireActivity().runOnUiThread {
                    selectedAddress = addr
                    step("ownerPairing")
                    promptOwnerPin(addr)
                }
            }
        )

        // Scan listener
        dkDevice.scanResultListener = object : ScanResultListener {
            override fun onFirstDeviceFound(address: String) {
                requireActivity().runOnUiThread {
                    selectedAddress = address
                    binding.tvVehicleDetails.text = "Vehicle: $address"
                    step("Found", done = true)
                }
                dkDevice.bleEventHandler(AppEvent.SHELL_STOP_DISCOVERY_COMMAND)
                dkDevice.connectToAddress(address)
            }
        }

        // Register receivers
        dkDevice.registerReceivers()
        registerOrderedPairingReceiver()
        requireActivity().registerReceiver(bondReceiver, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))

        dkDevice.onL2capOpened = { addr ->
            requireActivity().runOnUiThread {
                step("L2CAP open", done = true)
                runFullSequence(addr)
            }
        }
        dkDevice.onOpControlFlowCompleted = { addr ->
            requireActivity().runOnUiThread {
                step("OP_CONTROL_FLOW", done = true)
                markFlowCompleteUi()
                cleanupBle()
                navigateToPairingKeyExchange()
            }
        }

        // Start Pairing & Bonding
        binding.btnShareBond.setOnClickListener {
            if (!BleUtils.allPermissionsGranted(requireContext())) {
                BleUtils.requestPermissions(requireActivity() as Activity, 101)
                return@setOnClickListener
            }

            // Prevent double-tap
            binding.btnShareBond.isEnabled = false
            binding.btnShareBond.alpha = 0.5f

            flowCompleted = false
            PairingStore.setPending(requireContext(), true)
            PairingStore.setConnected(requireContext(), false)

            binding.tvVehicleStatus.text = ""
            binding.tvVehicleDetails.text = ""
            selectedAddress = null

            step("Scanning")
            dkDevice.bleEventHandler(AppEvent.SHELL_START_DISCOVERY_OP_COMMAND)
        }

        // Continue only after flow is done
        binding.btnContinue.setOnClickListener {
            if (!flowCompleted) return@setOnClickListener
            cleanupBle()
            navigateToPairingKeyExchange()
        }

        binding.btnViewLogs.setOnClickListener {
            showLogFile()
        }
    }

    override fun onDestroyView() {
        cleanupBle()
        _binding = null
        super.onDestroyView()
    }

    // ---------- Flow / BLE helpers ----------

    private fun cleanupBle() {
        runCatching { requireActivity().unregisterReceiver(pairingReceiver) }
        runCatching { requireActivity().unregisterReceiver(bondReceiver) }
        runCatching { dkDevice.disconnectAllDevices() }
        runCatching { dkDevice.unregisterReceivers() }
    }

    private fun markFlowCompleteUi() {
        if (flowCompleted || !isAdded) return
        flowCompleted = true

        PairingStore.setPending(requireContext(), false)
        PairingStore.setConnected(requireContext(), true)

        setStatusSafe("✅ Flow complete: Scan → Found → Bonded → L2CAP → OwnerPairing → SELECT → SPAKE → AUTH0/AUTH1")

        binding.btnShareBond.isEnabled = false
        binding.btnShareBond.alpha = 0.5f
        binding.btnContinue.visibility = View.VISIBLE
    }

    /** Runs OwnerPairing/SELECT/SPAKE etc after L2CAP is ready */
    private fun runFullSequence(addr: String) {
        viewLifecycleOwner.lifecycleScope.launch(Dispatchers.IO) {
            try {
                // These logical "steps" are just for UI
                step("OwnerPairing")
                dkDevice.sendOwnerPairingTest(addr, simulateNxp = true)
                delay(200)
                step("OwnerPairing", done = true)

                step("SELECT")
                delay(200)
                step("SELECT", done = true)

                step("SPAKE")
                delay(200)
                step("SPAKE", done = true)

                // BLE flow continues in DigitalKeyDevice via logCb etc.
                withContext(Dispatchers.Main) {
                    if (!isAdded) return@withContext
                    markFlowCompleteUi()
                }
            } catch (t: Throwable) {
                withContext(Dispatchers.Main) {
                    if (!isAdded) return@withContext

                    PairingStore.setPending(requireContext(), false)
                    PairingStore.setConnected(requireContext(), false)

                    setStatusSafe("❌ Error: ${t.message}")

                    binding.btnShareBond.isEnabled = true
                    binding.btnShareBond.alpha = 1f
                }
                cleanupBle()
            }
        }
    }

    // ---------- Navigation ----------

    private fun navigateToPairingKeyExchange() {
        if (!isAdded) return

        // Prefer the view's parent container id (works whether fragment is hosted in activity or another fragment)
        val containerId = (view?.parent as? ViewGroup)?.id ?: run {
            // fallback to the activity's content view id
            requireActivity().findViewById<View>(android.R.id.content).id
        }

        parentFragmentManager.commit {
            setReorderingAllowed(true)
            replace(containerId, PairingKeyExchangeFragment())
            addToBackStack("pairing_key_exchange")
        }
    }


    // ---------- Vehicle header from SharedPreferences ----------

    private fun renderVehicleHeaderFromPrefs() {
        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
        val json = sp.getString("last_vehicle_json", null) ?: return

        try {
            val obj   = JSONObject(json)
            val vin   = obj.optString("vin")
            val model = obj.optString("model")
            val year  = obj.optInt("year", 0)

            binding.tvVehicleName.text =
                if (model.isNullOrBlank()) "Vehicle" else model

            binding.tvVin.text =
                if (vin.isNullOrBlank()) binding.tvVin.text else vin

            val details = buildString {
                if (!model.isNullOrBlank()) append(model)
                if (year > 0) {
                    if (isNotEmpty()) append(" ")
                    append(year)
                }
            }
            if (details.isNotEmpty()) {
                binding.tvVehicleDetails.text = details
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // ---------- Logs ----------

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

    // ---------- Services / PIN ----------

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
                else setStatusSafe("PIN empty — cancelled")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
