package com.wnc.createaccount

import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.text.InputFilter
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wnc.createaccount.databinding.FragmentPairingBondingBinding
import com.wnc.createaccount.service.PassiveEntryService
import com.wnc.createaccount.ui.DigitalKeyDevice
import com.wnc.createaccount.ui.PairingBondingKeyFragment
import com.wnc.createaccount.ui.PairingBondingViewModel
import com.wnc.createaccount.ui.ScanResultListener
import com.wnc.createaccount.ui.VehiclePeripheral
import com.wnc.createaccount.utils.BleUtils
import kotlinx.coroutines.delay

import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlin.getValue

private const val ARG_PARAM1 = "param1"
private const val ARG_PARAM2 = "param2"

class HomeFragment : Fragment(R.layout.fragment_pairing_bonding) {
    companion object { const val TAG = "PairingBondingFragment" }

    private val vm: PairingBondingViewModel by viewModels()

    private lateinit var dkDevice: DigitalKeyDevice
    private var selectedAddress: String? = null
    private var vehiclePeripheral: VehiclePeripheral? = null

//    private val bondStateReceiver = object : BroadcastReceiver() {
//        override fun onReceive(context: Context, intent: Intent) {
//            if (intent.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
//            val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE) ?: return
//            val st = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)
//            if (st == BluetoothDevice.BOND_BONDED && dev.address == selectedAddress) {
//                updateStatus("Bonded with ${dev.address} → opening L2CAP…")
//                dkDevice.openDynamicL2capChannel(dev.address)
//            }
//        }
//    }
//
//    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
//        inflater.inflate(R.layout.fragment_pairing_bonding, container, false)
//
//    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
//        super.onViewCreated(view, savedInstanceState)
//
//        // Session + VIN
//        val sp = requireContext().getSharedPreferences("auth", Context.MODE_PRIVATE)
//        val token = sp.getString("jwt", null)
//        val vin   = sp.getString("last_vin", null)
//        if (token.isNullOrBlank() || vin.isNullOrBlank()) {
//            Toast.makeText(requireContext(), "Missing session or VIN. Please add a vehicle.", Toast.LENGTH_LONG).show()
//            Log.w(TAG, "token or vin null. token=${!token.isNullOrBlank()} vin=$vin")
//            return
//        }
//        view.findViewById<TextView?>(R.id.tvVin)?.text = vin
//
//        // Load vehicle meta
//        vm.loadVin(token, vin)
//        viewLifecycleOwner.lifecycleScope.launch {
//            repeatOnLifecycle(Lifecycle.State.STARTED) {
//                vm.ui.collect { s ->
//                    s.error?.let { Toast.makeText(requireContext(), it, Toast.LENGTH_LONG).show(); Log.e(TAG, it) }
//                    s.data?.let { item ->
//                        view.findViewById<TextView?>(R.id.tvVehicleName)?.text = item.make
//                        view.findViewById<TextView?>(R.id.tvVehicleDetails)?.text = "${item.make} ${item.model} · ${item.year}"
//                        sp.edit().putString("last_vehicle_json", JSONObject().apply {
//                            put("vehicle_id", item.vehicle_id); put("vin", item.vin)
//                            put("make", item.make); put("model", item.model)
//                            put("year", item.year); put("image_url", item.image_url)
//                            put("created_at", item.created_at)
//                        }.toString()).apply()
//                    }
//                }
//            }
//        }
//
//        // BLE init
//        if (BleUtils.allPermissionsGranted(requireContext())) {
//            startPassiveEntryService()
//            vehiclePeripheral = VehiclePeripheral(requireContext()).also { it.start(); updateStatus("Advertising vehicle") }
//        } else {
//            BleUtils.requestPermissions(requireActivity(), 101)
//        }
//
//        dkDevice = DigitalKeyDevice(
//            requireContext(),
//            { log -> Log.d(TAG, log) },
//            onOwnerPairingRequested = { address ->
//                requireActivity().runOnUiThread {
//                    selectedAddress = address
//                    promptOwnerPin(address)
//                    updateStatus("Owner pairing requested by $address (enter PIN)")
//                }
//            }
//        )
//
////        dkDevice.onL2capOpened = { addr ->
////            requireActivity().runOnUiThread {
////                updateStatus("L2CAP opened for $addr → sending APDUs…")
////                runApduSequence(addr)
////            }
////        }
//
//        dkDevice.scanResultListener = object : ScanResultListener {
//            override fun onFirstDeviceFound(address: String) {
//                requireActivity().runOnUiThread {
//                    selectedAddress = address
//                    updateStatus("Vehicle found: $address (connecting…)")
//                    view.findViewById<TextView?>(R.id.tvVehicleDetails)?.append("\n$address")
//                }
//            }
//        }
//
//        dkDevice.registerReceivers()
//        requireActivity().registerReceiver(bondStateReceiver, IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED))
//
//        // The button you wanted to “migrate” → start the Share & Bond flow
//        view.findViewById<Button?>(R.id.btnStartPairing)?.setOnClickListener {
//            if (!BleUtils.allPermissionsGranted(requireContext())) {
//                BleUtils.requestPermissions(requireActivity(), 0); return@setOnClickListener
//            }
//            updateStatus("Starting Share & Bond flow: scanning…")
//            dkDevice.bleEventHandler(AppEvent.SHELL_START_DISCOVERY_OP_COMMAND)
//        }
//    }
//
//    private fun startPassiveEntryService() {
//        requireContext().startService(Intent(requireContext(), PassiveEntryService::class.java))
//    }
//
//    private fun promptOwnerPin(address: String) {
//        val input = EditText(requireContext()).apply {
//            hint = "Enter Owner PIN"; filters = arrayOf(InputFilter.LengthFilter(16))
//        }
//        AlertDialog.Builder(requireContext())
//            .setTitle("Owner Pairing")
//            .setMessage("Enter Owner PIN for $address")
//            .setView(input)
//            .setPositiveButton("OK") { _, _ ->
//                val pin = input.text?.toString()?.trim().orEmpty()
//                if (pin.isNotEmpty()) dkDevice.setOwnerPin(address, pin)
//            }
//            .setNegativeButton("Cancel", null)
//            .show()
//    }
//
//    private fun runApduSequence(addr: String) {
//        viewLifecycleOwner.lifecycleScope.launch {
//            try {
//                updateStatus("Sending SELECT (no AID)…")
//                dkDevice.sendSelectNoAid(addr)
//                delay(150)
//
//                updateStatus("Sending SELECT AID…")
//                dkDevice.sendSelectAid(addr, dkDevice.hexStringToByteArray("A000000809434343444B467631"))
//                delay(200)
//
//                updateStatus("Sending SPAKE2+ REQUEST…")
//                dkDevice.sendSpake2Request(
//                    addr,
//                    spakeVer = 0x01.toByte() to 0x00.toByte(),
//                    dkProto = byteArrayOf(0x01, 0x02),
//                    scryptSalt = ByteArray(16) { 0x00 },
//                    nScrypt = 10_000, r = 8, p = 1, brand = 0x1234
//                )
//                delay(250)
//
//                val ownerInfo = dkDevice.getOwnerPin(addr)?.toByteArray() ?: ByteArray(4) { 0x00 }
//                updateStatus("Sending Owner Pairing (request)…")
//                dkDevice.sendOwnerPairingTest(addr, simulateNxp = false, ownerInfo = ownerInfo)
//                delay(250)
//
//                updateStatus("APDU sequence sent. Awaiting responses…")
//            } catch (t: Throwable) {
//                updateStatus("Flow error: ${t.message}")
//            }
//        }
//    }
//
//    private fun updateStatus(status: String) {
//        Log.d(TAG, "Status: $status")
//        view?.findViewById<TextView?>(R.id.tvVehicleStatus)?.text = "Status: $status"
//    }
//
//    override fun onDestroyView() {
//        super.onDestroyView()
//        kotlin.runCatching { requireActivity().unregisterReceiver(bondStateReceiver) }
//        dkDevice.disconnectAllDevices()
//        dkDevice.unregisterReceivers()
//        vehiclePeripheral?.stop()
//        vehiclePeripheral = null
//    }

}
