package com.wnc.createaccount.service

import android.annotation.SuppressLint
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import kotlin.concurrent.thread

class PassiveEntryService : Service() {
    private val CCC_DK_SERVICE_UUID = UUID.fromString("0000FFF5-0000-1000-8000-00805F9B34FB")
    private val TAG = "PassiveEntry"
    private val LE_PSM: Int = 0x0080
    private val PASSIVE_ENTRY_DEVICE = "KeyFob-1234"   // name or address of fob
    private val PASSIVE_RSSI_THRESHOLD = -65           // dBm; tweak for your range

    private lateinit var bluetoothAdapter: BluetoothAdapter
    private var scanning = false
    private val handler = Handler(Looper.getMainLooper())

    private val scannerCallback = @SuppressLint("MissingPermission")
    object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            val rssi = result.rssi
            Log.d(TAG, "Scan: ${device.address}  RSSI:$rssi")

            // Check if this is our fob and within range
            if ((device.name == PASSIVE_ENTRY_DEVICE || device.address == PASSIVE_ENTRY_DEVICE)
                && rssi > PASSIVE_RSSI_THRESHOLD
            ) {
                Log.i(TAG, "Passive entry candidate found, stopping scan…")
                stopScan()
                autoConnect(device)
            }
        }
    }


    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = manager.adapter
        startScan()
    }

    override fun onBind(intent: Intent?): IBinder? = null


    // inside PassiveEntryService (replace previous startScan())
    @SuppressLint("MissingPermission")
    private fun startScan() {
        if (scanning) return
        val scanner = bluetoothAdapter.bluetoothLeScanner

        // Build a scan filter that looks for the CCC_DK service UUID
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(CCC_DK_SERVICE_UUID))
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanner.startScan(listOf(filter), settings, scannerCallback)
        scanning = true
        Log.d(TAG, "Passive entry scanning started (filtering CCC_DK UUID)")
        handler.postDelayed({ stopScan(); startScan() }, 30_000)
    }


    @SuppressLint("MissingPermission")
    private fun stopScan() {
        if (!scanning) return
        bluetoothAdapter.bluetoothLeScanner.stopScan(scannerCallback)
        scanning = false
    }

    @SuppressLint("MissingPermission")
    private fun autoConnect(device: BluetoothDevice) {
        // Ensure bonding for encryption
        if (device.bondState == BluetoothDevice.BOND_NONE) {
            Log.d(TAG, "Creating bond for passive entry")
            device.createBond()
        }
        // After bonding, connect GATT and open L2CAP channel
        device.connectGatt(this, false, gattCallback)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "Passive entry GATT connected")
                // L2CAP CoC
                openL2capChannel(gatt.device)
                onPassiveEntryUnlock()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                gatt.close()
                Log.i(TAG, "Passive entry GATT disconnected, restart scan")
                startScan()
            }
        }
    }

    /** Existing L2CAP CoC helper */
    @SuppressLint("MissingPermission", "NewApi")
    private fun openL2capChannel(device: BluetoothDevice) {
        thread {
            try {
                val socket = device.createL2capChannel(LE_PSM)
                socket.connect()
                val input = socket.inputStream
                val output = socket.outputStream
                Log.i(TAG, "L2CAP channel open for passive entry")
                // TODO: read/write data as needed
            } catch (e: Exception) {
                Log.e(TAG, "L2CAP open failed: ${e.message}")
            }
        }
    }

    /** Action when fob is near enough and connected */
    private fun onPassiveEntryUnlock() {
        Log.i(TAG, ">>> Passive Entry Triggered: Unlock car door <<<")
        // Integrate with car unlock logic, CAN command, etc.
    }
}