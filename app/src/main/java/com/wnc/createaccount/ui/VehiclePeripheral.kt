package com.wnc.createaccount.ui

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import com.wnc.createaccount.utils.DkMessageType
import com.wnc.createaccount.utils.DkSubEventCategory
import com.wnc.createaccount.utils.DkSubEventCommandCompleteType
import java.util.UUID
import kotlin.collections.contentEquals

class VehiclePeripheral(private val ctx: Context)  {
    @SuppressLint("ServiceCast")
    private val btManager = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = btManager.adapter
    private var advertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null
    private val TAG = "VehiclePeripheral"

    // reuse your UUID constants from earlier (or re-declare here)
    private val CCC_DK_SERVICE_UUID = UUID.fromString("0000FFF5-0000-1000-8000-00805F9B34FB")
    private val VEHICLE_PSM_CHAR_UUID = UUID.fromString("0000FFF6-0000-1000-8000-00805F9B34FB")
    private val ANTENNA_ID_CHAR_UUID = UUID.fromString("0000FFF7-0000-1000-8000-00805F9B34FB")
    private val TX_POWER_CHAR_UUID = UUID.fromString("00002A07-0000-1000-8000-00805F9B34FB")


    // Keep track of subscribed centrals
    private val subscribedCentrals = mutableSetOf<BluetoothDevice>()

    @SuppressLint("MissingPermission")
    fun start() {
        if (adapter == null || !adapter.isEnabled) {
            Log.d(TAG, "Bluetooth adapter not available / disabled")
            return
        }
        if (!adapter.isMultipleAdvertisementSupported) {
            Log.d(TAG, "BLE Advertising not supported on this device")
            return
        }
        advertiser = adapter.bluetoothLeAdvertiser
        startAdvertising()
        startGattServer()
        Log.i(TAG, "VehiclePeripheral started")
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        try {
            advertiser?.stopAdvertising(adCallback)
        } catch (_: Exception) {}
        try {
            gattServer?.close()
        } catch (_: Exception) {}
        subscribedCentrals.clear()
        Log.i(TAG, "VehiclePeripheral stopped")
    }

    // --- Advertising ---
    private val adCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            super.onStartSuccess(settingsInEffect)
            Log.i(TAG, "Advertise started")
        }

        override fun onStartFailure(errorCode: Int) {
            super.onStartFailure(errorCode)
            Log.d(TAG, "Advertise failed: $errorCode")
        }
    }

    @SuppressLint("MissingPermission")
    private fun startAdvertising() {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        // Put the service UUID into advertisement (service UUID list)
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(CCC_DK_SERVICE_UUID))
            .setIncludeDeviceName(true)
            .build()

        advertiser?.startAdvertising(settings, data, adCallback)
    }

    // --- GATT Server ---
    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            super.onConnectionStateChange(device, status, newState)
            device ?: return
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.i(TAG, "Central connected: ${device.address}")
                // Optionally request pair from central by sending OWNER_PAIRING_REQUEST characteristic notification
                // Don't call createBond() here for the central — the central app should trigger bonding after seeing the notification.
                sendOwnerPairingRequest(device)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.i(TAG, "Central disconnected: ${device.address}")
                subscribedCentrals.remove(device)
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            super.onServiceAdded(status, service)
            Log.i(TAG, "Service added: status=$status service=${service?.uuid}")
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            super.onDescriptorWriteRequest(device, requestId, descriptor, preparedWrite, responseNeeded, offset, value)
            if (device != null && descriptor != null) {
                // Track CCC descriptor writes (subscribe/unsubscribe)
                if (descriptor.uuid == UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")) {
                    val enabled = value?.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == true
                    if (enabled) {
                        subscribedCentrals.add(device)
                        Log.i(TAG, "Central ${device.address} subscribed to notifications")
                        // Immediately send an owner pairing request if desired
                        sendOwnerPairingRequest(device)
                    } else {
                        subscribedCentrals.remove(device)
                        Log.i(TAG, "Central ${device.address} unsubscribed")
                    }
                }
            }
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            // Handle writes from central (e.g. SPAKE messages or pairing responses)
            if (characteristic?.uuid == VEHICLE_PSM_CHAR_UUID) {
                Log.i(TAG, "Write to VEHICLE_PSM from ${device?.address} len=${value?.size ?: 0}")
                // If central sends SPAKE msg1, you may process it here (not implemented in this example)
            }
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun startGattServer() {
        gattServer = btManager.openGattServer(ctx, gattServerCallback)
        // Build DK service with PSM char + antenna + txpower
        val service =
            BluetoothGattService(CCC_DK_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        // PSM characteristic — writable by central, notifiable by server (vehicle -> central)
        val psmChar = BluetoothGattCharacteristic(
            VEHICLE_PSM_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        // add CCC descriptor so centrals can write to enable notifications (0x2902)
        val cccd = BluetoothGattDescriptor(
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"),
            BluetoothGattDescriptor.PERMISSION_WRITE
        )
        psmChar.addDescriptor(cccd)

        // antenna id char (read)
        val antennaChar = BluetoothGattCharacteristic(
            ANTENNA_ID_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        antennaChar.value = ByteArray(2) { 0x00 } // dummy antenna id

        // Tx power char (read)
        val txPowerChar = BluetoothGattCharacteristic(
            TX_POWER_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        txPowerChar.value = byteArrayOf(0x00)

        service.addCharacteristic(psmChar)
        service.addCharacteristic(antennaChar)
        service.addCharacteristic(txPowerChar)

        gattServer?.addService(service)
    }

    // --- Owner pairing notification ---
    @SuppressLint("MissingPermission")
    private fun sendOwnerPairingRequest(device: BluetoothDevice) {
        // Frame: [DK_EVENT_NOTIFICATION, COMMAND_COMPLETE, REQUEST_OWNER_PAIRING]
        val frame = byteArrayOf(
            DkMessageType.DK_EVENT_NOTIFICATION.value,
            DkSubEventCategory.COMMAND_COMPLETE.value,
            DkSubEventCommandCompleteType.REQUEST_OWNER_PAIRING.value
        )
        val service = gattServer?.getService(CCC_DK_SERVICE_UUID)
        val ch = service?.getCharacteristic(VEHICLE_PSM_CHAR_UUID)
        if (ch != null) {
            ch.value = frame
            // Notify single central (requires that central subscribed to CCCD OR you can force notify)
            val notified = gattServer?.notifyCharacteristicChanged(device, ch, false) ?: false
            Log.i(TAG, "Sent OWNER_PAIRING_REQUEST to ${device.address}, notified=$notified")
        } else {
            Log.d(TAG, "PSM char not found to notify")
        }
    }

    // Optionally broadcast to all subscribed centrals:
    @SuppressLint("MissingPermission")
    fun broadcastOwnerPairingRequestToAll() {
        val frame = byteArrayOf(
            DkMessageType.DK_EVENT_NOTIFICATION.value,
            DkSubEventCategory.COMMAND_COMPLETE.value,
            DkSubEventCommandCompleteType.REQUEST_OWNER_PAIRING.value
        )
        val service = gattServer?.getService(CCC_DK_SERVICE_UUID)
        val ch = service?.getCharacteristic(VEHICLE_PSM_CHAR_UUID) ?: return
        ch.value = frame
        for (d in subscribedCentrals) {
            val ok = gattServer?.notifyCharacteristicChanged(d, ch, false) ?: false
            Log.i(TAG, "Broadcast to ${d.address} ok=$ok")
        }
    }
}