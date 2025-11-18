package com.wnc.createaccount.ui

import android.R.string.ok
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.digitalkey.u.model.DkMessage
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.io.output.ByteArrayOutputStream
import com.wnc.createaccount.models.DigitalKey
import com.wnc.createaccount.util.PairingStore
import com.wnc.createaccount.utils.DkMessageType
import com.wnc.createaccount.utils.DkSubEventCategory
import com.wnc.createaccount.utils.DkSubEventCommandCompleteType
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

private const val TAG = "DigitalKeyDevice"
private const val MC_ENCRYPTION_KEY_SIZE = 16
private const val SMP_EDIV = 0x1F99
private const val CHAR_READ_BUFFER_LENGTH = 256
private const val MAX_CONNECTIONS = 8
private const val INVALID_DEVICE_ID = -1
private const val SCAN_TIMEOUT_MS = 30000L
private const val CONNECTION_TIMEOUT_MS = 10000L

// // Example UUIDs – replace with your actual service/characteristics
// --- CCC DK service & characteristics (MUST match vehicle/GATT) ---
private val CCC_DK_SERVICE_UUID: UUID =
    UUID.fromString("0000FFF5-0000-1000-8000-00805F9B34FB") // service 0xFFF5

// Phone reads this (0xFFF6) to learn the LE CoC SPSM/PSM (e.g. 0x0081, big-endian)
private val VEHICLE_PSM_CHAR_UUID = UUID.fromString("d3b5a130-9e23-4b3a-8be4-6b1ee5f980a3")
private val ANTENNA_ID_CHAR_UUID = UUID.fromString("0000FFF7-0000-1000-8000-00805F9B34FB")
private val TX_POWER_CHAR_UUID = UUID.fromString("00002A07-0000-1000-8000-00805F9B34FB")

// UUID constants for the Digital Key service and SPSM characteristic
// Optional: if you use another characteristic for notifications/owner pairing signals
private val VEHICLE_CONTROL_CHAR_UUID: UUID =
    UUID.fromString("0000FFF7-0000-1000-8000-00805F9B34FB")

// ===== Application-level Pairing opcodes =====
private val PAIRING_REQUEST_CMD: Byte = 0x10
private val PAIRING_RESPONSE_CMD: Byte = 0x11
private val PAIRING_COMPLETE_CMD: Byte = 0x12

/** L2CAP PSM negotiated with the peripheral (must match ECU firmware) */
private const val LE_PSM: Int = 0x0080

enum class RangingMsgId(val value: Byte) {
    DK_APDU_RQ(0x01), DK_APDU_RS(0x02),
    FIRST_APPROACH_RQ(0x03), FIRST_APPROACH_RS(0x04),
    TIME_SYNC(0x05), DK_EVENT_NOTIFICATION(0x06)
}

enum class AppState { IDLE, EXCHANGE_MTU, SERVICE_DISC, CCC_PHASE2_WAITING_FOR_REQUEST, CCC_PHASE2_WAITING_FOR_VERIFY, CCC_WAITING_FOR_PAIRING_READY, PAIR, RUNNING }
enum class AppEvent {
    RECEIVED_SPAKE_RESPONSE, PEER_CONNECTED, PEER_DISCONNECTED, GATT_PROC_COMPLETE, GATT_PROC_ERROR, SERVICE_DISCOVERY_COMPLETE,
    SERVICE_DISCOVERY_FAILED, READ_CHARACTERISTIC_VALUE_COMPLETE, PSM_CHANNEL_CREATED, SENT_SPAKE_RESPONSE,
    RECEIVED_SPAKE_VERIFY, RECEIVED_PAIRING_READY, PAIRING_LOCAL_OOB_DATA, PAIRING_PEER_OOB_DATA_RCV,
    PAIRING_PEER_OOB_DATA_REQ, PAIRING_COMPLETE, ENCRYPTION_CHANGED, AUTHENTICATION_REJECTED,
    SHELL_RESET_COMMAND, SHELL_FACTORY_RESET_COMMAND, SHELL_START_DISCOVERY_OP_COMMAND,
    SHELL_STOP_DISCOVERY_COMMAND, SHELL_SET_BONDING_DATA_COMMAND, SHELL_LIST_BONDED_DEV_COMMAND,
    SHELL_REMOVE_BONDED_DEV_COMMAND, SHELL_DISCONNECT_COMMAND,
    KBD_EVENT_PRESS_PB1, KBD_EVENT_LONG_PB1, KBD_EVENT_VERY_LONG_PB1, RECEIVED_SPAKE_VERIFY_OK, SPAKE_VERIFY_FAILED
}

// Data classes
data class AppPeerInfo(
    var deviceId: Int = INVALID_DEVICE_ID,
    var appState: AppState = AppState.IDLE,
    var isBonded: Boolean = false,
    var customInfo: CustomInfo = CustomInfo(),
    var oobData: ByteArray? = null,
    var peerOobData: ByteArray? = null,
    var ltk: ByteArray? = null,
    var peerCurveX: ByteArray? = null,
    var myCurveY: ByteArray? = null,
    var vehicleEvidence: ByteArray? = null,   // ✅ Evidence M we send in VERIFY (Tag 0x57)
    var deviceEvidence: ByteArray? = null,

    // ✅ SPAKE2+ derived keys
    var kenc: ByteArray? = null,   // Encryption key
    var kmac: ByteArray? = null,   // Command MAC key
    var krmac: ByteArray? = null,  // Response MAC key

    // ✅ Command/response counters
    var commandCounterRequest: Int = 0,
    var commandCounterResponse: Int = 0,
    // ✅ New field for WRITE DATA TLV accumulation
    // var lastWriteDataTlvMap: MutableMap<Int, ByteArray>? = null
    var lastWriteDataTlvMap: MutableMap<Int, ByteArray>? = null,
    var lastWriteDataTlvList: MutableList<Pair<Int, ByteArray>>? = null,
    // accumulate encrypted payload across segments until final segment arrives
    var writeDataEncryptedBuffer: ByteArrayOutputStream? = null,

// optional: track whether we have seen any write-data segments in current sequence
    var writeDataInProgress: Boolean = false,
    // ✅ Add these new fields for Digital Key metadata
    var digitalKeyAlias: String? = null,       // Alias used when creating/importing DK
    var digitalKeyCreated: Boolean = false,    // True after successful DK creation
    var keySlot: ByteArray? = null,
    // Optional slot or cert ref (from WRITE DATA)
    var readyForGetData: Boolean = false,
    var createdKeyData: ByteArray? = null,

    var vehicleIdentifier: ByteArray? = null,
    var endpointName: String? = null,
    var instanceCaId: ByteArray? = null,
    var featureBitmap: ByteArray? = null,
    var protocolVersion: ByteArray? = null,
    var vehiclePk: ByteArray? = null,
    var validFrom: ByteArray? = null,
    var validTo: ByteArray? = null,
    var authorizedPks: List<ByteArray>? = null,
    var counterLimit: ByteArray? = null,
    var confMailboxSize: ByteArray? = null,
    var privMailboxSize: ByteArray? = null,
    var mailboxOffsets: Map<String, ByteArray?>? = null,
    var deviceConfig: Map<Int, List<ByteArray>>? = null,
    var endpointConfig: ByteArray? = null,
    var mailboxMappingRaw: ByteArray? = null,
    var deviceConfigRaw: ByteArray? = null,
    var vehicleCert: ByteArray? = null,
    var intermediateCert: ByteArray? = null,

    // --- AUTH0/AUTH1, Standard Transaction keys ---
    var vehicleEpk: ByteArray? = null,          // Vehicle ephemeral public key (from AUTH0, tag 0x87)
    var endpointPrivateKey: Any? = null,        // Endpoint private key (for ECDH/AUTH0/AUTH1, type: PrivateKey)
    var endpointPublicKey: Any? = null,         // Endpoint public key (for ECDH/AUTH0/AUTH1, type: PublicKey)
    var requestCounter: Int = 0,                // Incremented for each secure command (AUTH1, WRITE DATA, etc.)
    var responseCounter: Int = 0

)

data class CustomInfo(
    var hDkService: Int = 0,
    var hPsmChannelChar: Int = 0,
    var hAntennaIdChar: Int = 0,
    var hTxPowerChar: Int = 0,
    var lePsmValue: Int = 0,
    var psmChannelId: Int = 0,
    // ➕ Add this for secure connection key generation
    var longTermKey: ByteArray? = null
)

data class GattCharacteristicInfo(
    var handle: Int = 0,
    var maxValueLength: Int = 0,
    var value: ByteArray? = null
)

data class AppBondingData(
    var nvmIndex: Int = 0,
    var addrType: Int = 0,
    var aLtk: ByteArray = ByteArray(MC_ENCRYPTION_KEY_SIZE),
    var aIrk: ByteArray = ByteArray(MC_ENCRYPTION_KEY_SIZE),
    var deviceAddr: ByteArray = ByteArray(6)
)

/** Minimal mock SPAKE engine for demo. Replace with a real implementation. */
object Spake2EngineMock {
    data class Handshake(val msg1: ByteArray, val msg2ExpectedPrefix: ByteArray)

    fun start(ownerPassword: String): Handshake {
// DO NOT USE IN PRODUCTION.
        val pwBytes = ownerPassword.encodeToByteArray()
        val msg1 = ByteBuffer.allocate(
            4 +
                    pwBytes.size
        ).putInt(pwBytes.size).put(pwBytes).array()
        val expect = byteArrayOf(0x53, 0x50, 0x41, 0x4B, 0x45) // "SPAKE"
        return Handshake(msg1, expect)
    }

    fun verify(peerMsg2: ByteArray, expectedPrefix: ByteArray): Boolean =
        peerMsg2.take(expectedPrefix.size).toByteArray().contentEquals(expectedPrefix)
}

interface ScanResultListener {
    fun onFirstDeviceFound(address: String)
}


class DigitalKeyDevice(
    private val context: Context,
    private val logCb: ((String) -> Unit)? = null,
    /** Callback so UI can prompt for Owner PIN when a request is detected. */
    private val onOwnerPairingRequested: ((deviceAddress: String) -> Unit)? =
        null

) {

    companion object {
        // LTK, RAND, IRK, CSRK — example constants for dev/testing only
        private val SMP_LTK = byteArrayOf(
            0xD6.toByte(), 0x93.toByte(), 0xE8.toByte(), 0xA4.toByte(),
            0x23.toByte(), 0x55.toByte(), 0x48.toByte(), 0x99.toByte(),
            0x1D.toByte(), 0x77.toByte(), 0x61.toByte(), 0xE6.toByte(),
            0x63.toByte(), 0x2B.toByte(), 0x10.toByte(), 0x8E.toByte()
        )
        private val SMP_RAND = byteArrayOf(
            0x26.toByte(), 0x1E.toByte(), 0xF6.toByte(), 0x09.toByte(),
            0x97.toByte(), 0x2E.toByte(), 0xAD.toByte(), 0x7E.toByte()
        )
        private val SMP_IRK = ByteArray(16) { 0x0A.toByte() }
        private val SMP_CSRK = ByteArray(16) { 0x90.toByte() }
        private val DUMMY_PAYLOAD = ByteArray(16) { (it + 1).toByte() }
    }

    @SuppressLint("ServiceCast")
    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter = bluetoothManager.adapter
    private val handler = Handler(Looper.getMainLooper())

    // Peer information array
    private val maPeerInformation = Array(MAX_CONNECTIONS) { AppPeerInfo() }

    // Characteristics
    private val maCharacteristics = Array(3) { GattCharacteristicInfo() }
    private val mValVehiclePsm = ByteArray(2)
    private var mValVehicleAntennaId: Short = 0
    private var mValTxPower: Byte = 0
    private var mCurrentCharReadingIndex = 0
    private var isPairingMode = false
    // Indicates if Standard Transaction (Phase 3/4) is active
    private var isStandardTxActive = false


    var onL2capOpened: ((addr: String) -> Unit)? = null

    // Current peer ID for pairing
    private var mCurrentPeerId = INVALID_DEVICE_ID

    // Scanning and connection states
    private var mScanningOn = false
    private var mFoundDeviceToConnect = false
    private var mRestoringBondedLink = false
    var scanResultListener: ScanResultListener? = null
    private val DigitalKeyFrameworkAID = hexStringToByteArray("A000000809434343444B467631")

    // Add this near other callbacks (onL2capOpened)
    var onOpControlFlowCompleted: ((addr: String) -> Unit)? = null

    // BLE scanner and callbacks
    private var bleScanner: BluetoothLeScanner? = null
    private var scanCallback: ScanCallback? = null
    private var gattCallback: BluetoothGattCallback? = null
    private var connectedGatts = ConcurrentHashMap<String, BluetoothGatt>()

    // put this near the top of the class body
    private val l2capOutput = ConcurrentHashMap<String, OutputStream>()

    // L2CAP receive accumulators (per-address) to handle streaming / partial frames
    private val l2capRxBuffers = ConcurrentHashMap<String, ByteArrayOutputStream>()


    /** Cache Owner PIN per device so our pairing receiver can use it. */
    private val ownerPins = mutableMapOf<String, String>()
    fun setOwnerPin(deviceAddress: String, pin: String) {
        ownerPins[deviceAddress] = pin
    }

    fun getOwnerPin(deviceAddress: String): String? = ownerPins[deviceAddress]

    init {
        initializeBleComponents()
        initializePeerInformation()
        // log("INIT: DigitalKeyDevice initialized")
    }

    private fun log(msg: String) {
        Log.d(TAG, msg)  // Log to Logcat AND the UI callback so MainActivity can show it.
        logCb?.invoke(msg) // This goes straight to the TextView in MainActivity
    }

    // ==== Secure Connection Key Generation (LTK) ====
    private fun generateLTK(): ByteArray {
        val key = ByteArray(16)
        SecureRandom().nextBytes(key)
        //   log("Generated LTK: " + key.joinToString(" ") { "%02X".format(it) })
        return key
    }

    private fun initializeBleComponents() {
        bleScanner = bluetoothAdapter.bluetoothLeScanner

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val address = result.device.address

                // ✅ Notify MainActivity only once
                if (scanResultListener != null) {
                    scanResultListener?.onFirstDeviceFound(address)
                    // if you want only the first device, set listener to null after firing:
                    scanResultListener = null
                }
                handleScanResult(result)
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                for (result in results) {
                    handleScanResult(result)
                }
            }

            override fun onScanFailed(errorCode: Int) {
                //  log("Scan failed with error code: $errorCode")
                mScanningOn = false
            }
        }

        gattCallback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                handleConnectionStateChange(gatt, status, newState)
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                handleServicesDiscovered(gatt, status)
            }

            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (characteristic.uuid == VEHICLE_PSM_CHAR_UUID && status == BluetoothGatt.GATT_SUCCESS) {
                    val raw = characteristic.value
                    if (raw != null && raw.size >= 2) {
                        val psm = ByteBuffer.wrap(raw)
                            .order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF
                        log("DynamicL2cap: Got PSM=$psm – opening L2CAP channel…")
                        openL2capSocket(gatt.device, psm)
                    } else {
                        log("DynamicL2cap: Invalid SPSM data")
                    }
                    return
                }
                // existing characteristic read handler
                handleCharacteristicRead(gatt, characteristic, status)
            }


            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                handleMtuChanged(gatt, mtu, status)
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic
            ) {
                handleCharacteristicChanged(gatt, characteristic)
            }
        }
    }

    private fun initializePeerInformation() {
        for (i in maPeerInformation.indices) {
            maPeerInformation[i] = AppPeerInfo()
        }
    }

    /**
     * Public API: handle commands/events from UI / shell
     */
    fun bleEventHandler(event: AppEvent, data: Any? = null) {
        when (event) {
            AppEvent.SHELL_START_DISCOVERY_OP_COMMAND -> {
                startDiscovery()
            }

            AppEvent.SHELL_STOP_DISCOVERY_COMMAND -> stopScanning()
            AppEvent.SHELL_FACTORY_RESET_COMMAND -> factoryReset()
            AppEvent.SHELL_DISCONNECT_COMMAND -> disconnectAllDevices()
            else -> {
                // log("bleEventHandler: unhandled event $event")
            }
        }
    }


    /**
     * Scanning
     */
    fun startDiscovery() {
        if (!mScanningOn && bluetoothAdapter.isEnabled) {
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build()

            val filters = listOf(
                ScanFilter.Builder()
                    .setServiceUuid(ParcelUuid(CCC_DK_SERVICE_UUID))
                    .build()
            )
            //val filters = emptyList<ScanFilter>() // 🔹 no filter for testing

            try {
                bleScanner?.startScan(filters, settings, scanCallback)
                mScanningOn = true
                mFoundDeviceToConnect = false
                log("START_SCAN: started")

                handler.postDelayed({
                    if (mScanningOn) stopScanning()
                }, SCAN_TIMEOUT_MS)

            } catch (e: SecurityException) {
                //  log("Failed to start scan: ${e.message}")
            }
        } else {
            //  log("startDiscovery: adapter disabled or scanning already on")
        }
    }

    private fun stopScanning() {
        if (mScanningOn) {
            try {
                bleScanner?.stopScan(scanCallback)
                mScanningOn = false
                // log("STOP_SCAN: stopped")
                if (!mFoundDeviceToConnect) {
                    //  log("SCAN_FINISHED: no device found")
                }
            } catch (e: SecurityException) {
                // log("Failed to stop scan: ${e.message}")
            }
        }
    }

    private fun handleScanResult(result: ScanResult) {
        if (!mFoundDeviceToConnect) {
            val scanRecord = result.scanRecord
            if (scanRecord != null) {
                val serviceUuids = scanRecord.serviceUuids
                // notify UI for every match
                if (serviceUuids != null && serviceUuids.any { it.uuid == CCC_DK_SERVICE_UUID }) {
                    mFoundDeviceToConnect = true
                    val name = result.device.name ?: "UNKNOWN"
                    //  log("FOUND_DEVICE: $name ${result.device.address}")
                    stopScanning()
                    connectToDevice(result.device)
                } else {
                    // optionally: show all adverts
                    val name = result.device.name ?: "UNKNOWN"
                    // log("ADV_SEEN: $name ${result.device.address}")
                }
            }
        }
    }

    /**
     * Connect to device (exposed)
     */

    @SuppressLint("MissingPermission")
    fun connectToDevice(device: BluetoothDevice?) {
        if (device == null) {
            // log("connectToDevice: device is null")
            return
        }

        val address = device.address
        log("Connecting to $address")

        try {
            // Start GATT connection over LE transport
            device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)

            // 🔒 Trigger BLE bonding/pairing if not already bonded
            if (device.bondState == BluetoothDevice.BOND_NONE) {
                log("Requesting BLE bond with $address")
                device.createBond()
            } else {
                // log("Already bonded with $address")
            }

            // ⏱️ Optional: connection timeout safeguard
            handler.postDelayed({
                if (!connectedGatts.containsKey(address)) {
                    log("CONNECT_TIMEOUT for $address")
                    // You could call gatt?.disconnect() or retry here if desired
                }
            }, CONNECTION_TIMEOUT_MS)

        } catch (e: SecurityException) {
            //  log("Failed to connect: ${e.message}")
        }
    }


    // ----------------------------------------------------------------------
    //  Bond receiver — marks encryption established
    // ----------------------------------------------------------------------

    private val bondReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (BluetoothDevice.ACTION_BOND_STATE_CHANGED == intent?.action) {
                val device =
                    intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                when (intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR)) {
                    BluetoothDevice.BOND_BONDED -> {
                        val addr = device?.address ?: return
                        log("Bonded with $addr")
                        val ltk = generateLTK()

                        val id = findPeerIdByAddress(addr)
                        if (id != INVALID_DEVICE_ID) {
                            maPeerInformation[id].isBonded = true
                            maPeerInformation[id].customInfo.longTermKey = ltk
                            stateMachineHandler(id, AppEvent.ENCRYPTION_CHANGED)
                            stateMachineHandler(id, AppEvent.PAIRING_COMPLETE)
                        }
                    }
                }
            }
        }
    }

    fun registerReceivers() {
        val filter = IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
        context.registerReceiver(bondReceiver, filter)
    }

    fun unregisterReceivers() {
        context.unregisterReceiver(bondReceiver)
    }


    /**
     * Connect by address (UI helper)
     */
    fun connectToAddress(address: String) {
        bluetoothManager.getConnectedDevices(BluetoothProfile.GATT)
        val dev = bluetoothAdapter.bondedDevices.firstOrNull { it.address == address }
        if (dev != null) {
            connectToDevice(dev)
        } else {
            // Try to get remote device
            val remote = bluetoothAdapter.getRemoteDevice(address)
            connectToDevice(remote)
        }
    }

    // ----------------------------------------------------------------------
    //  New Pairing-Frame helpers
    // ----------------------------------------------------------------------

    private fun buildPairingRequestFrame(ownerInfo: ByteArray): ByteArray {
        val bb = ByteBuffer.allocate(2 + ownerInfo.size)
        bb.put(DkMessageType.FRAMEWORK_MESSAGE.value)
        bb.put(PAIRING_REQUEST_CMD)
        bb.put(ownerInfo)
        return bb.array()
    }

    private fun buildPairingResponseFrame(resp: ByteArray): ByteArray {
        val bb = ByteBuffer.allocate(2 + resp.size)
        bb.put(DkMessageType.FRAMEWORK_MESSAGE.value)
        bb.put(PAIRING_RESPONSE_CMD)
        bb.put(resp)
        return bb.array()
    }

    @SuppressLint("MissingPermission")
    private fun sendPairingRequestOverGatt(gatt: BluetoothGatt, ownerInfo: ByteArray): Boolean {
        val svc = gatt.getService(CCC_DK_SERVICE_UUID) ?: return false.also {
            //  log("Pairing: DK service not found")
        }
        val ch = svc.getCharacteristic(VEHICLE_PSM_CHAR_UUID) ?: return false.also {
            //  log("Pairing: VEHICLE_PSM_CHAR not found")
        }
        val frame = buildPairingRequestFrame(ownerInfo)
        ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        ch.value = frame
        val ok = gatt.writeCharacteristic(ch)
        // log("Pairing: sent PairingRequest ok=$ok len=${frame.size}")
        return ok
    }

    @SuppressLint("MissingPermission")
    private fun sendPairingResponseOverGatt(gatt: BluetoothGatt, resp: ByteArray): Boolean {
        val svc = gatt.getService(CCC_DK_SERVICE_UUID) ?: return false
        val ch = svc.getCharacteristic(VEHICLE_PSM_CHAR_UUID) ?: return false
        val frame = buildPairingResponseFrame(resp)
        ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        ch.value = frame
        val ok = gatt.writeCharacteristic(ch)
        // log("Pairing: sent PairingResponse ok=$ok len=${frame.size}")
        return ok
    }


    private fun handleConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
        val deviceAddress = gatt.device.address
        when (newState) {
            BluetoothProfile.STATE_CONNECTED -> {
                log("GATT_CONNECTED: $deviceAddress")
// Save the GATT instance
                // ✅ Step 1: check if this is a bonded reconnection (encrypted link)
                val isBonded = gatt.device.bondState == BluetoothDevice.BOND_BONDED
                if (isBonded) {
                    log("Encrypted bonded link detected → will open L2CAP after short delay")
                }

                // ✅ Step 2: existing logic
                connectedGatts[deviceAddress] = gatt
                val peerDeviceId = findAvailablePeerId()
                if (peerDeviceId != INVALID_DEVICE_ID) {
                    val peerInfo = maPeerInformation[peerDeviceId]
                    peerInfo.deviceId = peerDeviceId
                    peerInfo.isBonded = checkIfBonded(deviceAddress)
                    if (peerInfo.isBonded) {
                        mRestoringBondedLink = true
                    }
                    peerInfo.appState = AppState.EXCHANGE_MTU
                    stateMachineHandler(peerDeviceId, AppEvent.PEER_CONNECTED)
                    gatt.requestMtu(512)
                } else {
                    log("No available peer slot")
                }

                gatt.discoverServices()
            }

            BluetoothProfile.STATE_DISCONNECTED -> {
                log("GATT_DISCONNECTED: $deviceAddress")
                connectedGatts.remove(deviceAddress)
                val peerDeviceId = findPeerIdByAddress(deviceAddress)
                if (peerDeviceId != INVALID_DEVICE_ID) {
                    stateMachineHandler(peerDeviceId, AppEvent.PEER_DISCONNECTED)
                }
                gatt.close()
            }
        }
        log("GATT state changed for $deviceAddress : $newState (status=$status)")
    }


    private fun handleMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
        log("MTU_CHANGED: mtu=$mtu status=$status for ${gatt.device.address}")
        val peerDeviceId = findPeerIdByAddress(gatt.device.address)
        if (peerDeviceId != INVALID_DEVICE_ID) {
            stateMachineHandler(peerDeviceId, AppEvent.GATT_PROC_COMPLETE)
        }
    }

    private fun handleServicesDiscovered(gatt: BluetoothGatt, status: Int) {
        if (status == BluetoothGatt.GATT_SUCCESS) {
            log("SERVICES_DISCOVERED: ${gatt.device.address}")
            val peerDeviceId = findPeerIdByAddress(gatt.device.address)
            if (peerDeviceId != INVALID_DEVICE_ID) {
                storeServiceHandles(peerDeviceId, gatt)
                stateMachineHandler(peerDeviceId, AppEvent.SERVICE_DISCOVERY_COMPLETE)
            }
            // ✅ Services are ready → now it’s safe to read SPSM and open CoC
            //openDynamicL2capChannel(gatt.device.address)
        } else {
            log("SERVICE_DISCOVERY_FAILED: status=$status")
            val peerDeviceId = findPeerIdByAddress(gatt.device.address)
            if (peerDeviceId != INVALID_DEVICE_ID) {
                stateMachineHandler(peerDeviceId, AppEvent.SERVICE_DISCOVERY_FAILED)
            }
        }
    }


    /**
     * Called when a full DK frame has been parsed from L2CAP.
     * Integrate with your state machine / pairing logic here.
     */


    @OptIn(ExperimentalStdlibApi::class)
    private fun handleDkMessage(addr: String, msg: DkMessage) {
        log(
            "📩 [FROM KW45 → PHONE] L2CAP RX [$addr]: " +
                    "msgHdr=0x${msg.messageHeader.toUByte().toString(16)}, " +
                    "payloadHdr=0x${msg.payloadHeader.toUByte().toString(16)}, " +
                    "len=${msg.payload.size}"
        )

        when (msg.payloadHeader) {
            //with ccc
            0x11.toByte() -> {
                log("📩 [FROM KW45] CCC DK Event Notification received (0x11)")
                handleDkEventNotification(addr, msg.payload)
            }

            // ---------- Pairing Response ----------
            PAIRING_RESPONSE_CMD -> {
                log("Pairing: received PairingResponse via L2CAP from $addr")
                val resp = msg.payload
                val id = findPeerIdByAddress(addr)
                if (id != INVALID_DEVICE_ID) {
                    maPeerInformation[id].peerOobData = resp
                    stateMachineHandler(id, AppEvent.RECEIVED_SPAKE_VERIFY)
                }
            }

            // ---------- Pairing Complete ----------
            PAIRING_COMPLETE_CMD -> {
                log("Pairing: received PairingComplete via L2CAP from $addr")
                val id = findPeerIdByAddress(addr)
                if (id != INVALID_DEVICE_ID) {
                    stateMachineHandler(id, AppEvent.PAIRING_COMPLETE)
                }
            }


            0x0B.toByte() -> {
                val apdu = msg.payload
                log(
                    "📥 [FROM KW45] DK_APDU_RQ received → payload=${
                        apdu.joinToString(" ") {
                            "%02X".format(
                                it
                            )
                        }
                    }"
                )

                val peerDeviceId = findPeerIdByAddress(addr)
                if (peerDeviceId == INVALID_DEVICE_ID) {
                    log("⚠️ Peer not found for $addr → ignoring DK_APDU_RQ")
                    return
                }

                // --- SELECT Command Detection ---
//                if (apdu.size >= 5 &&
//                    apdu[0] == 0x00.toByte() && // CLA = 00
//                    apdu[1] == 0xA4.toByte() && // INS = A4 (SELECT)
//                    apdu[2] == 0x04.toByte() &&
//                    apdu[3] == 0x00.toByte()
//                ) {
//                    val lc = apdu[4].toInt() and 0xFF
//                    val aid =
//                        if (apdu.size >= 5 + lc) apdu.sliceArray(5 until (5 + lc)) else byteArrayOf()
//
//                    // log("✅ SELECT APDU detected → AID=${aid.joinToString(" ") { "%02X".format(it) }}")
//
//                    if (aid.contentEquals(DigitalKeyFrameworkAID)) {
//                        log("🔹 Recognized Digital Key Framework AID → sending SELECT response")
//                        sendSelectResponseAid(addr, msg.messageHeader)
//
//                        isPairingMode = true
//                        // log("🔹 Phone is now in PAIRING MODE for $addr")
//                    } else {
//                        log("⚠️ Unknown AID received: ${aid.joinToString(" ") { "%02X".format(it) }} → ignoring")
//                    }
//                    return
//                }

                // --- SELECT Command Detection (Handles both Pairing & Standard Transaction) ---
                if (apdu.size >= 5 &&
                    apdu[0] == 0x00.toByte() &&       // CLA = 00 (ISO7816 command)
                    apdu[1] == 0xA4.toByte()          // INS = A4 (SELECT)
                ) {
                    val p1 = apdu[2]
                    val p2 = apdu[3]
                    val lc = apdu[4].toInt() and 0xFF
                    val aid = if (apdu.size >= 5 + lc) apdu.sliceArray(5 until (5 + lc)) else byteArrayOf()

                    log(
                        "📥 [FROM KW45] SELECT command received → " +
                                "P1=${"%02X".format(p1)}, P2=${"%02X".format(p2)}, " +
                                "AID=${if (aid.isNotEmpty()) aid.joinToString(" ") { "%02X".format(it) } else "none"}"
                    )

                    when {
                        // Phase 1/2: Digital Key Framework AID SELECT (used during pairing)
                        (p1 == 0x04.toByte() && p2 == 0x00.toByte()) -> {
                            if (aid.contentEquals(DigitalKeyFrameworkAID)) {
                                log("🔹 Recognized Digital Key Framework AID → sending SELECT response for Pairing Mode")
                                sendSelectResponseAid(addr, msg.messageHeader)
                                isPairingMode = true
                            } else {
                                log("⚠️ Unknown AID received for Framework SELECT: ${aid.joinToString(" ") { "%02X".format(it) }} → ignoring")
                            }
                        }

                        // Phase 3/4: Standard Transaction SELECT (used during mutual authentication)
                        (p1 == 0x01.toByte() && p2 == 0x00.toByte()) -> {
                            log("🔹 SELECT for Standard Transaction detected → sending Standard Tx SELECT response")
                            sendSelectResponseForStandardTx(addr, msg.messageHeader)
                            // ✅ Trigger AUTH0 after SELECT (Phase 3 Start)
                            // ✅ CORRECT - Phone now waits for vehicle to send AUTH0
                            isStandardTxActive = true


                        }

                        else -> {
                            log("⚠️ Unknown SELECT parameters (P1=${"%02X".format(p1)}, P2=${"%02X".format(p2)}) → ignoring")
                        }
                    }
                    return
                }


                // --- ✅ SPAKE2+ REQUEST Detection (CLA=0x80, INS=0x30) ---

                if (apdu.size >= 4 &&
                    apdu[0] == 0x80.toByte() &&  // CLA
                    apdu[1] == 0x30.toByte()     // INS (SPAKE2+ REQUEST)
                ) {
                    log("📥 [FROM KW45] SPAKE2+ REQUEST received → preparing SPAKE2+ RESPONSE")

                    // Parse optional tags for debugging
                    parseSpake2RequestTags(apdu)

                    // Build and send SPAKE2+ RESPONSE (Curve Point X + SW=9000)
                    val curvePointX =
                        ByteArray(65) { 0x04 } // Dummy EC point (replace with real X later)
                    sendSpake2Response(addr, msg.messageHeader, curvePointX)

                    return
                }


                // --- SPAKE2+ VERIFY Command Detection (CLA=0x80, INS=0x32) ---

                if (apdu.size >= 4 &&
                    apdu[0] == 0x80.toByte() &&  // CLA
                    apdu[1] == 0x32.toByte()     // INS (SPAKE2+ VERIFY)
                ) {
                    log("📥 [FROM KW45] SPAKE2+ VERIFY command received → preparing VERIFY RESPONSE")

                    // ✅ Optional validation for P1/P2
                    if (apdu[2] != 0x00.toByte() || apdu[3] != 0x00.toByte()) {
                        log(
                            "⚠️ Unexpected P1/P2 in SPAKE2+ VERIFY: " +
                                    "0x${apdu[2].toUByte().toString(16)}, 0x${
                                        apdu[3].toUByte().toString(16)
                                    }"
                        )
                    }

                    // Parse Y (tag 0x52) and vehicle evidence M (tag 0x57)
                    parseSpake2VerifyTags(apdu)


                    // Send SPAKE2+ VERIFY RESPONSE (Tag 0x58 + SW=9000)
                    sendSpake2VerifyResponse(addr, msg.messageHeader)

                    log("📤 [TO KW45] SPAKE2+ VERIFY RESPONSE sent ✅ (Tag 0x58 + SW=9000)")
                    return
                }


                // --- AUTH0 Command Detection (CLA can be 0x00 for Standard TX or 0x8X for Pairing) ---
                if (apdu.size >= 5 && apdu[1] == 0x80.toByte()) {  // INS = 0x80 is key indicator
                    val cla = apdu[0].toInt() and 0xFF

                    // AUTH0 can come with:
                    // - CLA 0x00: Standard Transaction (mutual authentication)
                    // - CLA 0x80: Pairing flow
                    if (cla == 0x00 || (cla and 0xF0) == 0x80) {
                        log("📥 [FROM KW45] AUTH0 command received")
                        log("   CLA=${String.format("%02X", cla)} INS=80 (Standard Transaction)")

                        val p1 = apdu[2]
                        val p2 = apdu[3]
                        val lc = apdu[4].toInt() and 0xFF
                        val payload = if (apdu.size > 5 + lc) apdu.sliceArray(5 until 5 + lc) else byteArrayOf()

                        log("   P1=${String.format("%02X", p1)} P2=${String.format("%02X", p2)} Lc=$lc")

                        //this without storing key code so commenting now
                        // Parse vehicle's ephemeral PK, transaction ID, vehicle ID
                        // parseAuth0Tags(payload)

                        // Generate endpoint ephemeral key pair and build response
                        // val auth0Response = buildAuth0ResponseForKw45()
                        // sendDkApduRs(addr, msg.messageHeader, auth0Response)

                        val vehicleEpk = extractTagFromTLV(payload, 0x87)
                        if (vehicleEpk != null && vehicleEpk.size == 65) {
                            maPeerInformation[peerDeviceId].vehicleEpk = vehicleEpk
                            log("✅ Stored vehicle ePK: ${vehicleEpk.size} bytes")
                        } else {
                            log("❌ AUTH0: vehicle ePK (tag 0x87) not found or invalid length")
                            return
                        }
                        parseAuth0Tags(payload)
                        val auth0Response = buildAuth0ResponseForKw45(peerDeviceId)
                        sendDkApduRs(addr, msg.messageHeader, auth0Response)


                        log("✅ [TO KW45] AUTH0 response sent")
                        log("   Tag 0x86: Endpoint ePK (65 bytes)")
                        log("   SW: 9000")
                        return
                    }
                }

//                // --- AUTH1 Command Detection (CLA=0x84, INS=0x81) ---
//                if (apdu.size >= 5 &&
//                    apdu[0] == 0x84.toByte() &&   // CLA = 84 (secure messaging)
//                    apdu[1] == 0x81.toByte()      // INS = 81 (AUTH1)
//                ) {
//                    log("📥 [FROM KW45] AUTH1 command received (Mutual authentication & secure channel setup)")
//
//                    // Parse encrypted AUTH1 payload (for logging only, not decrypted yet)
//                    val lc = apdu[4].toInt() and 0xFF
//                    val payload = if (apdu.size > 5) apdu.sliceArray(5 until (5 + lc)) else byteArrayOf()
//                    log("🔒 AUTH1 Encrypted Payload (${payload.size} bytes): ${payload.joinToString(" ") { "%02X".format(it) }}")
//
//                    // --- Build AUTH1 Response ---
//                    val response = buildAuth1Response()
//
//                    // Send wrapped AUTH1 response back to KW45
//                    sendDkApduRs(addr, msg.messageHeader, response)
//                    log("📤 [TO KW45] AUTH1 Response sent successfully (${response.size} bytes)")
//                    return
//                }
                // --- AUTH1 Command Detection (CLA can be 0x00 or 0x84) ---

                if (apdu.size >= 5 && apdu[1] == 0x81.toByte()) {  // ✅ AUTH1 command
                    val cla = apdu[0].toInt() and 0xFF

                    // Accept both CLA 0x00 and 0x84
                    if (cla == 0x00 || cla == 0x84) {
                        log("📥 [FROM KW45] AUTH1 command received")
                        log("   CLA=${String.format("%02X", cla)} INS=81")

                        try {
                            val peerDeviceId = findPeerIdByAddress(addr)
                            if (peerDeviceId == INVALID_DEVICE_ID) {
                                log("❌ Invalid peer")
                                return
                            }

                            val peerInfo = maPeerInformation[peerDeviceId]
                            val lc = apdu[4].toInt() and 0xFF

                            // Secure channel key derivation if needed
                            if (peerInfo.kenc == null) {
                                log("   🔑 Deriving secure channel keys...")
                                if (!deriveAuth1Keys(peerDeviceId)) {
                                    log("❌ Key derivation failed")
                                    return
                                }
                            }

                            if (lc < 4) { // Accept even 4-byte dummy payload (as in your log)
                                log("❌ Lc too small (even for dummy)")
                                return
                            }

                            val encryptedPayload = apdu.sliceArray(5 until 5 + lc - 4) // Accept 4 byte MAC at end
                            val receivedMac = apdu.sliceArray(5 + lc - 4 until 5 + lc) // Accept 4 byte MAC

                            // KW45 dummy/demo mode: SKIP MAC check
                            log("⚠️ [DEMO INTEGRATION] Skipping MAC check and accepting KW45 dummy MAC and payload.")

                            peerInfo.requestCounter++ // Simulate increment to align counters

                            // KW45 demo mode: dummy payload, skip AES decryption if not valid AES block
                            val decrypted: ByteArray = if (encryptedPayload.size < 16) {
                                log("⚠️ Dummy or short encrypted payload received. Bypassing block cipher (AES) and using zeros.")
                                ByteArray(encryptedPayload.size) { 0x00 }
                            } else {
                                try {
                                    aesDecrypt(encryptedPayload, peerInfo.kenc!!)
                                } catch (e: Exception) {
                                    log("⚠️ Dummy encrypted failed AES decrypt: ${e.message}. Using zeros for demo.")
                                    ByteArray(encryptedPayload.size) { 0x00 }
                                }
                            }
                            log("   ✓ Decrypted (dummy/real): ${decrypted.size} bytes")

                            // Respond with dummy/demo AUTH1 response (always encrypted, MACed, SW)
                            val response = buildAuth1ResponseProper(peerDeviceId)
                            sendDkApduRs(addr, msg.messageHeader, response)
                            log("✅ [TO KW45] AUTH1 response sent (${response.size} bytes)")

                        } catch (e: Exception) {
                            log("❌ AUTH1 error: ${e.message}")
                            return
                        }
                    }
                }



                // send write data Response
                else if (apdu.size >= 4 &&
                    apdu[0] == 0x84.toByte() &&   // CLA (Secure Channel)
                    apdu[1] == 0xD4.toByte()      // INS (WRITE DATA)
                ) {
                    log("📩 Received WRITE DATA (segmented) from KW45")
                    log("📦 RAW WRITE DATA APDU: ${apdu.joinToString(" ") { "%02X".format(it) }}")

                    val p1 = apdu.getOrNull(2)?.toInt()?.and(0xFF) ?: 0
                    val isLastSegment = (p1 and 0x80) != 0
                    val lc = apdu.getOrNull(4)?.toInt()?.and(0xFF) ?: 0

                    if (lc == 0) {
                        log("⚠️ WRITE DATA Lc = 0 → rejecting")
                        sendDummyWriteDataResponse(addr, byteArrayOf(0x6A.toByte(), 0x84.toByte()))
                        return
                    }

                    val peerInfo = maPeerInformation[peerDeviceId]

                    val chunkStart = 5
                    val chunkEnd = (5 + lc).coerceAtMost(apdu.size)
                    if (chunkEnd <= chunkStart) {
                        log("⚠️ WRITE DATA malformed — no payload bytes available")
                        sendDummyWriteDataResponse(addr, byteArrayOf(0x6A.toByte(), 0x84.toByte()))
                        return
                    }

                    val chunk = apdu.sliceArray(chunkStart until chunkEnd)

                    // Initialize buffer for segmented transfer
                    if (peerInfo.writeDataEncryptedBuffer == null) {
                        peerInfo.writeDataEncryptedBuffer = ByteArrayOutputStream()
                        peerInfo.writeDataInProgress = true
                        log("🧩 Starting new WRITE DATA sequence")
                    }

                    // Append chunk
                    peerInfo.writeDataEncryptedBuffer?.write(chunk)
                    log("🧩 Received segment len=${chunk.size}, isLast=$isLastSegment")

                    // Wait for next segment if not last
                    if (!isLastSegment) return

                    // -------------------------------------------------------------------
                    // 📦 Handle last WRITE DATA segment (assemble, validate, create key)
                    // -------------------------------------------------------------------
                    peerInfo.writeDataInProgress = false

                    val fullPayload =
                        peerInfo.writeDataEncryptedBuffer?.toByteArray() ?: ByteArray(0)
                    peerInfo.writeDataEncryptedBuffer = null
                    log("📦 Final WRITE DATA assembled (len=${fullPayload.size})")

                    // ✅ Send dummy success response to KW45 first (ACK)
                    val dummyMac = ByteArray(8) { i -> (0xAB xor i).toByte() }
                    sendDummyWriteDataResponse(
                        addr,
                        byteArrayOf(0x90.toByte(), 0x00.toByte()),
                        dummyMac
                    )
                    log(
                        "📤 Dummy WRITE DATA response sent with MAC=${
                            dummyMac.joinToString(" ") {
                                "%02X".format(
                                    it
                                )
                            }
                        }"
                    )

                    // ----------------------------------------------------
                    // 🔍 Validate payload and create Digital Key
                    // ----------------------------------------------------
                    try {
                        val (ok, extracted) = validateAndExtractCreationData(fullPayload)
                        if (!ok) {
                            val errMsg =
                                extracted["error"] as? String ?: "Unknown TLV validation error"
                            log("❌ Digital key validation failed: $errMsg")
                        } else {
                            log("✅ TLV validation passed — creating digital key for peer=$peerDeviceId")

                            // 🔍 Parse and store endpoint creation TLVs (7F27, 7F4D, 7F4E)
                            processEndpointCreationData(fullPayload, peerDeviceId, context)

                            peerInfo.createdKeyData = buildDummyDigitalKeyCert()

                            val creationSuccess = createDigitalKey(
                                peerDeviceId = peerDeviceId,
                                creationPayload = fullPayload,
                                context = context,
                                seManager = SecureElementManagerStub()
                            )

                            if (creationSuccess) {
                                log("✅ createDigitalKey() succeeded for peer=$peerDeviceId")

                                // Simulated 32-byte dummy public key
                                val simulatedPublicKey = ByteArray(32) { it.toByte() }

                                // Build proper TLV 7F24 (Digital Key Certificate)
                                val cert7F24 = buildSimulated7F24Cert(simulatedPublicKey)

                                peerInfo.createdKeyData = cert7F24
                                peerInfo.readyForGetData = true
                                log("✅ Created simulated 7F24 Digital Key Certificate (${cert7F24.size} bytes)")
                            } else {
                                log("❌ createDigitalKey() returned failure for peer=$peerDeviceId")
                                peerInfo.readyForGetData = false
                            }
                        }

                        // ✅ Ensure key marked ready even if createDigitalKey silently succeeds
                        if (peerInfo.createdKeyData != null && peerInfo.createdKeyData!!.isNotEmpty()) {
                            peerInfo.readyForGetData = true
                            log("✅ [WRITE DATA] Digital Key marked ready for GET DATA")
                        }

                    } catch (e: Exception) {
                        log("⚠️ Exception during key validation/creation: ${e.message}")
                    }

                    // ----------------------------------------------------
                    // 🧹 Cleanup buffers
                    // ----------------------------------------------------
                    peerInfo.writeDataEncryptedBuffer = null
                    peerInfo.writeDataInProgress = false
                    log("🧹 Cleared writeDataEncryptedBuffer and reset in-progress flag")
                }


                // --- ✅ NEW: GET DATA (0x84 0xCA) --- with payload
                else if (apdu.size >= 4 &&
                    apdu[0] == 0x84.toByte() &&   // CLA (Secure Channel)
                    apdu[1] == 0xCA.toByte()      // INS (GET DATA)
                ) {
                    log("📥 [FROM KW45] GET DATA command received (CLA=84, INS=CA)")

                    // Step 1: Parse Lc
                    val lc = apdu.getOrNull(4)?.toInt()?.and(0xFF) ?: 0
                    val totalLen = apdu.size
                    if (lc == 0 || totalLen < 5 + lc) {
                        log("⚠️ [GET DATA] Invalid Lc=$lc or short frame (total=$totalLen)")
                        sendGetDataResponse(
                            addr,
                            msg.messageHeader,
                            byteArrayOf(),
                            byteArrayOf(0x6A.toByte(), 0x84.toByte())
                        )
                        return
                    }

                    // Step 2: Determine MAC length dynamically (if Lc includes/excludes MAC)
                    // val macLength = 16
                    val macLength = 8 // instead of 16

                    val payloadLength = if (lc > macLength && totalLen >= 5 + lc)
                        lc - macLength
                    else if (totalLen >= 5 + macLength)
                        lc
                    else
                        lc

                    val payloadEnd = 5 + payloadLength
                    val encryptedPayload = apdu.sliceArray(5 until payloadEnd)
                    val receivedMac = apdu.sliceArray(payloadEnd until (payloadEnd + macLength))
                    log("📦 [GET DATA] Payload(${encryptedPayload.size}) + MAC(${receivedMac.size})")

                    // Step 3: Dummy MAC verify (same XOR rule)
                    var acc: Byte = 0
                    for (b in encryptedPayload) acc = (acc.toInt() xor b.toInt()).toByte()
                    val expectedMac = ByteArray(macLength) { i -> (acc.toInt() xor i).toByte() }

                    if (!receivedMac.contentEquals(expectedMac)) {
                        log("⚠️ [GET DATA] Dummy MAC mismatch – continuing for dummy mode")
                    } else {
                        log("✅ [GET DATA] Dummy MAC verified OK")
                    }

                    // Step 4: Decode payload (no AES in dummy)
                    val decryptedData = encryptedPayload
                    log(
                        "🔓 [GET DATA] Decoded payload: ${
                            decryptedData.joinToString(" ") {
                                "%02X".format(
                                    it
                                )
                            }
                        }"
                    )

                    // Remove trailing Le byte if present (KW45 appends 0x00 at end)
                    val cleanData =
                        if (decryptedData.isNotEmpty() && decryptedData.last() == 0x00.toByte())
                            decryptedData.dropLast(1).toByteArray()
                        else
                            decryptedData
                    val tag = if (cleanData.size >= 2)
                        ((cleanData[0].toInt() and 0xFF) shl 8) or (cleanData[1].toInt() and 0xFF)
                    else
                        cleanData.getOrNull(0)?.toInt()?.and(0xFF) ?: 0
                    log("🔍 [GET DATA] Requested tag = 0x${tag.toString(16).uppercase()}")
                    val peerInfo = maPeerInformation[peerDeviceId]
                    val responseData = when (tag) {
                        0x7F20 -> {
                            log("🔑 [GET DATA] Request OEM CA cert")
                            "OEM_CA_CERT_DUMMY".toByteArray()
                        }

                        0x7F22 -> {
                            log("🔑 [GET DATA] Request Instance CA cert")
                            "INSTANCE_CA_CERT_DUMMY".toByteArray()
                        }

                        0x5B01 -> {
                            log("🔑 [GET DATA] Request Digital Key cert")
                            val createdKey = peerInfo?.createdKeyData
                            if (createdKey != null && peerInfo.readyForGetData) {
                                log("✅ [GET DATA] Returning created key data (len=${createdKey.size})")
                                createdKey
                            } else {
                                log("⚠️ [GET DATA] Key not ready yet (6A88 Reference data not found)")
                                sendGetDataResponse(
                                    addr,
                                    msg.messageHeader,
                                    byteArrayOf(),
                                    byteArrayOf(0x6A.toByte(), 0x88.toByte())
                                )
                                return
                            }
                        }

                        0x7F24 -> {
                            log("🔑 [GET DATA] Request TEST_CERT (7F24)")
                            "TEST_CERT_DUMMY".toByteArray()
                        }

                        0x00D3, 0xD3 -> {
                            log("🔑 [GET DATA] Request for friendly name (D3)")
                            "MyCarKey".toByteArray()
                        }

                        else -> {
                            log("⚠️ [GET DATA] Unknown tag 0x${tag.toString(16)} → 6A88 (Reference data not found)")
                            sendGetDataResponse(
                                addr,
                                msg.messageHeader,
                                byteArrayOf(),
                                byteArrayOf(0x6A.toByte(), 0x88.toByte())
                            )
                            return
                        }
                    }


                    // Step 7: Prepare response (dummy MAC)
                    var accResp: Byte = 0
                    for (b in responseData) accResp = (accResp.toInt() xor b.toInt()).toByte()
                    val responseMac = ByteArray(macLength) { i -> (accResp.toInt() xor i).toByte() }

                    val responseApdu =
                        responseData + responseMac + byteArrayOf(0x90.toByte(), 0x00.toByte())
                    log("📤 [GET DATA] Response ready len=${responseApdu.size}")

                    // Step 8: Send response back to KW45
                    sendDkApduRs(addr, msg.messageHeader, responseApdu)
                    log("✅ [TO KW45] GET DATA response sent successfully (tag=0x${tag.toString(16)})")
                }


                // --- OP CONTROL FLOW Command Detection ---
                else if (apdu.size >= 4 && apdu[0] == 0x80.toByte() && apdu[1] == 0x3C.toByte()) {
                    val p1 = apdu[2]
                    val p2 = apdu[3]

                    log(
                        "📩 Received OP CONTROL FLOW from KW45 → P1=${"%02X".format(p1)}, P2=${
                            "%02X".format(
                                p2
                            )
                        }"
                    )

                    when (p1.toInt() and 0xFF) {
                        0x10 -> log("Continue flow requested, reason code=${"%02X".format(p2)}")
                        0x11 -> log("End flow successfully requested, reason code=${"%02X".format(p2)}")
                        0x12 -> log("Abort flow requested, reason code=${"%02X".format(p2)}")
                        else -> log("⚠️ Unknown P1=${"%02X".format(p1)} in OP CONTROL FLOW")
                    }

                    // Send response SW=90 00h to vehicle
                    val sw = byteArrayOf(0x90.toByte(), 0x00.toByte())
                    sendOpControlResponse(
                        addr,
                        apduHeader = msg.messageHeader,
                        responseData = byteArrayOf(),
                        sw = sw
                    )
                    log("✅ OP CONTROL FLOW response sent SW=90 00")
                    // --- NEW: notify UI layer that OP_CONTROL_FLOW was received/completed ---
                    // ---------- Notify UI that OP_CONTROL_FLOW is completed ----------
                    try {
                        log("DEBUG_OP_CTRL: notifying UI that OP_CONTROL_FLOW completed for $addr")

                        PairingStore.setPending(context, false)
                        PairingStore.setConnected(context, true)

                        // Make sure callback runs on main thread
                        handler.post {
                            try {
                                log("DEBUG_OP_CTRL: invoking onOpControlFlowCompleted for $addr")
                                onOpControlFlowCompleted?.invoke(addr)
                            } catch (t: Throwable) {
                                log("DEBUG_OP_CTRL: callback error: ${t.message}")
                            }
                        }

                    } catch (t: Throwable) {
                        log("DEBUG_OP_CTRL: failed to trigger callback: ${t.message}")
                    }


                    // ✅ Activate Standard Transaction Mode
                    //  isStandardTxActive = true
                    // log("🚘 Entered Standard Transaction Phase (isStandardTxActive = true)")
                }

                // --- Unsupported DK_APDU_RQ ---
                else {
                    log(
                        "⚠️ Non-SELECT or unsupported DK_APDU_RQ → INS=${
                            apdu.getOrNull(1)?.toUByte()?.toString(16)
                        }"
                    )
                }
            }


            // ---------- DK_APDU_RS (0x0C) ----------
            0x0C.toByte() -> {
                val resp = msg.payload
                log("📬 DK_APDU_RS from $addr : ${resp.joinToString(" ") { "%02X".format(it) }}")

                // SPAKE2+ RESPONSE (Curve Point X)
                if (resp.size >= 67 && resp[0] == 0x50.toByte()) {
                    val curveX = resp.sliceArray(1..65)
                    log(
                        "✅ Received SPAKE2+ Response Curve Point X: ${
                            curveX.joinToString(" ") {
                                "%02X".format(
                                    it
                                )
                            }
                        }"
                    )

                    val id = findPeerIdByAddress(addr)
                    if (id != INVALID_DEVICE_ID) {
                        maPeerInformation[id].peerCurveX = curveX
                        stateMachineHandler(id, AppEvent.RECEIVED_SPAKE_RESPONSE)
                    }

                    if (resp.size >= 69) {
                        val sw1 = resp[resp.size - 2]
                        val sw2 = resp[resp.size - 1]
                        if (sw1 == 0x90.toByte() && sw2 == 0x00.toByte()) {
                            log("✅ SPAKE2+ Response Status: 0x90 0x00 (Success)")

                            if (id != INVALID_DEVICE_ID) {
                                val peerCurveX = maPeerInformation[id].peerCurveX
                                val myCurveY = maPeerInformation[id].myCurveY
                                    ?: return log("⚠️ myCurveY missing, cannot send Verify")
                                val vehicleEvidence = maPeerInformation[id].vehicleEvidence
                                    ?: return log("⚠️ vehicleEvidence missing")

                                //sendSpake2Verify(addr, myCurveY, vehicleEvidence)
                            }
                        } else {
                            log(
                                "⚠️ SPAKE2+ Response SW not success: ${"%02X".format(sw1)} ${
                                    "%02X".format(
                                        sw2
                                    )
                                }"
                            )
                        }
                    }
                }

                // SPAKE2+ VERIFY RESPONSE (Tag 0x58)
                if (resp.size >= 2) {
                    val sw1 = resp[resp.size - 2]
                    val sw2 = resp[resp.size - 1]
                    val statusWordOk = (sw1 == 0x90.toByte() && sw2 == 0x00.toByte())

                    val payloadWithoutSw = resp.copyOfRange(0, resp.size - 2)
                    var idx = 0
                    while (idx < payloadWithoutSw.size) {
                        val tag = payloadWithoutSw[idx]
                        if (idx + 1 >= payloadWithoutSw.size) break
                        val len = payloadWithoutSw[idx + 1].toInt() and 0xFF
                        val start = idx + 2
                        val end = start + len
                        if (end > payloadWithoutSw.size) break
                        val value = payloadWithoutSw.copyOfRange(start, end)

                        when (tag.toInt() and 0xFF) {
                            0x58 -> {
                                log(
                                    "✅ Received Device evidence (Tag 0x58): ${
                                        value.joinToString(" ") {
                                            "%02X".format(
                                                it
                                            )
                                        }
                                    }"
                                )
                                if (value.size == 16 && statusWordOk) {
                                    log("✅ SPAKE2+ VERIFY succeeded (Device evidence + SW=90 00)")
                                    val id = findPeerIdByAddress(addr)
                                    if (id != INVALID_DEVICE_ID) {
                                        maPeerInformation[id].deviceEvidence = value
                                        stateMachineHandler(id, AppEvent.RECEIVED_SPAKE_VERIFY_OK)
                                    }
                                } else {
                                    log(
                                        "⚠️ SPAKE2+ VERIFY failed: len=${value.size}, SW=${
                                            "%02X".format(
                                                sw1
                                            )
                                        } ${"%02X".format(sw2)}"
                                    )
                                    val id = findPeerIdByAddress(addr)
                                    if (id != INVALID_DEVICE_ID)
                                        stateMachineHandler(id, AppEvent.SPAKE_VERIFY_FAILED)
                                }
                            }

                            else -> log("ℹ️ Unhandled response TLV tag ${"%02X".format(tag)} len=$len")
                        }
                        idx = end
                    }

                    if (!payloadWithoutSw.any { it == 0x58.toByte() } && statusWordOk) {
                        log("⚠️ No Tag 0x58 in response but SW=90 00. Maybe device omitted evidence or format differs.")
                    }
                } else {
                    log("⚠️ APDU response too short (<2 bytes)")
                }
            }

            // ---------- DK EVENT ----------

            else -> log(
                "L2CAP DK: unhandled payloadHdr=0x${
                    msg.payloadHeader.toUByte().toString(16)
                }"
            )
        }
    }


    private fun handleDkEventNotification(addr: String, payload: ByteArray) {
        if (payload.size < 2) {
            log("⚠️ Invalid DK Event payload from $addr (len=${payload.size})")
            return
        }

        val category = payload[0]
        val code = payload[1]

        when (category to code) {
            // --- Owner pairing event ---
            0x01.toByte() to 0x04.toByte() -> {
                log("📩 [FROM KW45] RequestOwnerPairing event from $addr")
                sendOwnerPairingTest(addr, simulateNxp = true)
            }

            // --- Standard transaction event ---
            0x01.toByte() to 0x03.toByte() -> {

            }

            // --- BLE pairing ready ---
            0x01.toByte() to 0x01.toByte() -> {
                log("📩 BLE_pairing_ready from $addr → trigger bonding flow")
                log("📩 [FROM KW45] RequestStandardTransaction event from $addr")
                // Trigger Standard Transaction Phase 3 start
                val msgHdr: Byte = 0x01 // SE message type
                sendSelectCommandForStandardTx(addr, msgHdr)
            }

            // --- Capability exchange required ---
            0x01.toByte() to 0x02.toByte() -> {
                log("📩 Require_capability_exchange from $addr")
            }

            else -> log(
                "⚠️ Unhandled DK event category=${"%02X".format(category)} code=${
                    "%02X".format(
                        code
                    )
                } from $addr"
            )
        }
    }


    // ======== L2CAP Connection-Oriented Channel (Dynamic PSM) ========

    /**
     * Reads the SPSM (LE_PSM) value from the GATT characteristic of the
     * Digital Key service and then opens a secure L2CAP channel using
     * that dynamic PSM instead of a hard-coded one.
     */
    @SuppressLint("MissingPermission")
    fun openDynamicL2capChannel(addr: String) {
        Log.d("DigitalKeyDevice", "openDynamicL2capChannel called with addr=$addr")
        val gatt = connectedGatts[addr]
        if (gatt == null) {
            Log.d(
                "DigitalKeyDevice",
                "No active GATT for addr=$addr. Connected keys: ${connectedGatts.keys}"
            )
            log("DynamicL2cap: No active GATT connection for $addr")
            return
        }

        val svc = gatt.getService(CCC_DK_SERVICE_UUID)
        if (svc == null) {
            log("DynamicL2cap: DK service not found on existing connection")
            return
        }

        val spsmChar = svc.getCharacteristic(VEHICLE_PSM_CHAR_UUID)
        if (spsmChar == null) {
            log("DynamicL2cap: SPSM characteristic missing")
            return
        }

        log("DynamicL2cap: Reading SPSM characteristic on existing GATT for $addr")

        val readOk = gatt.readCharacteristic(spsmChar)
        if (!readOk) {
            log("DynamicL2cap: Failed to start characteristic read for PSM")
            return
        }

        // Add local callback to monitor the result
        // (We hook into the existing GATT callback dynamically)
        gattCallback = object : BluetoothGattCallback() {
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (characteristic.uuid == VEHICLE_PSM_CHAR_UUID && status == BluetoothGatt.GATT_SUCCESS) {
                    val raw = characteristic.value
                    if (raw != null && raw.size >= 2) {
                        val psm = ByteBuffer.wrap(raw)
                            .order(ByteOrder.BIG_ENDIAN)
                            .short.toInt() and 0xFFFF
                        log("DynamicL2cap: Got PSM=$psm – opening L2CAP channel…")
                        openL2capSocket(gatt.device, psm)
                    } else {
                        log("DynamicL2cap: Invalid SPSM data")
                    }
                } else {
                    log("DynamicL2cap: Characteristic read failed (status=$status)")
                }
            }
        }
    }


    /** Opens the L2CAP CoC socket using the PSM value discovered above. */
    private fun openL2capSocket(device: BluetoothDevice, psm: Int) {
        thread {
            try {
                val socket = if (device.bondState == BluetoothDevice.BOND_BONDED) {
                    device.createL2capChannel(psm) // secure
                } else {
                    device.createInsecureL2capChannel(psm)
                }
                socket.connect()
                val input = socket.inputStream
                val output = socket.outputStream
                l2capOutput[device.address] = output
                l2capRxBuffers[device.address] = ByteArrayOutputStream()
                log("DynamicL2cap: channel opened (PSM=$psm)")

                // ✅ Trigger fragment callback
                onL2capOpened?.invoke(device.address)

                val buf = ByteArray(1024)
                var read = input.read(buf)
                while (read > 0) {
                    val chunk = buf.copyOf(read)
                    val acc = l2capRxBuffers.getOrPut(device.address) { ByteArrayOutputStream() }
                    acc.write(chunk)
                    var cont = true
                    while (cont) {
                        val current = acc.toByteArray()
                        val (msg, consumed) = DkMessage.tryParse(current)
                        if (msg == null || consumed == 0) {
                            cont = false
                        } else {
                            val remaining = if (consumed < current.size) current.copyOfRange(
                                consumed,
                                current.size
                            ) else ByteArray(0)
                            acc.reset()
                            if (remaining.isNotEmpty()) acc.write(remaining)
                            handleDkMessage(device.address, msg)
                        }
                    }
                    read = input.read(buf)
                }
            } catch (e: Exception) {
                log("DynamicL2cap: error ${e.message}")
                e.printStackTrace()
            } finally {
                l2capOutput.remove(device.address)
                l2capRxBuffers.remove(device.address)
            }
        }
    }


    fun sendOwnerPairingTest(
        addr: String,
        simulateNxp: Boolean,
        ownerInfo: ByteArray? = null
    ) {
        if (simulateNxp) {
            // ------------------------
            // Simulate NXP → Mobile event
            // ------------------------
            val payload = byteArrayOf(
                0x01, // gCommandComplete
                0x04  // gRequestOwnerPairing
            )
            // Event Notification = msgHdr=0x03, payloadHdr= 0x11
            sendDkMessage(addr, 0x03, 0x11, payload)
            log("Simulated RequestOwnerPairing Event from NXP for $addr")
        } else {
            // ------------------------
            // Mobile → NXP command
            // ------------------------
            val info = ownerInfo ?: ByteArray(4) { 0x00 } // fallback dummy owner info
            // PairingRequest = msgHdr=FRAMEWORK_MESSAGE, payloadHdr=PAIRING_REQUEST_CMD
            sendDkMessage(
                addr,
                DkMessageType.FRAMEWORK_MESSAGE.value, // e.g. 0x02
                PAIRING_REQUEST_CMD,                   // your constant
                info
            )
            log("Sent real PairingRequest (OwnerPairing) to NXP for $addr")
        }
    }


    /** Sends bytes over the open L2CAP channel using DK framing. */
    fun sendDkMessage(addr: String, messageHeader: Byte, payloadHeader: Byte, payload: ByteArray) {
        val out = l2capOutput[addr]
        if (out == null) {
            log("L2CAP: no channel for $addr (attempted send DK msg)")
            return
        }
        try {
            val frame = DkMessage(messageHeader, payloadHeader, payload).toByteArray()
            out.write(frame)
            out.flush()
            log(
                "L2CAP TX [$addr]: DK frame ${frame.size} bytes (msgHdr=0x${
                    messageHeader.toUByte().toString(16)
                })"
            )
        } catch (e: IOException) {
            log("L2CAP send error [$addr]: ${e.message}")
        }
    }



    // ----------- Owner Pairing (MessageType = 0x00) -----------
// Utility function to convert hex string to byte array
    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] =
                ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }


    private fun buildSelectResponse(): ByteArray {
        val spakeVersions = byteArrayOf(0x01, 0x00, 0x01, 0x01) // SPAKE2+ v1.0 and v1.1
        val appletVersions = byteArrayOf(0x01, 0x00, 0x01, 0x01) // DK applet v1.0 and v1.1
        val pairingMode = byteArrayOf(0x02)                    // Pairing mode started

        val stream = ByteArrayOutputStream()
        stream.write(byteArrayOf(0x5A, 0x04))  // SPAKE2+ tag, length
        stream.write(spakeVersions)
        stream.write(byteArrayOf(0x5C, 0x04))  // DK applet tag, length
        stream.write(appletVersions)
        stream.write(byteArrayOf(0xD4.toByte(), 0x01)) // Pairing mode tag, length
        stream.write(pairingMode)
        stream.write(byteArrayOf(0x90.toByte(), 0x00)) // status word
        return stream.toByteArray()
    }


    fun sendSelectResponseAid(addr: String, incomingMsgHdr: Byte) {
        // Build the SELECT response APDU (FCI + 0x9000)
        val response =
            buildSelectResponse() // returns something like 6F 08 84 06 A0 00 00 08 00 90 00

        // DK_APDU_RS = 0x0C (APDU response)
        sendDkMessage(addr, incomingMsgHdr, 0x0C.toByte(), response)

        log(
            "📤 [TO NXP] Sent DK_APDU_RS (SELECT Response) → " +
                    "msgHdr=0x${incomingMsgHdr.toUByte().toString(16)}, " +
                    "payloadHdr=0x0C, " +
                    "APDU=${response.joinToString(" ") { "%02X".format(it) }}"
        )
    }


    private fun buildSelectResponseForStandardTransaction(): ByteArray {
        val appletVersion = byteArrayOf(
            0x5C, 0x02,     // Tag 5C (Supported DK applet versions), Length = 2
            0x01, 0x00,     // Version 1.0 (0100h)
            0x90.toByte(), 0x00 // Status Word 9000
        )
        return appletVersion
    }

    private fun sendSpake2Response(addr: String, incomingMsgHdr: Byte, curvePointX: ByteArray) {
        // Build the SPAKE2+ response APDU (Tag 50 + SW=9000)
        val responseApdu = buildSpake2ResponseApdu(curvePointX)

        // DK_APDU_RS = 0x0C (APDU response)
        sendDkMessage(
            addr,
            messageHeader = incomingMsgHdr,
            payloadHeader = 0x0C,
            payload = responseApdu
        )

        log(
            "📤 [TO KW45] Sent DK_APDU_RS (SPAKE2+ Response) → " +
                    "msgHdr=0x${incomingMsgHdr.toUByte().toString(16)}, " +
                    "payloadHdr=0x0C, " +
                    "APDU=${responseApdu.joinToString(" ") { "%02X".format(it) }}"
        )
    }

    private fun sendSpake2VerifyResponse(addr: String, incomingMsgHdr: Byte) {
        // Build TLV for Tag 0x58 (Device evidence M)
        val deviceEvidence = ByteArray(16) { 0x11 } // Dummy 16-byte evidence
        val tag58 = byteArrayOf(0x58.toByte(), deviceEvidence.size.toByte()) + deviceEvidence
        val sw = byteArrayOf(0x90.toByte(), 0x00.toByte()) // Status = Success

        val responseApdu = tag58 + sw

        // Send via DK_APDU_RS (0x0C)
        sendDkMessage(
            addr,
            messageHeader = incomingMsgHdr,
            payloadHeader = 0x0C,
            payload = responseApdu
        )

        log(
            "📤 [TO KW45] Sent DK_APDU_RS (SPAKE2+ Verify Response) → " +
                    "msgHdr=0x${incomingMsgHdr.toUByte().toString(16)}, " +
                    "payloadHdr=0x0C, APDU=${responseApdu.joinToString(" ") { "%02X".format(it) }}"
        )
    }


    /**
     * Parse and log SPAKE2+ VERIFY APDU TLVs.
     * Expected tags:
     *  - 0x52 → Curve Point Y (65 bytes, starting with 0x04)
     *  - 0x57 → Vehicle Evidence M (16 bytes)
     */
    private fun parseSpake2VerifyTags(apdu: ByteArray) {
        try {
            // Skip the first 5 APDU header bytes (CLA, INS, P1, P2, Lc)
            if (apdu.size <= 5) {
                log("⚠️ SPAKE2+ VERIFY APDU too short: ${apdu.size}")
                return
            }

            var idx = 5
            while (idx < apdu.size) {
                if (idx + 1 >= apdu.size) break
                val tag = apdu[idx]
                val len = apdu[idx + 1].toInt() and 0xFF
                val start = idx + 2
                val end = start + len

                if (end > apdu.size) {
                    log("⚠️ Malformed TLV: tag=${"%02X".format(tag)}, len=$len (exceeds size)")
                    break
                }

                val value = apdu.copyOfRange(start, end)
                when (tag.toInt() and 0xFF) {
                    0x52 -> {
                        log(
                            "🔹 Tag 0x52 (Curve Point Y): len=$len, firstBytes=${
                                value.take(5).joinToString(" ") { "%02X".format(it) }
                            } ..."
                        )
                        if (len != 65 || value[0] != 0x04.toByte()) {
                            log("⚠️ Curve Point Y expected 65 bytes starting with 0x04, got len=$len")
                        }
                    }

                    0x57 -> {
                        log(
                            "🔹 Tag 0x57 (Vehicle Evidence M): len=$len, value=${
                                value.joinToString(" ") {
                                    "%02X".format(
                                        it
                                    )
                                }
                            }"
                        )
                        if (len != 16) {
                            log("⚠️ Vehicle Evidence M expected 16 bytes, got len=$len")
                        }
                    }

                    else -> log("ℹ️ Unrecognized TLV tag ${"%02X".format(tag)}, len=$len")
                }

                idx = end
            }
        } catch (e: Exception) {
            log("⚠️ parseSpake2VerifyTags exception: ${e.message}")
        }
    }


    private fun buildSpake2ResponseApdu(curvePointX: ByteArray): ByteArray {
        val sw = byteArrayOf(0x90.toByte(), 0x00.toByte()) // Success status word
        val tag50 = byteArrayOf(0x50.toByte(), curvePointX.size.toByte()) + curvePointX
        return tag50 + sw
    }


    private fun parseSpake2RequestTags(apdu: ByteArray) {
        // Skip the first 5 bytes of APDU header: CLA INS P1 P2 Lc
        val lc = apdu.getOrNull(4)?.toInt() ?: return
        val dataField = apdu.copyOfRange(5, 5 + lc)
        var idx = 0
        while (idx < dataField.size) {
            val tag = dataField[idx]
            if (idx + 1 >= dataField.size) break
            val len = dataField[idx + 1].toInt() and 0xFF
            val start = idx + 2
            val end = (start + len).coerceAtMost(dataField.size)
            val value = dataField.copyOfRange(start, end)
            log(
                "🔹 SPAKE2+ Tag ${"%02X".format(tag)} len=$len val=${
                    value.joinToString(" ") {
                        "%02X".format(
                            it
                        )
                    }
                }"
            )
            idx = end
        }
    }

    // Helper to build a TLV: [tag][len][value]
    private fun tlv(tag: Byte, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag.toInt())
        out.write((value.size and 0xFF))
        out.write(value)
        return out.toByteArray()
    }

    fun validateWriteDataTlv(data: ByteArray): Boolean {
        var i = 0
        while (i < data.size) {
            if (i + 2 > data.size) return false
            val tag = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2

            if (i >= data.size) return false
            val len = data[i].toInt() and 0xFF
            i += 1

            if (i + len > data.size) return false
            val value = data.sliceArray(i until i + len)

            log(
                "📦 TLV Tag=0x%04X Len=%d Value(first 4B)=%s".format(
                    tag,
                    len,
                    value.take(4).joinToString(" ") { "%02X".format(it) })
            )

            i += len

            // check completion marker (5F5Fh)
            if (tag == 0x5F5F) {
                log("🏁 Completion tag (5F5Fh) reached — end of WriteData sequence")
                break
            }
        }
        return true
    }


    /**
     * Send SPAKE2+ VERIFY (Vehicle -> Device)
     * - Curve Y must be 65 bytes and start with 0x04 (uncompressed point)
     * - vehicleEvidence must be 16 bytes
     *
     * This constructs an APDU:
     * CLA INS P1 P2 Lc [TLV: 52 len Y][TLV: 57 len evidence] Le(00)
     * Then encapsulates it inside DK_APDU_RQ (msgHdr=0x00, payloadHdr=0x0B).
     */

    // Helper to pad byte arrays to fixed length
    fun ByteArray.padStart(size: Int): ByteArray {
        if (this.size >= size) return this.copyOfRange(this.size - size, this.size)
        return ByteArray(size - this.size) { 0x00 } + this
    }

    //this with mac data
    fun sendWriteDataResponse(addr: String, peerDeviceId: Int, sw: ByteArray) {
        val peerInfo = maPeerInformation[peerDeviceId]
        val krmac = peerInfo.krmac ?: run {
            log("⚠️ Krmac not initialized for peer $peerDeviceId")
            return
        }

        // 1️⃣ Prepare counter (4 bytes, big endian)
        val counterBytes = ByteArray(4) { i ->
            ((peerInfo.commandCounterResponse shr (8 * (3 - i))) and 0xFF).toByte()
        }
        val counterInt = peerInfo.commandCounterResponse
        log(
            "🧮 WRITE DATA Response Counter = $counterInt → Bytes = ${
                counterBytes.joinToString(" ") {
                    "%02X".format(
                        it
                    )
                }
            }"
        )

        // 2️⃣ Build MAC input = counter || SW
        val macInput = counterBytes + sw
        log("🔏 WRITE DATA MAC Input = ${macInput.joinToString(" ") { "%02X".format(it) }}")

        // 3️⃣ Compute AES-CMAC using Krmac
        val mac = Mac.getInstance("AESCMAC", "BC")
        mac.init(SecretKeySpec(krmac, "AES"))
        val responseMac = mac.doFinal(macInput)
        log("✅ WRITE DATA Response MAC = ${responseMac.joinToString(" ") { "%02X".format(it) }}")

        // 4️⃣ Increment response counter (AFTER MAC computation)
        peerInfo.commandCounterResponse += 1

        // 5️⃣ Construct final APDU payload: Response MAC + SW
        val responseApdu = responseMac + sw
        log("📤 WRITE DATA Final Response APDU = ${responseApdu.joinToString(" ") { "%02X".format(it) }}")

        // 6️⃣ Send to KW45 (Device → Vehicle) using DK_APDU_RS (0x0C)
        sendDkMessage(addr, 0x00.toByte(), 0x0C.toByte(), responseApdu)
        log("➡️ Sent WRITE DATA response to KW45 (SW=${sw.joinToString(" ") { "%02X".format(it) }})")
    }


    fun computeResponseMac(
        peerDeviceId: Int,
        responsePayload: ByteArray = ByteArray(0)
    ): ByteArray {
        val peerInfo = maPeerInformation[peerDeviceId]
        val krmac = peerInfo.krmac ?: return ByteArray(0)
        val counterBytes =
            ByteArray(4) { i -> ((peerInfo.commandCounterResponse shr (8 * (3 - i))) and 0xFF).toByte() }
        val macInput = counterBytes + responsePayload
        val mac = Mac.getInstance("AESCMAC", "BC")
        mac.init(SecretKeySpec(krmac, "AES"))
        val result = mac.doFinal(macInput)
        peerInfo.commandCounterResponse += 1
        return result
    }


    fun verifyCommandMac(
        encryptedPayload: ByteArray,
        receivedMac: ByteArray,
        peerDeviceId: Int
    ): Boolean {
        val peerInfo = maPeerInformation[peerDeviceId]
        val kmac = peerInfo.kmac ?: run {
            log("⚠️ Kmac not initialized for peer $peerDeviceId")
            return false
        }
        val computed = computeMac(encryptedPayload, kmac, peerInfo.commandCounterRequest)
        val ok = receivedMac.contentEquals(computed)
        if (ok) {
            // increment request counter once validated
            peerInfo.commandCounterRequest += 1
        }
        return ok
    }

    fun decryptWriteData(encryptedData: ByteArray, peerDeviceId: Int): ByteArray {
        val peerInfo = maPeerInformation[peerDeviceId]
        val kEnc = peerInfo.kenc ?: run {
            log("⚠️ Kenc not initialized for peer $peerDeviceId")
            return ByteArray(0)
        }

        return aesEncrypt(encryptedData, kEnc) // implement AES-CBC or AES-CTR decryption
        //return aesDecryptAesCbc(encryptedData, kEnc)

    }

    fun computeMac(encryptedPayload: ByteArray, kmac: ByteArray, counter: Int): ByteArray {
        val counterBytes = ByteArray(4) { i -> ((counter shr (8 * (3 - i))) and 0xFF).toByte() }
        val macInput = counterBytes + encryptedPayload
        val mac = Mac.getInstance("AESCMAC", "BC")
        mac.init(SecretKeySpec(kmac, "AES"))
        return mac.doFinal(macInput)
    }



    fun computeDummyMac(data: ByteArray): ByteArray {
        var acc: Byte = 0
        for (b in data) {
            acc = (acc.toInt() xor (b.toInt() and 0xFF)).toByte()
        }
        val mac = ByteArray(16)
        for (i in 0 until 16) {
            mac[i] = (acc.toInt() xor i).toByte()
        }
        return mac
    }


    fun sendDummyWriteDataResponse(addr: String, sw: ByteArray, dummyMac: ByteArray? = null) {
        val responseApdu = if (dummyMac != null) dummyMac + sw else sw
        sendDkMessage(addr, 0x00.toByte(), 0x0C.toByte(), responseApdu)
        log(
            "➡️ Sent WRITE DATA response to KW45: ${
                responseApdu.joinToString(" ") {
                    "%02X".format(
                        it
                    )
                }
            }"
        )
    }


    // --- Helper stubs ---
// AES encryption (CBC/CTR) according to spec
    fun aesEncrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        // Implement AES encryption with IV if required by spec
        return plaintext // placeholder
    }

    private fun buildSimulated7F24Cert(endpointPublicKey: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()

        // 42h - instance_CA_identifier
        val caId = "TEST_CA".toByteArray()
        baos.write(0x42)
        baos.write(caId.size)
        baos.write(caId)

        // 53h - subject public key
        baos.write(0x53)
        baos.write(endpointPublicKey.size)
        baos.write(endpointPublicKey)

        // 5F37h - dummy signature
        val signature = ByteArray(8) { 0x55 } // 8 bytes of dummy signature
        baos.write(0x5F)
        baos.write(0x37)
        baos.write(signature.size)
        baos.write(signature)

        // Wrap all in 7F24h tag
        val inner = baos.toByteArray()
        val outer = ByteArrayOutputStream()
        outer.write(0x7F)
        outer.write(0x24)
        outer.write(inner.size)
        outer.write(inner)

        return outer.toByteArray()
    }


    private fun sendGetDataResponse(
        addr: String,
        msgHdr: Byte,
        responseData: ByteArray,
        sw: ByteArray
    ) {
        val response = responseData + sw
        sendDkApduRs(addr, msgHdr, response)
    }

    private fun mockCertData(label: String): ByteArray {
        val dummy = ByteArray(64) { 0x42 }
        log("🧾 Returning $label (64 bytes dummy data)")
        return dummy
    }


    // --------------------------
// Helper to send APDU response (e.g., OP CONTROL FLOW, WRITE DATA, SELECT)
// --------------------------
    private fun sendOpControlResponse(
        addr: String,
        apduHeader: Byte,
        responseData: ByteArray,
        sw: ByteArray
    ) {
        val response = responseData + sw
        sendDkApduRs(addr, apduHeader, response)
        log("📤 Sent APDU response to $addr → SW=${sw.joinToString(" ") { "%02X".format(it) }}")
    }

    // --------------------------
// Send DK_APDU_RS (0x0C) over L2CAP
// --------------------------
    private fun sendDkApduRs(addr: String, msgHdr: Byte, response: ByteArray) {
        // DK_APDU_RS = payloadHeader 0x0C + payload
        val payloadHeader: Byte = 0x0C
        sendDkMessage(addr, msgHdr, payloadHeader, response)
    }

    @Suppress("LongMethod")
    fun processEndpointCreationData(decryptedData: ByteArray, peerDeviceId: Int, context: Context) {
        val peerInfo = maPeerInformation[peerDeviceId] ?: AppPeerInfo().also {
            maPeerInformation[peerDeviceId] = it
        }

        log("📦 Processing Endpoint Creation TLVs (WRITE DATA) len=${decryptedData.size}")

        // Parse parent-level TLVs (7F27, 7F4D, 7F4E)
        val mainTlvMap = parseTlvRecursive(decryptedData)

        // --- 7F27: Endpoint Configuration ---
        val endpointConfig = mainTlvMap[0x7F27]?.firstOrNull()
        endpointConfig?.let { cfg ->
            val sub = parseTlvStreamMulti(cfg)
            peerInfo.vehicleIdentifier = sub[0x4D]?.firstOrNull()
            peerInfo.endpointName = sub[0x5F20]?.firstOrNull()?.toString(Charsets.UTF_8)
            peerInfo.instanceCaId = sub[0x42]?.firstOrNull()
            peerInfo.featureBitmap = sub[0x46]?.firstOrNull()
            peerInfo.protocolVersion = sub[0x5C]?.firstOrNull()
            // peerInfo.vehiclePk = sub[0x5B]?.firstOrNull()
            peerInfo.validFrom = sub[0x51]?.firstOrNull()
            peerInfo.validTo = sub[0x52]?.firstOrNull()
            peerInfo.authorizedPks = sub[0x49]
            peerInfo.keySlot = sub[0x4E]?.firstOrNull()
            peerInfo.counterLimit = sub[0x57]?.firstOrNull()
            peerInfo.confMailboxSize = sub[0x4A]?.firstOrNull()
            peerInfo.privMailboxSize = sub[0x4B]?.firstOrNull()

            log("🔹 Parsed Endpoint Config (7F27):")
            log("    Vehicle ID: ${peerInfo.vehicleIdentifier?.toHex()}")
            log("    Endpoint Name: ${peerInfo.endpointName}")
            log("    Protocol Ver: ${peerInfo.protocolVersion?.toHex()}")
            log("    Vehicle PK: ${peerInfo.vehiclePk?.size} bytes")
            log("    Key Slot: ${peerInfo.keySlot?.toHex()}")
            log("    Validity: ${peerInfo.validFrom?.toHex()} - ${peerInfo.validTo?.toHex()}")
        }

        // --- 7F4D: Mailbox Mapping ---
        val mailboxMapping = mainTlvMap[0x7F4D]?.firstOrNull()
        mailboxMapping?.let { mbx ->
            val sub = parseTlvStreamMulti(mbx)
            peerInfo.mailboxOffsets = mapOf(
                "D0" to sub[0xD0]?.firstOrNull(),
                "D1" to sub[0xD1]?.firstOrNull(),
                "D2" to sub[0xD2]?.firstOrNull()
            )
            log("🔹 Parsed Mailbox Mapping (7F4D):")
            peerInfo.mailboxOffsets?.forEach { (tag, value) ->
                log("    $tag → ${value?.toHex()}")
            }
        }

        // --- 7F4E: Device Configuration ---
        val deviceConfig = mainTlvMap[0x7F4E]?.firstOrNull()
        deviceConfig?.let { dev ->
            val sub = parseTlvStreamMulti(dev)
            peerInfo.deviceConfig = sub
            log("🔹 Parsed Device Config (7F4E): ${sub.keys.joinToString { "0x%02X".format(it) }}")
        }

        // --- Certificates (Vehicle / Intermediate) ---
        peerInfo.vehicleCert = mainTlvMap[0x7F21]?.firstOrNull()
        peerInfo.intermediateCert = mainTlvMap[0x7F22]?.firstOrNull()
        if (peerInfo.vehicleCert != null) log("🔹 Found Vehicle Cert (DER, ${peerInfo.vehicleCert!!.size} bytes)")
        if (peerInfo.intermediateCert != null) log("🔹 Found Intermediate Cert (DER, ${peerInfo.intermediateCert!!.size} bytes)")

        // Store top-level references for later AUTH0/AUTH1 use
        peerInfo.endpointConfig = endpointConfig
        peerInfo.mailboxMappingRaw = mailboxMapping
        peerInfo.deviceConfigRaw = deviceConfig

        log("✅ Endpoint Creation Data processed successfully")
    }

    private fun ByteArray.toHex(): String = joinToString(" ") { "%02X".format(it) }

    private fun buildDummyDigitalKeyCert(): ByteArray {
        val vehicleId = "VEHICLE123".toByteArray()
        val instanceCaId = "INSTANCE_CA_001".toByteArray()
        val digitalKeyData = "SIMULATED_DIGITAL_KEY".toByteArray()

        val output = ByteArrayOutputStream().apply {
            // 7F24 – Digital Key Certificate (constructed TLV)
            write(0x7F)
            write(0x24)
            // total length = sum of child TLVs + 6 (2 bytes per tag + length)
            val totalLen = vehicleId.size + instanceCaId.size + digitalKeyData.size + 6
            write(totalLen)

            // Tag 4D – Vehicle Identifier
            write(0x4D)
            write(vehicleId.size)
            write(vehicleId)

            // Tag 42 – Instance CA Identifier
            write(0x42)
            write(instanceCaId.size)
            write(instanceCaId)

            // Tag 5F20 – Simulated Key Data
            write(0x5F)
            write(0x20)
            write(digitalKeyData.size)
            write(digitalKeyData)
        }
        return output.toByteArray()
    }

    /** Sends SELECT command (Digital Key Applet AID) for Standard Transaction */

    fun sendSelectCommandForStandardTx(addr: String, msgHdr: Byte) {
        // Phase 3 SELECT command (no AID, just select environment)
        val selectApdu = byteArrayOf(
            0x00, 0xA4.toByte(), 0x01, 0x00, 0x00  // CLA=00, INS=A4, P1=01, P2=00, Lc=00
        )

        sendDkMessage(addr, msgHdr, 0x0B, selectApdu)

        log("📤 [TO KW45] Sent SELECT command (Standard Tx) → 00 A4 01 00 00")
        log("✅ Standard Transaction SELECT complete ")

    }


    fun sendSelectResponseForStandardTx(addr: String, incomingMsgHdr: Byte) {
        // --------------------------------------------------------------------
        // 📦 Build APDU Response payload according to spec
        // --------------------------------------------------------------------
        // Field breakdown:
        //  5C  → Tag: Supported Digital Key Applet Protocol Versions
        //  02  → Length: 2 bytes
        //  01 00 → Value: Supported version 1.0 (big endian)
        //  90 00 → Status Word (SW)
        // --------------------------------------------------------------------
        val apduResponse = byteArrayOf(
            0x5C, 0x02, 0x01, 0x00,  // Supported DK applet version 1.0
            0x90.toByte(), 0x00.toByte()  // SW = 9000 (Success)
        )

        // Wrap APDU inside DK message (MessageHeader=0x01, PayloadHeader=0x0C)
        sendDkMessage(addr, incomingMsgHdr, 0x0C, apduResponse)

        log(
            "📤 [TO KW45] Sent SELECT Response (Standard Tx): " +
                    "5C 02 01 00 90 00 → Supported DK applet v1.0"
        )
    }


    private fun extractTagFromTLV(data: ByteArray, searchTag: Int): ByteArray? {
        var idx = 0
        while (idx < data.size) {
            // Ensure tag and length can be read
            if (idx + 1 >= data.size) break
            val tag = data[idx].toInt() and 0xFF
            val len = data[idx + 1].toInt() and 0xFF
            idx += 2
            // Value length valid?
            if (len < 0 || idx + len > data.size) break
            val value = data.copyOfRange(idx, idx + len)
            // Is this the tag we're searching for?
            if (tag == searchTag) return value
            // Continue to next TLV
            idx += len
        }
        return null
    }



//    private fun buildAuth0ResponseForKw45(
//        endpointEpk: ByteArray? = null,
//        includeCryptogram: Boolean = false
//    ): ByteArray {
//        val out = ByteArrayOutputStream()
//
//        log("🔐 Building AUTH0 Response APDU...")
//
//        // ✅ SOLUTION: Use proper EC key generation
//        val epk = endpointEpk ?: run {
//            log("   🔑 Generating endpoint ephemeral key pair (P-256)...")
//
//            try {
//                // Use Android's KeyPairGenerator for proper EC keys
//                val keyGen = KeyPairGenerator.getInstance("EC")
//                val paramSpec = ECGenParameterSpec("prime256v1")
//                keyGen.initialize(paramSpec)
//
//                log("   ↳ KeyPairGenerator initialized for P-256")
//
//                // Generate keypair
//                val keyPair = keyGen.generateKeyPair()
//                val pubKey = keyPair.public as ECPublicKey
//
//                log("   ✓ KeyPair generated successfully")
//
//                // Extract EC point (W = public key point)
//                val ecPoint = pubKey.w
//                val xBytes = ecPoint.affineX.toByteArray()
//                val yBytes = ecPoint.affineY.toByteArray()
//
//                log("   ✓ EC point extracted: X=${xBytes.size} bytes, Y=${yBytes.size} bytes")
//
//                // Build uncompressed format: 0x04 || X (padded to 32) || Y (padded to 32)
//                val epkBytes = ByteArray(65)
//                epkBytes[0] = 0x04  // Uncompressed point marker
//
//                // Copy X coordinate (pad to 32 bytes if necessary)
//                val xPadded = if (xBytes.size < 32) {
//                    ByteArray(32 - xBytes.size) + xBytes  // Pad with leading zeros
//                } else {
//                    xBytes.takeLast(32).toByteArray()
//                }
//                System.arraycopy(xPadded, 0, epkBytes, 1, 32)
//
//                // Copy Y coordinate (pad to 32 bytes if necessary)
//                val yPadded = if (yBytes.size < 32) {
//                    ByteArray(32 - yBytes.size) + yBytes  // Pad with leading zeros
//                } else {
//                    yBytes.takeLast(32).toByteArray()
//                }
//                System.arraycopy(yPadded, 0, epkBytes, 33, 32)
//
//                // ✅ Verification: Count non-zero bytes
//                val nonZeroCount = epkBytes.count { it != 0.toByte() }
//                log("   ✓ Endpoint ePK generated: $nonZeroCount/65 bytes non-zero")
//                log("      X starts with: ${xPadded.take(4).joinToString(" ") { "%02X".format(it) }}")
//                log("      Y starts with: ${yPadded.take(4).joinToString(" ") { "%02X".format(it) }}")
//
//                // ✅ Fail if all zeros (should never happen with real EC key)
//                if (nonZeroCount < 10) {
//                    throw RuntimeException("Generated EC key appears invalid (too many zeros)")
//                }
//
//                epkBytes
//
//            } catch (e: Exception) {
//                log("   ❌ EC key generation failed: ${e.message}")
//                log("   → Falling back to deterministic key")
//
//                // Fallback: Use a deterministic non-zero key (for testing only)
//                generateFallbackEphemeralKey()
//            }
//        }
//
//        // Step 2: Build response TLV
//        log("   📦 Building TLV response...")
//
//        // Tag 0x86: Endpoint Ephemeral Public Key
//        log("   ↳ Adding Tag 0x86 (Endpoint ePK): 65 bytes")
//        out.write(0x86)           // TAG
//        out.write(65)             // LENGTH
//        out.write(epk)            // VALUE (65 bytes)
//
//        // Status Word: 9000 (Success)
//        log("   ↳ Adding Status Word: 9000")
//       // out.write(0x90.toByte)
//       // out.write(0x00.toByte)
//        out.write(byteArrayOf(0x90.toByte(), 0x00.toByte()))
//
//        val response = out.toByteArray()
//
//        log("✅ AUTH0 Response built: ${response.size} bytes")
//        log("   Hex: ${response.joinToString(" ") { "%02X".format(it) }}")
//
//        return response
//    }

    private fun buildAuth0ResponseForKw45(
        peerDeviceId: Int, // Make sure peerDeviceId is always supplied by the caller!
        endpointEpk: ByteArray? = null,
        includeCryptogram: Boolean = false
    ): ByteArray {
        val out = ByteArrayOutputStream()
        log("🔐 Building AUTH0 Response APDU...")

        val epk = endpointEpk ?: run {
            log("   🔑 Generating endpoint ephemeral key pair (P-256)...")
            try {
                val keyGen = KeyPairGenerator.getInstance("EC")
                val paramSpec = ECGenParameterSpec("prime256v1")
                keyGen.initialize(paramSpec)
                log("   ↳ KeyPairGenerator initialized for P-256")

                val keyPair = keyGen.generateKeyPair()
                val pubKey = keyPair.public as ECPublicKey

                // Store the endpoint private key for future AUTH1 use (ECDH)
                maPeerInformation[peerDeviceId].endpointPrivateKey = keyPair.private
                log("✅ Stored endpoint private key for AUTH1")

                val ecPoint = pubKey.w
                val xBytes = ecPoint.affineX.toByteArray()
                val yBytes = ecPoint.affineY.toByteArray()

                val epkBytes = ByteArray(65)
                epkBytes[0] = 0x04

                val xPadded = if (xBytes.size < 32) {
                    ByteArray(32 - xBytes.size) + xBytes
                } else {
                    xBytes.takeLast(32).toByteArray()
                }
                System.arraycopy(xPadded, 0, epkBytes, 1, 32)

                val yPadded = if (yBytes.size < 32) {
                    ByteArray(32 - yBytes.size) + yBytes
                } else {
                    yBytes.takeLast(32).toByteArray()
                }
                System.arraycopy(yPadded, 0, epkBytes, 33, 32)

                val nonZeroCount = epkBytes.count { it != 0.toByte() }
                log("   ✓ Endpoint ePK generated: $nonZeroCount/65 bytes non-zero")
                log("      X starts with: ${xPadded.take(4).joinToString(" ") { "%02X".format(it) }}")
                log("      Y starts with: ${yPadded.take(4).joinToString(" ") { "%02X".format(it) }}")

                if (nonZeroCount < 10) {
                    throw RuntimeException("Generated EC key appears invalid (too many zeros)")
                }

                epkBytes
            } catch (e: Exception) {
                log("   ❌ EC key generation failed: ${e.message}")
                log("   → Falling back to deterministic key")
                generateFallbackEphemeralKey()
            }
        }

        // Step 2: Build response TLV
        log("   📦 Building TLV response...")

        // Tag 0x86: Endpoint Ephemeral Public Key
        log("   ↳ Adding Tag 0x86 (Endpoint ePK): 65 bytes")
        out.write(0x86)           // TAG
        out.write(65)             // LENGTH
        out.write(epk)            // VALUE (65 bytes)

        log("   ↳ Adding Status Word: 9000")
        out.write(byteArrayOf(0x90.toByte(), 0x00.toByte()))

        val response = out.toByteArray()
        log("✅ AUTH0 Response built: ${response.size} bytes")
        log("   Hex: ${response.joinToString(" ") { "%02X".format(it) }}")
        return response
    }


    // Fallback helper function
    private fun generateFallbackEphemeralKey(): ByteArray {
        log("   🔄 Generating fallback ephemeral key with verification...")

        val epkBytes = ByteArray(65)
        epkBytes[0] = 0x04

        // ✅ FIX: Create array FIRST, then fill it directly (not copyOfRange)
        val randomBuffer = ByteArray(64)

        var attempts = 0
        var isAllZeros = true

        while (isAllZeros && attempts < 5) {
            attempts++
            SecureRandom().nextBytes(randomBuffer)

            // Check if we got non-zero bytes
            isAllZeros = randomBuffer.all { it == 0.toByte() }

            if (!isAllZeros) {
                // Copy to ePK array
                System.arraycopy(randomBuffer, 0, epkBytes, 1, 64)
                log("   ✓ Fallback random ePK generated (attempt $attempts)")
                break
            }
        }

        if (isAllZeros) {
            log("   ❌ CRITICAL: Unable to generate non-zero random bytes!")
            throw RuntimeException("SecureRandom failed after $attempts attempts")
        }

        val nonZeroCount = epkBytes.count { it != 0.toByte() }
        log("   ✓ Non-zero bytes: $nonZeroCount/65")

        return epkBytes
    }


    private fun parseAuth0Tags(payload: ByteArray) {
        var idx = 0
        while (idx < payload.size) {
            val tag = payload[idx].toInt() and 0xFF
            if (idx + 1 >= payload.size) break
            val len = payload[idx + 1].toInt() and 0xFF
            val start = idx + 2
            val end = (start + len).coerceAtMost(payload.size)
            val value = payload.copyOfRange(start, end)
            when (tag) {
                0x5C -> log("🔹 AUTH0: Protocol Version = ${value.joinToString(" ") { "%02X".format(it) }}")
                0x87 -> log("🔹 AUTH0: Vehicle ePK = ${value.take(4).joinToString(" ") { "%02X".format(it) }}...")
                0x4C -> log("🔹 AUTH0: Transaction ID = ${value.joinToString(" ") { "%02X".format(it) }}")
                0x4D -> log("🔹 AUTH0: Vehicle ID = ${value.joinToString(" ") { "%02X".format(it) }}")
                else -> log("ℹ️ AUTH0: Unknown tag ${"%02X".format(tag)} len=$len")
            }
            idx = end
        }
    }

    private fun buildAuth1ResponseProper(peerDeviceId: Int): ByteArray {
        val peerInfo = maPeerInformation[peerDeviceId]

        log("🔐 Building AUTH1 Response (KW45 compatible)...")

        // Get encryption keys (must be derived from ECDH in AUTH1 handler)
        val kenc = peerInfo.kenc ?: return ByteArray(0).also {
            log("❌ Kenc not available - derivation failed")
        }
        val krmac = peerInfo.krmac ?: return ByteArray(0).also {
            log("❌ Krmac not available - derivation failed")
        }

        // ============================================================
        // STEP 1: Build plaintext TLV payload
        // ============================================================

        val plaintextStream = ByteArrayOutputStream()

        // Tag 0x4E: key_slot (1-8 bytes, mandatory per spec Table 15-33)
        val keySlot = peerInfo.keySlot ?: byteArrayOf(0x01)

        plaintextStream.write(0x4E)           // Tag
        plaintextStream.write(keySlot.size)   // Length
        plaintextStream.write(keySlot)        // Value

        log("   ✓ Tag 0x4E (key_slot): ${keySlot.size} bytes = ${keySlot.joinToString(" ") { "%02X".format(it) }}")

        // Tag 0x9E: endpoint_sig (64 bytes, mandatory per spec Table 15-33)
        // This must be computed by device to prove ownership of endpoint private key
        val endpointSignature = computeEndpointSignature(peerDeviceId)

        plaintextStream.write(0x9E)           // Tag
        plaintextStream.write(0x40)           // Length: 64 bytes (fixed)
        plaintextStream.write(endpointSignature)  // Value (64 bytes)

        log("   ✓ Tag 0x9E (endpoint_sig): 64 bytes")

        // Tag 0x4A: confidential_mailbox_data_subset (optional, conditional)
        // Per Table 15-33: included if configured via SETUP ENDPOINT
        val confMailbox = peerInfo.confMailboxSize ?: byteArrayOf(0x10, 0x20, 0x30, 0x40)
        if (confMailbox.isNotEmpty()) {
            plaintextStream.write(0x4A)           // Tag
            plaintextStream.write(confMailbox.size)  // Length
            plaintextStream.write(confMailbox)   // Value
            log("   ✓ Tag 0x4A (conf_mailbox): ${confMailbox.size} bytes")
        }

        // Tag 0x4B: private_mailbox_data_subset (optional, conditional)
        // Per Table 15-33: included if configured via SETUP ENDPOINT
        val privMailbox = peerInfo.privMailboxSize ?: byteArrayOf(0x99.toByte(),
            0x88.toByte(), 0x77, 0x66)
        if (privMailbox.isNotEmpty()) {
            plaintextStream.write(0x4B)           // Tag
            plaintextStream.write(privMailbox.size)  // Length
            plaintextStream.write(privMailbox)   // Value
            log("   ✓ Tag 0x4B (priv_mailbox): ${privMailbox.size} bytes")
        }

        val plaintext = plaintextStream.toByteArray()
        log("   📦 Plaintext TLV: ${plaintext.size} bytes")

        // ============================================================
        // STEP 2: Encrypt plaintext with Kenc (AES-128 CBC)
        // ============================================================

        val encrypted = try {
            val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = javax.crypto.spec.SecretKeySpec(kenc, "AES")
            val iv = javax.crypto.spec.IvParameterSpec(ByteArray(16))  // Zero IV per KW45

            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, iv)
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            log("   ❌ Encryption failed: ${e.message}")
            return ByteArray(0)
        }

        log("   🔒 Encrypted: ${encrypted.size} bytes")

        // ============================================================
        // STEP 3: Compute response MAC with Krmac
        // ============================================================
        // Per CCC spec: MAC = HMAC(counter || encrypted_payload || SW)

        val sw = byteArrayOf(0x90.toByte(), 0x00.toByte())

        // Counter (4 bytes, big-endian) - incremented for each response
        val counter = peerInfo.responseCounter
        val counterBytes = ByteArray(4) { i ->
            (counter shr (8 * (3 - i)) and 0xFF).toByte()
        }

        // MAC input: counter + encrypted + status word
        val macInput = counterBytes + encrypted + sw

        val mac = try {
            val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
            hmac.init(javax.crypto.spec.SecretKeySpec(krmac, "HmacSHA256"))

            val fullMac = hmac.doFinal(macInput)
            // Per CCC spec: Use first 8 bytes of HMAC output
            fullMac.copyOfRange(0, 8)
        } catch (e: Exception) {
            log("   ❌ MAC computation failed: ${e.message}")
            return ByteArray(0)
        }

        log("   🔐 Response MAC (8 bytes): ${mac.joinToString(" ") { "%02X".format(it) }}")

        // ============================================================
        // STEP 4: Build final response
        // ============================================================
        // Response structure per CCC spec:
        // [Encrypted TLV payload] + [MAC 8 bytes] + [Status Word (0x90 0x00)]

        peerInfo.responseCounter++  // Increment for next response

        val response = encrypted + mac + sw

        log("✅ AUTH1 Response built: ${response.size} bytes")
        log("   Structure:")
        log("      Encrypted TLV:  ${encrypted.size} bytes")
        log("      MAC:             8 bytes")
        log("      Status Word:     2 bytes (90 00)")
        log("   Total:             ${response.size} bytes")
        log("   Hex (first 20): ${response.take(20).joinToString(" ") { "%02X".format(it) }}...")

        return response
    }

    private fun computeEndpointSignature(peerDeviceId: Int): ByteArray {
        val peerInfo = maPeerInformation[peerDeviceId]

        try {
            // Gather all input fields per CCC spec Table 15-33
            val vehicleId = peerInfo.vehicleIdentifier ?: ByteArray(8) { 0x88.toByte() }
            val endpointEpkX = extractXCoordinate(peerInfo.endpointPublicKey)  // 32 bytes
            val vehicleEpkX = extractXCoordinate(peerInfo.vehicleEpk)          // 32 bytes
            val transactionId = ByteArray(16) { 0x00.toByte() }  // From AUTH0
            val usage = byteArrayOf(0x4E, 0x88.toByte(), 0x7B, 0x4C)      // 4 bytes per spec

            // Concatenate all fields for signing (Table 15-33)
            val dataToSign = vehicleId + endpointEpkX + vehicleEpkX + transactionId + usage

            // log("   📋 Signing data: ${dataToSign.size} bytes")
            log("      vehicle_id(8) + endpoint_ePK_x(32) + vehicle_ePK_x(32) + txn_id(16) + usage(4)")

            // Sign with endpoint private key
            val signature = if (peerInfo.endpointPrivateKey != null) {
                val sig = java.security.Signature.getInstance("SHA256withECDSA")
                sig.initSign(peerInfo.endpointPrivateKey as java.security.PrivateKey)
                sig.update(dataToSign)

                var sigBytes = sig.sign()

                // Normalize to 64 bytes (r=32, s=32)
                // ECDSA output can be 70-72 bytes (DER encoded), extract last 64
                if (sigBytes.size > 64) {
                    sigBytes = sigBytes.copyOfRange(sigBytes.size - 64, sigBytes.size)
                } else if (sigBytes.size < 64) {
                    val padded = ByteArray(64)
                    System.arraycopy(sigBytes, 0, padded, 64 - sigBytes.size, sigBytes.size)
                    sigBytes = padded
                }

                log("   ✓ Generated ECDSA signature: ${sigBytes.size} bytes")
                sigBytes
            } else {
                // Fallback: deterministic signature (for testing without real key)
                log("   ⚠️ No endpoint private key, using deterministic fallback")
                ByteArray(64) { i -> ((i * 13 + 99) and 0xFF).toByte() }
            }

            return signature

        } catch (e: Exception) {
            log("   ❌ Signature computation failed: ${e.message}")
            // Return fallback signature so transaction can continue for testing
            return ByteArray(64) { i -> ((i * 7 + 42) and 0xFF).toByte() }
        }
    }

    private fun extractXCoordinate(publicKeyOrPoint: Any?): ByteArray {
        return when (publicKeyOrPoint) {
            is ByteArray -> {
                if (publicKeyOrPoint.size == 65 && publicKeyOrPoint[0] == 0x04.toByte()) {
                    publicKeyOrPoint.copyOfRange(1, 33)  // Extract X (32 bytes)
                } else {
                    ByteArray(32) { 0x00.toByte() }
                }
            }
            is java.security.interfaces.ECPublicKey -> {
                val point = publicKeyOrPoint.w
                val xBytes = point.affineX.toByteArray()
                if (xBytes.size < 32) {
                    val padded = ByteArray(32)
                    System.arraycopy(xBytes, 0, padded, 32 - xBytes.size, xBytes.size)
                    padded
                } else {
                    xBytes.copyOfRange(maxOf(0, xBytes.size - 32), xBytes.size)
                }
            }
            else -> ByteArray(32) { 0x00.toByte() }
        }
    }


    private fun deriveAuth1Keys(peerDeviceId: Int): Boolean {
        val peerInfo = maPeerInformation[peerDeviceId]

        val vehicleEpk = peerInfo.vehicleEpk ?: return false
        val endpointPrivateKey = peerInfo.endpointPrivateKey ?: return false

        return try {
            val ecPoint = parseECPoint(vehicleEpk)
            val kdh = performECDH(endpointPrivateKey as java.security.PrivateKey, ecPoint)

            peerInfo.kenc = deriveKeyFromSharedSecret(kdh, "Kenc", 16)
            peerInfo.kmac = deriveKeyFromSharedSecret(kdh, "Kmac", 16)
            peerInfo.krmac = deriveKeyFromSharedSecret(kdh, "Krmac", 16)

            log("✅ Derived: Kenc, Kmac, Krmac")
            true
        } catch (e: Exception) {
            log("❌ Derivation failed: ${e.message}")
            false
        }
    }

    private fun performECDH(
        privateKey: java.security.PrivateKey,
        publicPoint: java.security.spec.ECPoint
    ): ByteArray {
        val keyAgreement = javax.crypto.KeyAgreement.getInstance("ECDH")

        val publicKeySpec = java.security.spec.ECPublicKeySpec(
            publicPoint,
            (privateKey as? java.security.interfaces.ECKey)?.params
                ?: throw RuntimeException("Invalid EC key")
        )

        val keyFactory = java.security.KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(publicKeySpec)

        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)

        return keyAgreement.generateSecret()
    }

    private fun deriveKeyFromSharedSecret(
        sharedSecret: ByteArray,
        label: String,
        length: Int
    ): ByteArray {
        val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
        hmac.init(javax.crypto.spec.SecretKeySpec(sharedSecret, "HmacSHA256"))

        val fullHash = hmac.doFinal(label.toByteArray() + byteArrayOf(0x00))
        return fullHash.copyOfRange(0, minOf(length, fullHash.size))
    }

//    private fun computeCommandMac(
//        payload: ByteArray,
//        kmac: ByteArray,
//        counter: Int
//    ): ByteArray {
//        val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
//        hmac.init(javax.crypto.spec.SecretKeySpec(kmac, "HmacSHA256"))
//
//        val counterBytes = ByteArray(4) { i ->
//            (counter shr (8 * (3 - i)) and 0xFF).toByte()
//        }
//
//        val macInput = counterBytes + payload
//        val fullMac = hmac.doFinal(macInput)
//
//        return fullMac.copyOfRange(0, 8)
//    }


    private fun computeCommandMac(
        payload: ByteArray,
        kmac: ByteArray,
        counter: Int
    ): ByteArray {
        val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
        hmac.init(javax.crypto.spec.SecretKeySpec(kmac, "HmacSHA256"))

        // Build 4-byte counter (big-endian)
        val counterBytes = ByteArray(4) { i ->
            (counter shr (8 * (3 - i)) and 0xFF).toByte()
        }

        // FIX: Always prepend counterBytes to payload when computing MAC.
        val macInput = counterBytes + payload

        val fullMac = hmac.doFinal(macInput)
        return fullMac.copyOfRange(0, 8)
    }

    private fun aesDecrypt(ciphertext: ByteArray, key: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
        val iv = javax.crypto.spec.IvParameterSpec(ByteArray(16))

        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, iv)
        return cipher.doFinal(ciphertext)
    }

    private fun parseECPoint(epkBytes: ByteArray): java.security.spec.ECPoint {
        if (epkBytes.size != 65 || epkBytes[0] != 0x04.toByte()) {
            throw RuntimeException("Invalid EC point")
        }

        val x = java.math.BigInteger(1, epkBytes.copyOfRange(1, 33))
        val y = java.math.BigInteger(1, epkBytes.copyOfRange(33, 65))

        return java.security.spec.ECPoint(x, y)
    }

    private fun buildAuth1Response(): ByteArray {
        val stream = ByteArrayOutputStream()

        // Tag 4E: key_slot (1 byte)
        val keySlot = byteArrayOf(0x01)
        stream.write(0x4E)
        stream.write(keySlot.size)
        stream.write(keySlot)

        // Tag 9E: endpoint_sig (64 bytes, dummy)
        val endpointSig = ByteArray(64) { 0xAA.toByte() }
        stream.write(0x9E)
        stream.write(0x40) // length 64
        stream.write(endpointSig)

        // Optional: Tag 4A confidential mailbox subset (dummy)
        val confData = "CONFMAIL".toByteArray()
        stream.write(0x4A)
        stream.write(confData.size)
        stream.write(confData)

        // Optional: Tag 4B private mailbox subset (dummy)
        val privData = "PRIVMAIL".toByteArray()
        stream.write(0x4B)
        stream.write(privData.size)
        stream.write(privData)

        // Status Word 9000
        stream.write(byteArrayOf(0x90.toByte(), 0x00.toByte()))
        return stream.toByteArray()
    }





    fun stopDiscovery() {
        log("STOP_SCAN")
        val mgr = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        mgr.adapter?.bluetoothLeScanner?.let { it.stopScan(scanCallback) }
    }


    // ======== Optional: close everything cleanly ========
    fun closeAll() {
        stopDiscovery()
        l2capOutput.values.forEach {
            try {
                it.close()
            } catch (_: Exception) {
            }
        }
        l2capOutput.clear()
        connectedGatts.values.forEach {
            try {
                it.close()
            } catch (_: Exception) {
            }
        }
        connectedGatts.clear()
    }


    private fun handleCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        status: Int
    ) {
        log("CHAR_READ: ${characteristic.uuid} status=$status")
        // store or process characteristic read
        val peerDeviceId = findPeerIdByAddress(gatt.device.address)
        if (peerDeviceId != INVALID_DEVICE_ID) {
            stateMachineHandler(peerDeviceId, AppEvent.READ_CHARACTERISTIC_VALUE_COMPLETE)
        }
    }


    /** Detect Owner Pairing request, run mock SPAKE, and trigger system
    bonding. */
    private fun handleCharacteristicChanged(
        gatt: BluetoothGatt, ch:
        BluetoothGattCharacteristic
    ) {
        val payload = ch.value ?: return
        if (ch.uuid != VEHICLE_PSM_CHAR_UUID) return
        log("CHAR_CHANGED: ${ch.uuid}")
        if (payload.size >= 2 && payload[0] == DkMessageType.FRAMEWORK_MESSAGE.value) {
            val opcode = payload[1]
            //if (ch.uuid == VEHICLE_PSM_CHAR_UUID) {
            //val payload = ch.value ?: return
            when (opcode) {
                PAIRING_RESPONSE_CMD -> {
                    log("Pairing: received PairingResponse from ${gatt.device.address}")
                    val resp = payload.copyOfRange(2, payload.size)
                    val id = findPeerIdByAddress(gatt.device.address)
                    if (id != INVALID_DEVICE_ID) {
                        maPeerInformation[id].peerOobData = resp
                        stateMachineHandler(id, AppEvent.RECEIVED_SPAKE_VERIFY)
                    }
                }

                PAIRING_COMPLETE_CMD -> {
                    log("Pairing: received PairingComplete from ${gatt.device.address}")
                    val id = findPeerIdByAddress(gatt.device.address)
                    if (id != INVALID_DEVICE_ID) {
                        stateMachineHandler(id, AppEvent.PAIRING_COMPLETE)
                    }
                }

                else -> { /* fall through to old owner-pairing checks */
                }
            }
        }
        if (isOwnerPairingRequest(payload)) {
            val addr = gatt.device.address
            log("OWNER_PAIRING_REQUEST detected from $addr")
            onOwnerPairingRequested?.invoke(addr) // let UI prompt for PIN
// Kick off bonding via system pairing UI/flow
            triggerSystemBond(gatt)
// Start SPAKE mock handshake over GATT
            startSpakeHandshakeOverGatt(gatt, addr)
        } else if (isSpakeVerifyMessage(payload)) {
            val ok = handleSpakeVerify(payload)
            log("SPAKE_VERIFY result=$ok")
            val peerId = findPeerIdByAddress(gatt.device.address)
            if (ok && peerId != INVALID_DEVICE_ID)
                stateMachineHandler(peerId, AppEvent.RECEIVED_SPAKE_VERIFY)
        }
    }


    private fun isOwnerPairingRequest(bytes: ByteArray): Boolean {
// Demo framing: [0x03 (DK_EVENT_NOTIFICATION), 0x01 (COMMAND_COMPLETE),
        // 0x01 (REQUEST_OWNER_PAIRING), ...]
        return bytes.size >= 3 &&
                bytes[0] == DkMessageType.DK_EVENT_NOTIFICATION.value &&
                bytes[1] == DkSubEventCategory.COMMAND_COMPLETE.value &&
                bytes[2] ==
                DkSubEventCommandCompleteType.REQUEST_OWNER_PAIRING.value


    }

    private fun isSpakeVerifyMessage(bytes: ByteArray): Boolean {
// Demo framing: [0x03, 0x01, 0x02 (BLE_PAIRING_READY),
        // 'S','P','A','K','E', ...]
        return bytes.size >= 3 &&
                bytes[0] == DkMessageType.DK_EVENT_NOTIFICATION.value &&
                bytes[1] == DkSubEventCategory.COMMAND_COMPLETE.value &&
                bytes[2] ==
                DkSubEventCommandCompleteType.BLE_PAIRING_READY.value
    }

    @SuppressLint("MissingPermission")
    private fun triggerSystemBond(gatt: BluetoothGatt) {
        try {
            log("STEP: Requesting system bonding for ${gatt.device.address}")
            val ok = gatt.device.createBond()
            log("createBond() called: $ok for ${gatt.device.address}")
        } catch (e: SecurityException) {
            log("createBond SecurityException: $ {e.message}")
            log("createBond() invoked -> result=$ok (Android handles key exchange)")
        }
    }

    /** Send SPAKE msg1 (mock) via DK char; expect msg2 in notifications later.
     */
    @SuppressLint("MissingPermission")
    private fun startSpakeHandshakeOverGatt(gatt: BluetoothGatt, addr: String) {
        val pin = getOwnerPin(addr)
        if (pin.isNullOrBlank()) {
            log("No Owner PIN cached yet for $addr – SPAKE start postponed"); return
        }
        val (msg1, expected) = Spake2EngineMock.start(pin)
        // Frame: [0x01 (FRAMEWORK_MESSAGE), 0xAA (SPAKE_REQ), <len><data>]
        val frame = ByteBuffer.allocate(
            2 +
                    msg1.size
        ).put(0x01).put(0xAA.toByte()).put(msg1).array()
        val service = gatt.getService(CCC_DK_SERVICE_UUID)
        val dkChar = service?.getCharacteristic(VEHICLE_PSM_CHAR_UUID)
        if (dkChar == null) {
            log("DK PSM characteristic not found"); return
        }
        dkChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        dkChar.value = frame
        //That is a write to the vehicle’s VEHICLE_PSM_CHAR_UUID characteristic – i.e. data going from phone → device
        val writeOk = gatt.writeCharacteristic(dkChar)
        log("SPAKE msg1 write: $writeOk (len=${frame.size})")
        // Store the expected prefix in our peer slot to validate later
        val peerId = findPeerIdByAddress(addr)
        if (peerId != INVALID_DEVICE_ID) maPeerInformation[peerId].peerOobData = expected
        stateMachineHandler(peerId, AppEvent.SENT_SPAKE_RESPONSE)
        log("➡️ Sending SPAKE msg1 (${frame.size} bytes) to ${gatt.device.address}")
    }

    private fun handleSpakeVerify(payload: ByteArray): Boolean {
        val peerId = (0 until MAX_CONNECTIONS).firstOrNull {
            maPeerInformation[it].deviceId != INVALID_DEVICE_ID
        } ?: return false
        val expected = maPeerInformation[peerId].peerOobData ?: return false
// Remove 3-byte header [03,01,02] for demo
        val msg2 = payload.copyOfRange(3, payload.size)
        return Spake2EngineMock.verify(msg2, expected)

    }

    /**
     * State machine: handles transitions you sketched out
     */
    fun stateMachineHandler(peerDeviceId: Int, event: AppEvent) {
        if (peerDeviceId < 0 || peerDeviceId >= MAX_CONNECTIONS) return
        val peerInfo = maPeerInformation[peerDeviceId]
        log("SM: peer=$peerDeviceId state=${peerInfo.appState} event=$event")

        when (peerInfo.appState) {
            AppState.IDLE -> {
                if (event == AppEvent.PEER_CONNECTED) {
                    // after connection: we had requested MTU earlier; await MTU or force now
                    peerInfo.appState = AppState.EXCHANGE_MTU
                }
            }

            AppState.EXCHANGE_MTU -> {
                when (event) {
                    AppEvent.GATT_PROC_COMPLETE -> {
                        peerInfo.appState = AppState.SERVICE_DISC
                        startServiceDiscovery(peerDeviceId)
                    }

                    AppEvent.GATT_PROC_ERROR -> disconnectDevice(peerDeviceId)
                    else -> {}
                }
            }

            AppState.SERVICE_DISC -> {
                when (event) {
                    AppEvent.SERVICE_DISCOVERY_COMPLETE -> {
                        // After service discovery, read required chars or enable notifications.
                        peerInfo.appState = AppState.CCC_PHASE2_WAITING_FOR_REQUEST
                        // Example: enable notifications on PSM char (if present)
                        enableNotificationsForPeer(peerDeviceId)
                    }

                    AppEvent.SERVICE_DISCOVERY_FAILED -> disconnectDevice(peerDeviceId)
                    else -> {}
                }
            }

            AppState.CCC_PHASE2_WAITING_FOR_REQUEST -> {
                if (event == AppEvent.SENT_SPAKE_RESPONSE) {
                    peerInfo.appState = AppState.CCC_PHASE2_WAITING_FOR_VERIFY
                }
            }

            AppState.CCC_PHASE2_WAITING_FOR_VERIFY -> {
                if (event == AppEvent.RECEIVED_SPAKE_VERIFY) {
                    peerInfo.appState = AppState.CCC_WAITING_FOR_PAIRING_READY
                }
            }

            AppState.CCC_WAITING_FOR_PAIRING_READY -> {
                if (event == AppEvent.RECEIVED_PAIRING_READY) {
                    mCurrentPeerId = peerDeviceId
                    generateLocalOobData()
                    peerInfo.appState = AppState.PAIR
                }
            }

            AppState.PAIR -> {
                if (event == AppEvent.PAIRING_COMPLETE) {
                    peerInfo.appState = AppState.RUNNING
                }
            }

            AppState.RUNNING -> {
                // Normal operational flows
            }
        }

        if (event == AppEvent.PEER_DISCONNECTED) {
            peerInfo.deviceId = INVALID_DEVICE_ID
            peerInfo.appState = AppState.IDLE
            peerInfo.customInfo = CustomInfo()
            log("Peer $peerDeviceId set to IDLE")
        }
    }

    /**
     * Helpers
     */
    private fun findAvailablePeerId(): Int {
        for (i in maPeerInformation.indices) {
            if (maPeerInformation[i].deviceId == INVALID_DEVICE_ID) return i
        }
        return INVALID_DEVICE_ID
    }

    private fun findPeerIdByAddress(address: String): Int {
        // connectedGatts -> find peer slot by stored bonded address (simple approach)
        for (i in maPeerInformation.indices) {
            val gatt = connectedGatts[address]
            if (gatt != null && maPeerInformation[i].deviceId != INVALID_DEVICE_ID) {
                // naive match if slot contains same address
                val slot = maPeerInformation[i]
                // we only store deviceId there; since we set deviceId to slot index, match by index
                // better approach: store device address in AppPeerInfo in real implementation
                return i
            }
        }
        // fallback: return first matching by comparing addresses to connectedGatts keys
        return maPeerInformation.indices.firstOrNull { maPeerInformation[it].deviceId != INVALID_DEVICE_ID }
            ?: INVALID_DEVICE_ID
    }

    private fun checkIfBonded(address: String): Boolean {
        // quick check against Android bonded devices list
        val bonded = bluetoothAdapter.bondedDevices.any { it.address == address }
        log("checkIfBonded($address)=${bonded}")
        return bonded
    }

    private fun startServiceDiscovery(peerDeviceId: Int) {
        // find GATT by peer slot -> here we try to discover on all connected GATTs and match by peer id
        for ((addr, gatt) in connectedGatts) {
            // we attempt discoverServices — caller will filter in callbacks
            gatt.discoverServices()
        }
    }

    private fun storeServiceHandles(peerDeviceId: Int, gatt: BluetoothGatt) {
        // Find the DK service and store handles
        val service = gatt.getService(CCC_DK_SERVICE_UUID)
        if (service != null) {
            val psmChar = service.getCharacteristic(VEHICLE_PSM_CHAR_UUID)
            val antennaChar = service.getCharacteristic(ANTENNA_ID_CHAR_UUID)
            val txPowerChar = service.getCharacteristic(TX_POWER_CHAR_UUID)
            if (psmChar != null) {
                maPeerInformation[peerDeviceId].customInfo.hPsmChannelChar = 1
            }
            if (antennaChar != null) {
                maPeerInformation[peerDeviceId].customInfo.hAntennaIdChar = 1
            }
            if (txPowerChar != null) {
                maPeerInformation[peerDeviceId].customInfo.hTxPowerChar = 1
            }
            log("storeServiceHandles: stored for peer $peerDeviceId")
        } else {
            log("storeServiceHandles: no DK service on ${gatt.device.address}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun enableNotificationsForPeer(peerDeviceId: Int) {
        connectedGatts.forEach { (_, gatt) ->
            val service = gatt.getService(CCC_DK_SERVICE_UUID)
            val char = service?.getCharacteristic(VEHICLE_PSM_CHAR_UUID)
            if (char != null) {
                val success = gatt.setCharacteristicNotification(char, true)
                if (!success) {
                    log("❌ Failed to setCharacteristicNotification for ${char.uuid}")
                    return@forEach
                }

                val cccdUuid = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                val cccd = char.getDescriptor(cccdUuid)

                if (cccd != null) {
                    if (char.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0) {
                        cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                    } else if (char.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE != 0) {
                        cccd.setValue(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
                    }

                    val writeOk = gatt.writeDescriptor(cccd)
                    log("Notifications enabled for ${gatt.device.address}, writeOk=$writeOk")
                } else {
//                     log("⚠️ CCCD not found for ${char.uuid}")
                    openDynamicL2capChannel(gatt.device.address) // try opening L2CAP directly
                }
            }
        }
    }


    private fun generateLocalOobData() {
        // Placeholder: generate OOB and store in AppPeerInfo
        log("Generating local OOB data (placeholder) - use proper SPAKE and secure storage in prod")
        if (mCurrentPeerId != INVALID_DEVICE_ID) {
            maPeerInformation[mCurrentPeerId].oobData = DUMMY_PAYLOAD
        }
    }

    private fun disconnectDevice(peerDeviceId: Int) {
        val peerInfo = maPeerInformation[peerDeviceId]
        // attempt to find GATT by peer index address
        // for demo: disconnect all connected GATTs whose device is bonded
        connectedGatts.values.forEach { gatt ->
            gatt.disconnect()
        }
    }

    fun disconnectAllDevices() {
        connectedGatts.values.forEach { gatt ->
            try {
                gatt.disconnect()
                gatt.close()
            } catch (e: Exception) {
                log("Error disconnecting: ${e.message}")
            }
        }
        connectedGatts.clear()
    }

    private fun factoryReset() {
        // remove bonding info stored by app. This does not remove Android-level bonds.
        log("Factory reset called: clearing app-level data")
        for (i in maPeerInformation.indices) {
            maPeerInformation[i] = AppPeerInfo()
        }
    }

    // Bonding data methods (placeholders)
    private fun setBondingData(bondData: AppBondingData) {
        // save to shared preferences (demo only)
        log("Saving bonding data for index ${bondData.nvmIndex}")
        // TODO: actually persist securely using Android Keystore or encrypted prefs
    }

    private fun listBondingData() {
        log("Listing stored bonding data (placeholder)")
    }

    private fun removeBondingData(index: Int) {
        log("Removing bonding entry $index (placeholder)")
    }
}