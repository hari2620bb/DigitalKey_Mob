package com.wnc.createaccount.ui

// Imports assumed
import android.Manifest
import android.bluetooth.*
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.concurrent.thread

// CCC UUIDs
val DK_SERVICE_UUID = java.util.UUID.fromString("0000fff5-0000-1000-8000-00805f9b34fb")
val SPSM_CHAR_UUID = java.util.UUID.fromString("d3b5a130-9e23-4b3a-8be4-6b1ee5f980a3")

@RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
fun connectAndOpenL2cap(context: Context, piAddr: String) {
    val btAdapter = BluetoothAdapter.getDefaultAdapter()
    val device = btAdapter.getRemoteDevice(piAddr)

    val gattCallback = object : BluetoothGattCallback() {
        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                gatt.discoverServices()
            } else {
                // handle disconnect
            }
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val svc = gatt.getService(DK_SERVICE_UUID)
            if (svc == null) {
                // service not found — fail
                return
            }
            val spsmChar = svc.getCharacteristic(SPSM_CHAR_UUID)
            if (spsmChar == null) {
                // characteristic not found — fail
                return
            }
            // Read SPSM characteristic (async)
            val ok = gatt.readCharacteristic(spsmChar)
            if (!ok) {
                // read failed to start
            }
        }

        @RequiresApi(Build.VERSION_CODES.Q)
        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (characteristic.uuid == SPSM_CHAR_UUID && status == BluetoothGatt.GATT_SUCCESS) {
                val raw = characteristic.value // ByteArray
                if (raw != null && raw.size >= 2) {
                    // CCC spec says SPSM is big-endian uint16
                    val psm = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xffff
                    // Now open L2CAP (background thread)
                    openL2capSocket(device, psm)
                }
            }
        }
    }

    // Connect GATT (make sure you have BLUETOOTH_CONNECT permission on Android 12+)
    device.connectGatt(context, false, gattCallback)
}

@RequiresApi(Build.VERSION_CODES.Q)
fun openL2capSocket(device: BluetoothDevice, psm: Int) {
    thread {
        try {
            // Choose secure or insecure based on your needs:
            // val socket = device.createInsecureL2capChannel(psm) // less auth
            val socket = device.createL2capChannel(psm) // preferred if encrypted/authenticated

            // This is blocking; wrap in try/catch
            socket.connect()

            val input: InputStream = socket.inputStream
            val output: OutputStream = socket.outputStream

            // Example: send hello
            val payload = "hello".toByteArray(Charsets.UTF_8)
            output.write(payload)
            output.flush()

            // read loop (simple):
            val buf = ByteArray(1024)
            var read = input.read(buf)
            while (read > 0) {
                val resp = String(buf, 0, read, Charsets.UTF_8)
                println("Got L2CAP data: $resp")
                read = input.read(buf)
            }

            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
