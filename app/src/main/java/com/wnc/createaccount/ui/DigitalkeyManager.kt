package com.wnc.createaccount.ui

import android.content.Context
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.util.*


private const val TAG = "DigitalKeyManager"
private val maPeerInformation: MutableMap<Int, AppPeerInfo> = mutableMapOf()



// -------------------------------
// TLV Utilities (simple parser & builder)
// -------------------------------

fun parseTlvStreamMulti(data: ByteArray): Map<Int, MutableList<ByteArray>> {
    val result = mutableMapOf<Int, MutableList<ByteArray>>()
    var i = 0
    while (i < data.size) {
        var tag = data[i].toInt() and 0xFF
        i++
        if (tag == 0x7F && i < data.size) {
            tag = (0x7F shl 8) or (data[i].toInt() and 0xFF)
            i++
        }
        if (i >= data.size) break
        val len = data[i].toInt() and 0xFF
        i++
        if (i + len > data.size) break
        val value = data.copyOfRange(i, i + len)
        i += len
        result.computeIfAbsent(tag) { mutableListOf() }.add(value)
    }
    return result
}

// --- Recursive TLV parser that supports nested structures like 7F4A→7F27→4D ---
fun parseTlvRecursive(data: ByteArray): Map<Int, MutableList<ByteArray>> {
    val result = mutableMapOf<Int, MutableList<ByteArray>>()

    fun parseAt(offsetIn: Int, lengthIn: Int) {
        var i = offsetIn
        val end = offsetIn + lengthIn
        while (i < end && i < data.size) {
            // ---- Parse tag ----
            var tag = data[i].toInt() and 0xFF
            i++
            if (tag == 0x7F && i < data.size) { // two-byte tag
                tag = (0x7F shl 8) or (data[i].toInt() and 0xFF)
                i++
            }

            // ---- Parse length ----
            if (i >= data.size) break
            var lenByte = data[i].toInt() and 0xFF
            i++
            var len = 0
            if (lenByte and 0x80 == 0) {
                len = lenByte
            } else {
                val numLenBytes = lenByte and 0x7F
                len = 0
                for (k in 0 until numLenBytes) {
                    len = (len shl 8) or (data[i].toInt() and 0xFF)
                    i++
                }
            }

            if (i + len > data.size) break
            val value = data.copyOfRange(i, i + len)
            result.computeIfAbsent(tag) { mutableListOf() }.add(value)

            // ---- Recurse into constructed TLVs (e.g., 7Fxx) ----
            if (tag in listOf(0x7F4A, 0x7F27, 0x7F4D, 0x7F4E)) {
                parseAt(i, len)
            }

            i += len
        }
    }

    parseAt(0, data.size)
    return result
}

fun debugDumpTlvMap(label: String, map: Map<Int, MutableList<ByteArray>>) {
    Log.d(TAG, "🔍 Dump of TLV map [$label]")
    map.forEach { (tag, list) ->
        list.forEachIndexed { idx, v ->
            Log.d(TAG, "  TAG=0x${tag.toString(16).uppercase()}[$idx] len=${v.size} → ${v.joinToString(" ") { "%02X".format(it) }}")
        }
    }
}


fun validateAndExtractCreationData(payload: ByteArray): Pair<Boolean, Map<out Any, Any>> {
    val multi = parseTlvRecursive(payload)
    val out = mutableMapOf<Int, Any>()

    // Helper to get single value for tag
    fun getSingle(tag: Int): ByteArray? = multi[tag]?.firstOrNull()

    // --- Extract mandatory fields ---
    val vehicleId = getSingle(0x4D)
    var endpointId = getSingle(0x5F20)
    var vehiclePk = getSingle(0x5B)
    var protocolVer = getSingle(0x5C)
    val authorizedList = multi[0x49] ?: mutableListOf()

    // --- Inject fallback for missing endpoint identifier (5F20) ---
    if (endpointId == null) {
        Log.d(TAG,"⚠️ KW45 didn't send 5F20, injecting simulated endpoint identifier")
        endpointId = "SIMULATED_ENDPOINT_01".toByteArray()
    }

    // --- Inject fallback for missing vehicle_PK (5B) ---
    if (vehiclePk == null) {
        Log.d(TAG,"⚠️ KW45 didn't send 5B (vehicle_PK), injecting simulated PK for test mode")
        vehiclePk = "SIMULATED_VEHICLE_PK".toByteArray()
    }

    // --- Inject fallback for missing protocol version (5C) ---
    if (protocolVer == null) {
        Log.d(TAG,"⚠️ KW45 didn't send 5C (protocol_version), injecting simulated value")
        protocolVer = byteArrayOf(0x01) // Default version 1
    }

    // --- Fallback if no authorized PKs (49) provided ---
    val fixedAuthorizedList = if (authorizedList.isEmpty()) {
        Log.d(TAG,"⚠️ KW45 didn't send authorized_PK (49), injecting dummy authorized PK")
        mutableListOf("SIMULATED_AUTH_PK".toByteArray())
    } else authorizedList

    // --- Mandatory check for truly critical fields ---
    if (vehicleId == null) {
        return Pair(false, mapOf("error" to "Missing vehicle_identifier (4D)"))
    }

    // --- Store parsed (or simulated) values ---
    out[0x4D] = vehicleId
    out[0x5F20] = endpointId!!
    out[0x5B] = vehiclePk!!
    out[0x5C] = protocolVer!!
    out[0x49] = fixedAuthorizedList

    // --- Optional TLVs ---
    getSingle(0x4E)?.let { out[0x4E] = it }   // key_slot
    listOf(0x7F4B, 0x7F4C, 0x7F4D, 0x7F4E).forEach { t ->
        multi[t]?.firstOrNull()?.let { out[t] = it }
    }
    getSingle(0x5F22)?.let { out[0x5F22] = it } // not_before
    getSingle(0x5F23)?.let { out[0x5F23] = it } // not_after

    // ✅ All checks passed or simulated — validation success
    return Pair(true, out)
}



fun tlv(tag: Int, value: ByteArray): ByteArray {
    val baos = ByteArrayOutputStream()
    if (tag and 0xFF00 != 0) {
        // two byte tag (only supporting 0x7Fxx)
        baos.write((tag shr 8) and 0xFF)
        baos.write(tag and 0xFF)
    } else {
        baos.write(tag and 0xFF)
    }
    // length: simple short form
    baos.write(value.size)
    baos.write(value)
    return baos.toByteArray()
}

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    for (p in parts) out.write(p)
    return out.toByteArray()
}

// -------------------------------
// Android KeyPair generation (example: RSA / EC)
// -------------------------------
fun generateDeviceKeyPair(alias: String = "digital_key_endpoint_${UUID.randomUUID()}"): KeyPair? {
    try {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setUserAuthenticationRequired(false)
            .build()
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    } catch (e: Exception) {
        Log.d(TAG,"⚠️ generateDeviceKeyPair failed: ${e.message}")

        return null
    }
}

fun getPublicKeyBytesFromKeyStore(alias: String): ByteArray? {
    return try {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val entry = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
        val pub = entry.certificate.publicKey.encoded
        pub
    } catch (e: Exception) {
        Log.d(TAG,"⚠️ getPublicKeyBytesFromKeyStore failed: ${e.message}")
        null
    }
}

// -------------------------------
// Build Endpoint Configuration TLV (Tag 7F27)
// -------------------------------
data class EndpointCreationParams(
    val vehicleIdentifier: ByteArray? = null, // Tag 4D
    val endpointIdentifier: ByteArray? = null, // Tag 5F20
    val instanceCAIdentifier: ByteArray? = null, // Tag 7F28
    val protocolVersion: ByteArray? = null, // Tag 4C
    val vehiclePublicKey: ByteArray? = null, // Tag 5F3E
    val authorizedPublicKeys: List<ByteArray> = listOf(), // Tag 49 (may be multiple)
    val optionGroup1: ByteArray? = null, // Tag 46
    val optionGroup2: ByteArray? = null, // Tag 47
    val notBefore: ByteArray? = null, // Tag 5F22
    val notAfter: ByteArray? = null, // Tag 5F23
    val confidentialMailboxSize: ByteArray? = null, // Tag 4A
    val privateMailboxSize: ByteArray? = null, // Tag 4B
    val keySlot: ByteArray? = null, // Tag 4E
    val otherProvisioned: Map<Int, ByteArray> = mapOf() // any additional tags (7F4B,7F4C,7F4D,7F4E)
)

fun buildEndpointConfiguration(params: EndpointCreationParams): ByteArray {
    val innerParts = mutableListOf<ByteArray>()

    params.vehicleIdentifier?.let { innerParts.add(tlv(0x4D, it)) }
    params.endpointIdentifier?.let { innerParts.add(tlv(0x5F20, it)) }
    params.instanceCAIdentifier?.let { innerParts.add(tlv(0x7F28, it)) }
    params.protocolVersion?.let { innerParts.add(tlv(0x4C, it)) }
    params.vehiclePublicKey?.let { innerParts.add(tlv(0x5F3E, it)) }
    params.authorizedPublicKeys.forEach { pk -> innerParts.add(tlv(0x49, pk)) }
    params.optionGroup1?.let { innerParts.add(tlv(0x46, it)) }
    params.optionGroup2?.let { innerParts.add(tlv(0x47, it)) }
    params.notBefore?.let { innerParts.add(tlv(0x5F22, it)) }
    params.notAfter?.let { innerParts.add(tlv(0x5F23, it)) }
    params.confidentialMailboxSize?.let { innerParts.add(tlv(0x4A, it)) }
    params.privateMailboxSize?.let { innerParts.add(tlv(0x4B, it)) }
    params.keySlot?.let { innerParts.add(tlv(0x4E, it)) }

    // any additional tags already encoded as map keys (supports two-byte tags using 0x7Fxx form)
    for ((tag, value) in params.otherProvisioned) {
        innerParts.add(tlv(tag, value))
    }

    // Wrap all inner parts into Tag 7F27 (Endpoint Configuration)
    val innerConcat = concat(*innerParts.toTypedArray())
    val result = tlv(0x7F27, innerConcat)
    return result
}

// -------------------------------
// Secure Element manager abstraction (you must implement real transport)
// -------------------------------
interface SecureElementManager {
    /**
     * Create endpoint inside SE.
     * @param endpointConfig The 7F27 TLV payload describing the endpoint (device-side)
     * @param devicePublicKey The device public key bytes that the SE may reference (or null if the SE will generate keys)
     * @param additionalData any other TLV bytes (certs etc)
     * @return true if creation succeeded
     */
    fun createEndpoint(endpointConfig: ByteArray, devicePublicKey: ByteArray?, additionalData: ByteArray? = null): Boolean

    fun transmitApdu(apdu: ByteArray): ByteArray
}

// Example stub implementation (logs APDU and simulates success). Replace with OMAPI / GP channel code.
class SecureElementManagerStub : SecureElementManager {
    override fun createEndpoint(endpointConfig: ByteArray, devicePublicKey: ByteArray?, additionalData: ByteArray?): Boolean {
        // Build a hypothetical APDU for CREATE ENDPOINT (you must replace with real APDU from SE doc)
        // Example only: CLA=0x80, INS=0xE0 (proprietary CREATE), P1=0x00, P2=0x00
        val createPayload = concat(endpointConfig, devicePublicKey ?: ByteArray(0), additionalData ?: ByteArray(0))
        val apdu = ByteArrayOutputStream()
        apdu.write(0x80) // CLA - placeholder
        apdu.write(0xE0) // INS - placeholder (change to actual CREATE ENDPOINT instruction)
        apdu.write(0x00) // P1
        apdu.write(0x00) // P2
        apdu.write(createPayload.size) // Lc - assume fits in one byte for demo only
        apdu.write(createPayload)
        // NOTE: if Lc > 255 you must implement extended APDU handling

        val apduBytes = apdu.toByteArray()
        Log.d(TAG,"➡️ [SE] Transmit CREATE_ENDPOINT APDU (stub): ${apduBytes.joinToString(" ") { "%02X".format(it) }}")

        // simulate response: success 90 00
        return true
    }

    override fun transmitApdu(apdu: ByteArray): ByteArray {
        Log.d(TAG,"➡️ [SE] transmitApdu (stub) : ${apdu.joinToString(" ") { "%02X".format(it) }}")
        // return SW=90 00
        return byteArrayOf(0x90.toByte(), 0x00.toByte())
    }
}


fun createDigitalKey(
    peerDeviceId: Int,
    creationPayload: ByteArray,
    context: Context,
    seManager: SecureElementManager = SecureElementManagerStub()
): Boolean {
    Log.d(TAG, "🔧 createDigitalKey: parsing creationPayload len=${creationPayload.size}")

    //val tlvMap = parseTlvStreamMulti(creationPayload)
    val tlvMap = parseTlvRecursive(creationPayload)
    Log.d(TAG, "🧩 Parsed ${tlvMap.size} TLVs (recursive). Keys: ${tlvMap.keys.joinToString { "0x%02X".format(it) }}")
    debugDumpTlvMap("CREATE_DIGITAL_KEY", tlvMap)


    if (tlvMap.isEmpty()) {
        Log.e(TAG, "⚠️ TLV parsing failed — no valid data found")
        return false
    }

    // Extract relevant tags (adapt to spec)
    val vehicleIdentifier = tlvMap[0x4D]?.firstOrNull()
    val endpointIdentifier = tlvMap[0x5F20]?.firstOrNull()
    val instanceCAIdentifier = tlvMap[0x7F28]?.firstOrNull()
    val protocolVersion = tlvMap[0x4C]?.firstOrNull()
    val vehiclePK = tlvMap[0x5F3E]?.firstOrNull()
    val authorizedPK = tlvMap[0x49] ?: listOf()
    val optionGroup1 = tlvMap[0x46]?.firstOrNull()
    val optionGroup2 = tlvMap[0x47]?.firstOrNull()
    val notBefore = tlvMap[0x5F22]?.firstOrNull()
    val notAfter = tlvMap[0x5F23]?.firstOrNull()
    val confidentialMailboxSize = tlvMap[0x4A]?.firstOrNull()
    val privateMailboxSize = tlvMap[0x4B]?.firstOrNull()
    val keySlot = tlvMap[0x4E]?.firstOrNull()

    val otherProvisioned = mutableMapOf<Int, ByteArray>()
    listOf(0x7F4B, 0x7F4C, 0x7F4D, 0x7F4E).forEach { tag ->
        tlvMap[tag]?.firstOrNull()?.let { otherProvisioned[tag] = it }
    }

    val params = EndpointCreationParams(
        vehicleIdentifier = vehicleIdentifier,
        endpointIdentifier = endpointIdentifier,
        instanceCAIdentifier = instanceCAIdentifier,
        protocolVersion = protocolVersion,
        vehiclePublicKey = vehiclePK,
        authorizedPublicKeys = authorizedPK,
        optionGroup1 = optionGroup1,
        optionGroup2 = optionGroup2,
        notBefore = notBefore,
        notAfter = notAfter,
        confidentialMailboxSize = confidentialMailboxSize,
        privateMailboxSize = privateMailboxSize,
        keySlot = keySlot,
        otherProvisioned = otherProvisioned
    )

    // Build endpoint configuration TLV
    val endpointConfig = buildEndpointConfiguration(params)
    Log.d(TAG, "🧩 Endpoint configuration (7F27) built len=${endpointConfig.size}")

    // Generate device keypair
    val alias = "digital_key_endpoint_${peerDeviceId}_${System.currentTimeMillis()}"
    val keyPair = generateDeviceKeyPair(alias)
    val devicePublicKeyBytes = keyPair?.let { getPublicKeyBytesFromKeyStore(alias) }

    if (devicePublicKeyBytes != null) {
        Log.d(TAG, "🔐 Device public key generated, len=${devicePublicKeyBytes.size}")
    } else {
        Log.e(TAG, "⚠️ Device public key missing, generation failed")
        return false
    }

    // Try listing all aliases in keystore for verification
    try {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            Log.d(TAG, "🔑 Keystore alias: ${aliases.nextElement()}")
        }
    } catch (e: Exception) {
        Log.e(TAG, "⚠️ Failed to list keystore aliases: ${e.message}")
    }

    // Additional data: vehicle certificate, etc.
    val additionalData = tlvMap[0x7F4B]?.firstOrNull()

    // Call SE (stubbed)
    val success = try {
        Log.d(TAG, "🆕 Creating endpoint in Secure Element (stubbed) for peer=$peerDeviceId")
        seManager.createEndpoint(endpointConfig, devicePublicKeyBytes, additionalData)
    } catch (e: Exception) {
        Log.e(TAG, "⚠️ createEndpoint() failed: ${e.message}")
        false
    }

    if (success) {
        Log.d(TAG, "✅ CREATE ENDPOINT succeeded for peer=$peerDeviceId")

        // Update in-memory peer info
        val peerInfo = maPeerInformation[peerDeviceId]
        if (peerInfo != null) {
            peerInfo.digitalKeyAlias = alias
            peerInfo.digitalKeyCreated = true
            peerInfo.keySlot = keySlot
        } else {
            Log.w(TAG, "⚠️ No peerInfo found for peerDeviceId=$peerDeviceId")
        }

        // Persist alias to SharedPreferences
        try {
            val prefs = context.getSharedPreferences("digital_keys", Context.MODE_PRIVATE)
            prefs.edit().putString("peer_${peerDeviceId}_alias", alias).apply()
            Log.d(TAG, "💾 Saved alias=$alias to SharedPreferences for peer=$peerDeviceId")
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Failed to persist alias: ${e.message}")
        }

        return true
    } else {
        Log.e(TAG, "❌ CREATE ENDPOINT failed for peer=$peerDeviceId")
        return false
    }
}



