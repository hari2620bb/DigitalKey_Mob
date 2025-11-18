package com.wnc.createaccount.ui

// secure_store.kt
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import okio.ByteString.Companion.of
import com.squareup.moshi.Moshi
import com.wnc.createaccount.models.DigitalKey
import java.io.File
import java.nio.charset.StandardCharsets

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

fun ensureAesKey(context: Context, alias: String) {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    if (!ks.containsAlias(alias)) {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(true) // optional — will fail on devices without StrongBox; remove if crash risk
            .build()
        keyGen.init(spec)
        keyGen.generateKey()
    }
}

fun getKeystoreSecretKey(alias: String): SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
    ks.load(null)
    return (ks.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
}

fun encryptDigitalKey(context: Context, alias: String, digitalKey: DigitalKey): ByteArray {
    ensureAesKey(context, alias)
    val key = getKeystoreSecretKey(alias)

    val moshi = Moshi.Builder().build()
    val jsonAdapter = moshi.adapter(DigitalKey::class.java)
    val json = jsonAdapter.toJson(digitalKey)
    val plaintext = json.toByteArray(StandardCharsets.UTF_8)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val iv = cipher.iv // 12 bytes typically
    val ciphertext = cipher.doFinal(plaintext)

    // store iv + ciphertext
    val out = ByteArray(iv.size + ciphertext.size)
    System.arraycopy(iv, 0, out, 0, iv.size)
    System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)
    return out
}

fun decryptDigitalKey(context: Context, alias: String, data: ByteArray): DigitalKey? {
    val key = getKeystoreSecretKey(alias)
    val iv = data.sliceArray(0 until 12)
    val ciphertext = data.sliceArray(12 until data.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.DECRYPT_MODE, key, spec)
    val plaintext = cipher.doFinal(ciphertext)
    val json = String(plaintext, StandardCharsets.UTF_8)
    val moshi = Moshi.Builder().build()
    val jsonAdapter = moshi.adapter(DigitalKey::class.java)
    return jsonAdapter.fromJson(json)
}

fun persistEncryptedDigitalKeyToFile(context: Context, peerDeviceId: Int, encryptedBytes: ByteArray) {
    val f = File(context.filesDir, "digital_key_peer_$peerDeviceId.bin")
    f.writeBytes(encryptedBytes)
}
