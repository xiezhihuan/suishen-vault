package dev.suishen.vault

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.plugin.Invoke
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object Biometrics {
    private const val STORE = "AndroidKeyStore"
    private const val ALIAS = "suishen-device-v1"
    private const val PREF = "device-wrapper"
    private var pending: CancellationSignal? = null
    fun cancel() = pending?.cancel()
    private fun store() = KeyStore.getInstance(STORE).apply { load(null) }

    fun remove(activity: Activity) {
        for (slot in 0..1) store().deleteEntry("$ALIAS-$slot")
        check(activity.getSharedPreferences(PREF, 0).edit().clear().commit())
    }
    fun authenticate(activity: Activity, enroll: Boolean, invoke: Invoke) {
        if (pending != null || activity.isFinishing) { invoke.reject("验证未完成"); return }
        val prefs = activity.getSharedPreferences(PREF, 0)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val current = prefs.getInt("slot", 0)
        val slot = if (enroll) 1 - current else current
        val alias = "$ALIAS-$slot"
        val sealed: ByteArray?
        if (enroll) {
            val spec = KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= 30)
                spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(-1)
            }
            val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).apply {
                init(spec.build())
            }.generateKey()
            cipher.init(Cipher.ENCRYPT_MODE, key)
            sealed = null
        } else {
            val key = store().getKey(alias, null) as? SecretKey ?: error("需要重新登记")
            val blob = Base64.decode(prefs.getString("blob", "") ?: "", Base64.NO_WRAP)
            require(blob.size == 12 + 32 + 16)
            sealed = blob.copyOfRange(12, blob.size)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        }
        val signal = CancellationSignal()
        val builder = BiometricPrompt.Builder(activity)
            .setTitle(if (enroll) "启用密库生物识别" else "验证本次密库操作")
            .setNegativeButton("取消", activity.mainExecutor) { _, _ ->
                if (pending === signal) {
                    pending = null
                    signal.cancel()
                    invoke.reject("验证已取消")
                }
            }
        if (Build.VERSION.SDK_INT >= 30) builder.setAllowedAuthenticators(BIOMETRIC_STRONG)
        val prompt = builder.build()
        pending = signal
        try {
            prompt.authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (pending !== signal) return
                        pending = null
                        invoke.reject("验证未完成")
                    }
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (pending !== signal) return
                        pending = null
                        try {
                            check(!signal.isCanceled)
                            val authorized = requireNotNull(result.cryptoObject?.cipher)
                            val raw = if (sealed == null) ByteArray(32).also { SecureRandom().nextBytes(it) }
                                else authorized.doFinal(sealed)
                            try {
                                require(raw.size == 32)
                                if (sealed == null) {
                                    val encrypted = authorized.doFinal(raw)
                                    require(authorized.iv.size == 12)
                                    check(prefs.edit().putInt("slot", slot).putString("blob", Base64.encodeToString(
                                        authorized.iv + encrypted, Base64.NO_WRAP)).commit())
                                }
                                // 仅返回到 Rust 的本地插件调用；WebView 没有插件权限。
                                invoke.resolveObject(raw.map { it.toInt() and 255 })
                            } finally { raw.fill(0) }
                        } catch (_: Exception) { invoke.reject("验证未完成") }
                    }
                })
        } catch (e: Exception) { pending = null; throw e }
    }
}
