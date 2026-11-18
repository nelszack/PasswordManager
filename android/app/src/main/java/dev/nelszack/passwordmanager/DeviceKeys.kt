package dev.nelszack.passwordmanager

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object DeviceKeys {
    private fun prefs(context: Context) =
        context.getSharedPreferences("device-keys", Context.MODE_PRIVATE)

    private fun alias(vault: String) =
        "pm.biometric." +
            MessageDigest.getInstance("SHA-256").digest(vault.toByteArray()).joinToString("") {
                "%02x".format(it)
            }

    fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    fun decode(text: String): ByteArray =
        Base64.decode(text, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(alias: String, biometric: Boolean): SecretKey {
        (store().getKey(alias, null) as? SecretKey)?.let {
            return it
        }
        val spec =
            KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
        if (biometric) {
            spec.setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
            if (android.os.Build.VERSION.SDK_INT >= 30)
                spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            else spec.setUserAuthenticationValidityDurationSeconds(-1)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(spec.build())
            generateKey()
        }
    }

    fun enabled(context: Context, vault: String) = prefs(context).contains(alias(vault))

    fun disable(context: Context, vault: String) {
        prefs(context).edit().remove(alias(vault)).commit()
        store().deleteEntry(alias(vault))
    }

    fun enable(activity: SecureActivity, vault: String, material: ByteArray, done: () -> Unit) {
        try {
            check(Vault.primaryUnlock) { "Unlock with your original password or key file first" }
            disable(activity, vault)
            val cipher =
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.ENCRYPT_MODE, key(alias(vault), true))
                }
            prompt(activity, "Enable biometric unlock", cipher, onCancel = { material.fill(0) }) {
                approved ->
                try {
                    // Auth-per-use keys cannot process AAD until CryptoObject
                    // authentication succeeds. Doing so earlier poisons the operation.
                    approved.updateAAD(vault.toByteArray())
                    val encrypted = approved.doFinal(material)
                    check(
                        prefs(activity)
                            .edit()
                            .putString(alias(vault), encode(approved.iv) + "." + encode(encrypted))
                            .commit()
                    )
                    done()
                } finally {
                    material.fill(0)
                }
            }
        } catch (error: Exception) {
            material.fill(0)
            throw error
        }
    }

    fun unlock(activity: SecureActivity, vault: String, done: (ByteArray) -> Unit) {
        try {
            val parts =
                prefs(activity).getString(alias(vault), null)?.split('.')
                    ?: error("Biometric unlock is not enabled")
            val secret =
                store().getKey(alias(vault), null) as? SecretKey
                    ?: error("Biometric key unavailable")
            val cipher =
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, decode(parts[0])))
                }
            prompt(activity, "Unlock vault", cipher) { approved ->
                val material =
                    try {
                        approved.updateAAD(vault.toByteArray())
                        approved.doFinal(decode(parts[1]))
                    } catch (error: Exception) {
                        disable(activity, vault)
                        throw IllegalStateException(
                            "Biometric key unavailable. Use your original password or key file.",
                            error,
                        )
                    }
                try {
                    done(material)
                } catch (error: Exception) {
                    material.fill(0)
                    throw error
                }
            }
        } catch (error: Exception) {
            disable(activity, vault)
            throw IllegalStateException(
                "Biometric key unavailable. Use your original password or key file.",
                error,
            )
        }
    }

    private fun prompt(
        activity: SecureActivity,
        title: String,
        cipher: Cipher,
        onCancel: () -> Unit = {},
        done: (Cipher) -> Unit,
    ) {
        check(
            BiometricManager.from(activity)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        ) {
            "Strong biometrics are unavailable"
        }
        var finished = false
        lateinit var observer: DefaultLifecycleObserver
        val complete =
            activity.sessionCallback<BiometricPrompt.AuthenticationResult>(onCancel) { result ->
                done(requireNotNull(result.cryptoObject?.cipher))
            }
        val failure =
            activity.sessionCallback<CharSequence> { message -> error(message.toString()) }
        fun finish(): Boolean {
            if (finished) return false
            finished = true
            activity.lifecycle.removeObserver(observer)
            return true
        }
        val prompt =
            BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        if (finish()) complete(result)
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (!finish()) return
                        onCancel()
                        if (
                            code !in
                                setOf(
                                    BiometricPrompt.ERROR_CANCELED,
                                    BiometricPrompt.ERROR_USER_CANCELED,
                                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                                )
                        )
                            failure(message)
                    }
                },
            )
        observer =
            object : DefaultLifecycleObserver {
                override fun onStop(owner: LifecycleOwner) {
                    if (finish()) {
                        onCancel()
                        prompt.cancelAuthentication()
                    }
                }
            }
        activity.lifecycle.addObserver(observer)
        try {
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Use password or key file")
                    .build(),
                BiometricPrompt.CryptoObject(cipher),
            )
        } catch (error: Exception) {
            finish()
            onCancel()
            throw error
        }
    }

    fun saveToken(context: Context, token: String) {
        val cipher =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, key("pm.sync-token", false))
            }
        val encrypted = cipher.doFinal(token.toByteArray())
        check(
            prefs(context)
                .edit()
                .putString("sync-token", encode(cipher.iv) + "." + encode(encrypted))
                .commit()
        )
    }

    fun token(context: Context): String {
        val parts =
            prefs(context).getString("sync-token", null)?.split('.')
                ?: error("Save a sync credential first")
        val secret =
            store().getKey("pm.sync-token", null) as? SecretKey
                ?: error("Save the sync credential again")
        val cipher =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, decode(parts[0])))
            }
        val bytes = cipher.doFinal(decode(parts[1]))
        return try {
            bytes.toString(Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }
}
