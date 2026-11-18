package dev.nelszack.passwordmanager

import android.content.ComponentName
import android.content.pm.ApplicationInfo
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MobileIntegrationTest {
    @Test
    fun installedAppProtectsScreensAndSystemServiceEntryPoints() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertEquals(0, context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
        val manager = context.packageManager
        assertEquals(
            "android.permission.BIND_AUTOFILL_SERVICE",
            manager
                .getServiceInfo(ComponentName(context, VaultAutofillService::class.java), 0)
                .permission,
        )
        if (android.os.Build.VERSION.SDK_INT >= 34)
            assertEquals(
                "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE",
                manager
                    .getServiceInfo(ComponentName(context, VaultCredentialService::class.java), 0)
                    .permission,
            )
        assertTrue(
            CallerIdentity.appOrigin(context, context.packageName)
                .startsWith("androidapp://${context.packageName}/")
        )
        assertFalse(CallerIdentity.trustedBrowser(context, context.packageName))
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        var stopped: MainActivity? = null
        scenario.onActivity { activity ->
            assertTrue(
                activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            )
            stopped = activity
        }
        scenario.close()
        instrumentation.waitForIdleSync()
        drainWorker()
        // Simulate a delayed authentication callback arriving after onStop.
        val ran = java.util.concurrent.atomic.AtomicBoolean(false)
        val task =
            SecureActivity::class
                .java
                .declaredMethods
                .single { it.name == "task" }
                .apply { isAccessible = true }
        instrumentation.runOnMainSync {
            task.invoke(requireNotNull(stopped), { ran.set(true) }, { _: Any? -> })
        }
        drainWorker()
        assertFalse("Stopped activities must not run late authentication work", ran.get())
    }

    @Test
    fun jniVaultAndPasskeySurviveLockAndVerifyWithAndroidCrypto() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        drainWorker()
        Vault.context = context
        Vault.request("lock")
        val created = Vault.json("create", "password" to "Cedar-Lantern-Quartz-9274!")
        try {
            Vault.request(
                "save",
                "name" to "Synthetic login",
                "username" to "alice",
                "password" to "synthetic-secret",
                "url" to "https://example.com",
            )
            val options =
                JSONObject(
                    """{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"alice","displayName":"Alice"},"challenge":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""
                )
            val registered =
                Vault.json(
                    "passkey_create",
                    "request" to options,
                    "origin" to "https://example.com",
                )
            val att =
                DeviceKeys.decode(
                    registered.getJSONObject("response").getString("attestationObject")
                )
            // Decode the fixed 'none' attestation's authData byte string, then
            // reconstruct the public key strictly from the emitted COSE key.
            val marker = "authData".toByteArray()
            val start =
                (0..att.size - marker.size).first { index ->
                    marker.indices.all { att[index + it] == marker[it] }
                } + marker.size
            assertEquals(0x58, att[start].toInt() and 255)
            val auth = att.copyOfRange(start + 2, start + 2 + (att[start + 1].toInt() and 255))
            val credentialLength = ((auth[53].toInt() and 255) shl 8) or (auth[54].toInt() and 255)
            val cose = auth.copyOfRange(55 + credentialLength, auth.size)
            assertEquals(77, cose.size)
            val x = BigInteger(1, cose.copyOfRange(10, 42))
            val y = BigInteger(1, cose.copyOfRange(45, 77))
            val parameters =
                AlgorithmParameters.getInstance("EC")
                    .apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
            val publicKey =
                KeyFactory.getInstance("EC")
                    .generatePublic(ECPublicKeySpec(ECPoint(x, y), parameters))
            Vault.request("lock")
            assertThrows(IllegalStateException::class.java) { Vault.request("list") }
            Vault.request(
                "unlock",
                "vault" to created.getString("vault"),
                "password" to "Cedar-Lantern-Quartz-9274!",
            )
            val keys = Vault.request("passkeys") as JSONArray
            assertEquals(1, keys.length())
            val id = keys.getJSONObject(0).getLong("id")
            assertFalse(
                Vault.json("item", "id" to id)
                    .getJSONArray("fields")
                    .toString()
                    .contains("private_key")
            )
            val request =
                JSONObject()
                    .put("rpId", "example.com")
                    .put("challenge", DeviceKeys.encode(ByteArray(32) { 7 }))
            val response =
                Vault.json(
                        "passkey_get",
                        "id" to id,
                        "request" to request,
                        "origin" to "https://example.com",
                    )
                    .getJSONObject("response")
            val clientHash =
                MessageDigest.getInstance("SHA-256")
                    .digest(DeviceKeys.decode(response.getString("clientDataJSON")))
            val verifier =
                Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(publicKey)
                    update(DeviceKeys.decode(response.getString("authenticatorData")))
                    update(clientHash)
                }
            assertTrue(verifier.verify(DeviceKeys.decode(response.getString("signature"))))
            val browserHash = ByteArray(32) { 11 }
            val delegated =
                Vault.json(
                        "passkey_get",
                        "id" to id,
                        "request" to request,
                        "origin" to "https://example.com",
                        "client_hash" to DeviceKeys.encode(browserHash),
                    )
                    .getJSONObject("response")
            assertEquals(
                DeviceKeys.encode("{}".toByteArray()),
                delegated.getString("clientDataJSON"),
            )
            val browserVerifier =
                Signature.getInstance("SHA256withECDSA").apply {
                    initVerify(publicKey)
                    update(DeviceKeys.decode(delegated.getString("authenticatorData")))
                    update(browserHash)
                }
            assertTrue(browserVerifier.verify(DeviceKeys.decode(delegated.getString("signature"))))
            assertThrows(IllegalStateException::class.java) {
                Vault.request(
                    "passkey_get",
                    "id" to id,
                    "request" to request,
                    "origin" to "https://evil.com",
                )
            }
            val wrapped = Vault.json("biometric_material")
            Vault.request("lock")
            Vault.request(
                "biometric_unlock",
                "vault" to created.getString("vault"),
                "material" to wrapped.getString("material"),
            )
            assertThrows(IllegalStateException::class.java) { Vault.request("biometric_material") }
        } finally {
            Vault.request("lock")
            context.filesDir.resolve("vaults").resolve(created.getString("vault")).delete()
        }
    }

    private fun drainWorker() {
        val drained = java.util.concurrent.CountDownLatch(1)
        Vault.worker.execute { drained.countDown() }
        check(drained.await(10, java.util.concurrent.TimeUnit.SECONDS)) {
            "Vault worker did not settle"
        }
    }
}
