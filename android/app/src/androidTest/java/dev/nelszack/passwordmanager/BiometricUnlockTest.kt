package dev.nelszack.passwordmanager

import android.view.KeyEvent
import androidx.biometric.BiometricManager
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.IllegalBlockSizeException
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Run this class in its own instrumentation process; storage is isolated in cache. */
@RunWith(AndroidJUnit4::class)
class BiometricUnlockTest {
    @Before
    fun settlePreviousCallbacks() {
        vault.drain()
    }

    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("biometric-regression")
    }

    @Test
    fun callbackErrorsAreHandledAndStaleCallbacksAreDiscarded() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val scenario = vault.launch(MainActivity::class.java)
        try {
            val cleaned = AtomicBoolean(false)
            scenario.onActivity { activity ->
                val callback =
                    activity.sessionCallback<Unit>({ cleaned.set(true) }) {
                        throw IllegalBlockSizeException("Synthetic keystore failure")
                    }
                callback(Unit)
                assertTrue(cleaned.get())
            }
            instrumentation.waitForIdleSync()
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            val ran = AtomicBoolean(false)
            val pendingMaterial = ByteArray(70) { 7 }
            lateinit var late: (Unit) -> Unit
            scenario.onActivity { activity ->
                late =
                    activity.sessionCallback({ pendingMaterial.fill(0) }) { _: Unit ->
                        ran.set(true)
                    }
            }
            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.moveToState(Lifecycle.State.RESUMED)
            instrumentation.runOnMainSync { late(Unit) }
            assertFalse(ran.get())
            assertTrue(pendingMaterial.all { it == 0.toByte() })
        } finally {
            scenario.close()
        }
    }

    @Test
    fun asynchronousUiErrorsDoNotCrashTheActivity() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val scenario = vault.launch(MainActivity::class.java)
        try {
            val completed = CountDownLatch(1)
            scenario.onActivity { activity ->
                activity.task({ Unit }) {
                    completed.countDown()
                    throw IllegalStateException("Synthetic completion failure")
                }
            }
            assertTrue(completed.await(10, TimeUnit.SECONDS))
            instrumentation.waitForIdleSync()
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        } finally {
            scenario.close()
        }
    }

    @Test
    fun rejectedEnrollmentWipesMaterial() {
        Vault.request("lock")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val scenario = vault.launch(MainActivity::class.java)
        val material = ByteArray(70) { 9 }
        val vault = "not-a-real-vault-${UUID.randomUUID()}"
        try {
            scenario.onActivity { activity ->
                assertThrows(IllegalStateException::class.java) {
                    DeviceKeys.enable(activity, vault, material) {}
                }
            }
            assertTrue(material.all { it == 0.toByte() })
            assertFalse(DeviceKeys.enabled(context, vault))
        } finally {
            scenario.close()
        }
    }

    @Test
    fun interactiveBiometricKeyRoundTrip() {
        assumeTrue(
            "Opt in with -e interactiveBiometrics true and authenticate two prompts",
            InstrumentationRegistry.getArguments().getString("interactiveBiometrics") == "true",
        )
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(
            BiometricManager.from(context)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        )
        val scenario = vault.launch(MainActivity::class.java)
        Vault.worker.submit {}.get(10, TimeUnit.SECONDS)
        val vault =
            Vault.json("create", "password" to "Synthetic-Biometric-Vault-9274!").getString("vault")
        val material = DeviceKeys.decode(Vault.json("biometric_material").getString("material"))
        val expected = material.copyOf()
        var recovered: ByteArray? = null
        try {
            val enabled = CountDownLatch(1)
            scenario.onActivity { activity ->
                DeviceKeys.enable(activity, vault, material) { enabled.countDown() }
            }
            assertTrue("Authenticate the enable prompt", enabled.await(120, TimeUnit.SECONDS))
            assertTrue(material.all { it == 0.toByte() })
            assertTrue(DeviceKeys.enabled(context, vault))
            Vault.request("lock")
            val unlocked = CountDownLatch(1)
            scenario.onActivity { activity ->
                DeviceKeys.unlock(activity, vault) { bytes ->
                    recovered = bytes.copyOf()
                    bytes.fill(0)
                    unlocked.countDown()
                }
            }
            assertTrue("Authenticate the unlock prompt", unlocked.await(120, TimeUnit.SECONDS))
            assertTrue(
                "Biometric key round trip failed",
                expected.contentEquals(requireNotNull(recovered)),
            )
            Vault.request(
                "biometric_unlock",
                "vault" to vault,
                "material" to DeviceKeys.encode(requireNotNull(recovered)),
            )
            assertTrue(Vault.json("status").getBoolean("unlocked"))
        } finally {
            material.fill(0)
            expected.fill(0)
            recovered?.fill(0)
            DeviceKeys.disable(context, vault)
            Vault.request("lock")
            scenario.close()
        }
    }
}
