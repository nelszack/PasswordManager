package dev.nelszack.passwordmanager

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Run alone; all native vault operations are bound to synthetic cache storage. */
@RunWith(AndroidJUnit4::class)
class AutofillSessionLifecycleTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("autofill-session")
    }

    /**
     * Stop the activity. ActivityScenario does so by starting an empty activity on
     * top and gives up after 45 seconds; a busy CI emulator can take longer, so keep
     * waiting for the stop it already requested before failing.
     */
    private fun stop(scenario: ActivityScenario<*>) {
        try {
            scenario.moveToState(Lifecycle.State.CREATED)
        } catch (timeout: AssertionError) {
            val end = android.os.SystemClock.elapsedRealtime() + 30_000
            while (scenario.state != Lifecycle.State.CREATED) {
                if (android.os.SystemClock.elapsedRealtime() > end) throw timeout
                Thread.sleep(200)
            }
        }
    }

    @Test
    fun completedHandoffRetainsUnlockButCancellationManagementAndLockRevokeIt() {
        vault.requireUnlocked()
        val password = "Synthetic-Session-Vault-9274!"
        val created = Vault.json("create", "password" to password)
        val scope = AutofillScope("com.android.chrome", "https://accounts.example.com", true)
        fun reopen() {
            Vault.request("unlock", "vault" to created.getString("vault"), "password" to password)
            Vault.autofillSession.grant(scope)
        }
        val completed = vault.launch(AutofillSessionFixtureActivity::class.java)
        vault.drain()
        completed.onActivity { activity ->
            Vault.autofillSession.grant(scope)
            activity.completedHandoff = true
            activity.finish()
        }
        completed.close()
        vault.drain()
        assertTrue(Vault.json("status").getBoolean("unlocked"))
        assertTrue(Vault.autofillSession.allows(scope))

        val cancelled = vault.launch(AutofillSessionFixtureActivity::class.java)
        stop(cancelled)
        vault.drain()
        assertFalse(Vault.json("status").getBoolean("unlocked"))
        assertFalse(Vault.autofillSession.allows(scope))
        cancelled.close()
        vault.drain()

        reopen()
        val management = vault.launch(MainActivity::class.java)
        vault.drain()
        assertFalse(Vault.json("status").getBoolean("unlocked"))
        assertFalse(Vault.autofillSession.allows(scope))
        management.close()
        vault.drain()

        reopen()
        Vault.lock()
        vault.drain()
        assertFalse(Vault.autofillSession.allows(scope))
        assertFalse(Vault.json("status").getBoolean("unlocked"))
    }
}
