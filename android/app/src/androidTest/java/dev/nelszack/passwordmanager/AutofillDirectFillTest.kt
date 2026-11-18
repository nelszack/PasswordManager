package dev.nelszack.passwordmanager

import android.content.ComponentName
import android.content.Intent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Run alone: a separate test-APK form and cache-only vault exercise real Dataset authentication.
 */
@RunWith(AndroidJUnit4::class)
class AutofillDirectFillTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("direct-fill")
    }

    @Test
    fun tappingAccountSuggestionFillsWithoutOpeningPicker() {
        val instrumentation = vault.instrumentation
        val context = vault.context
        val automation = instrumentation.uiAutomation
        val originalServiceInfo = automation.serviceInfo
        val client = instrumentation.context.packageName
        fun waitFor(predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
            val end = android.os.SystemClock.elapsedRealtime() + 15000
            fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
                if (predicate(node)) return node
                for (i in 0 until node.childCount) node.getChild(i)?.let {
                    find(it)?.let { found ->
                        return found
                    }
                }
                return null
            }
            while (android.os.SystemClock.elapsedRealtime() < end) {
                automation.rootInActiveWindow?.let {
                    find(it)?.let { found ->
                        return found
                    }
                }
                // Inline chips belong to the IME's window, not the login form.
                for (window in automation.windows) window.root?.let {
                    find(it)?.let { found ->
                        return found
                    }
                }
                Thread.sleep(100)
            }
            return null
        }
        fun click(node: AccessibilityNodeInfo) {
            var current: AccessibilityNodeInfo? = node
            repeat(5) {
                val candidate = current ?: return@repeat
                if (
                    candidate.isClickable &&
                        candidate.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                )
                    return
                current = candidate.parent
            }
            error("Synthetic control was not clickable")
        }
        try {
            automation.serviceInfo =
                automation.serviceInfo.apply {
                    flags =
                        flags or
                            android.accessibilityservice.AccessibilityServiceInfo
                                .FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                }
            vault.requireUnlocked()
            val origin = CallerIdentity.appOrigin(context, client)
            val scope = AutofillScope(client, origin, false)
            val username = "synthetic-inline-user"
            Vault.request("create", "password" to "Synthetic-Inline-Vault-9274!")
            Vault.request(
                "save",
                "name" to "Synthetic account",
                "username" to username,
                "password" to "synthetic-password",
                "url" to origin,
            )
            Vault.autofillSession.grant(scope)
            context.startActivity(
                Intent()
                    .setComponent(
                        ComponentName(client, SyntheticAutofillClientActivity::class.java.name)
                    )
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            click(
                requireNotNull(
                    waitFor {
                        it.text?.toString()?.equals("Request test suggestions", true) == true
                    }
                )
            )
            val suggestion = waitFor {
                it.text?.toString() == username ||
                    it.contentDescription?.toString()?.startsWith("$username,") == true ||
                    it.text?.toString()?.startsWith("$username\n") == true
            }
            assertNotNull("The synthetic account suggestion must appear", suggestion)
            click(requireNotNull(suggestion))
            val filled = waitFor {
                it.className?.toString() == "android.widget.EditText" &&
                    it.text?.toString() == username
            }
            assertNotNull("Tapping the suggestion must fill the synthetic username", filled)
            val checked = java.util.concurrent.CountDownLatch(1)
            var mask = -1
            context.sendOrderedBroadcast(
                Intent("dev.nelszack.passwordmanager.TEST_CHECK_CLIENT").setPackage(client),
                null,
                object : android.content.BroadcastReceiver() {
                    override fun onReceive(context: android.content.Context, intent: Intent) {
                        mask = resultCode
                        checked.countDown()
                    }
                },
                android.os.Handler(android.os.Looper.getMainLooper()),
                -1,
                null,
                null,
            )
            assertTrue(
                "The synthetic form must answer its value check",
                checked.await(10, java.util.concurrent.TimeUnit.SECONDS),
            )
            assertEquals("Both synthetic fields must match (username=1, password=2)", 3, mask)
            assertTrue(Vault.autofillSession.allows(scope))
        } finally {
            // Restore the accessibility configuration even if closing the test client fails.
            try {
                context.sendBroadcast(
                    Intent("dev.nelszack.passwordmanager.TEST_FINISH_CLIENT").setPackage(client)
                )
            } finally {
                automation.serviceInfo = originalServiceInfo
            }
        }
    }
}
