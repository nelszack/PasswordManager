package dev.nelszack.passwordmanager

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.widget.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Run alone. Prime JNI before UI; never sync or open actual app vault files. */
@RunWith(AndroidJUnit4::class)
class MobileParityTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("parity-ui")
    }

    @Test
    fun typedEditingRecoveryGenerationAndBackupWorkThroughNativeScreens() {
        vault.requireUnlocked()
        val instrumentation = vault.instrumentation
        val context = vault.context
        val created = Vault.json("create", "password" to "Synthetic-Parity-Vault-9274!")
        val scenario = vault.launch(MobileManagementFixtureActivity::class.java)
        val screen = SyntheticScreen(scenario, vault)
        screen.click("Add item")
        scenario.onActivity { activity ->
            screen
                .views(activity.window.decorView)
                .filterIsInstance<Spinner>()
                .first()
                .setSelection(4)
        }
        screen.input("Name", "Synthetic Wi-Fi")
        screen.input("Username / owner", "synthetic-owner")
        screen.input("Password / primary secret", "synthetic-wifi-secret")
        screen.input("Websites (one per line)", "https://example.com\nhttps://alt.example.com")
        screen.input("Notes", "synthetic notes")
        screen.click("Add custom field")
        screen.input("Field name", "private detail")
        screen.input("Field value", "synthetic-field-secret")
        screen.click("Save item")
        screen.waitFor("Synthetic items")
        val saved = Vault.commandJson(VaultCommands.item(1))
        assertEquals("wifi", saved.getString("kind"))
        assertEquals(2, saved.getJSONArray("urls").length())
        assertEquals(1, saved.getJSONArray("fields").length())
        Vault.command(
            VaultCommands.update(
                1,
                saved.getString("name"),
                saved.optString("username"),
                "replacement-secret",
            ),
            saved.getLong("revision"),
        )
        assertEquals(
            1,
            Vault.commandJson(VaultCommands.history(1)).getJSONArray("history").length(),
        )
        Vault.command(VaultCommands.delete(1))
        scenario.onActivity { it.openTools() }
        screen.click("Deleted items")
        screen.click("Restore Synthetic Wi-Fi")
        screen.waitFor("Trash is empty")
        assertEquals(
            "replacement-secret",
            Vault.commandJson(VaultCommands.item(1)).getString("password"),
        )
        Vault.command(
            VaultCommands.setAuthenticator(
                1,
                "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
            )
        )
        scenario.onActivity { it.openItem(1) }
        screen.click("Authenticator & Duo")
        screen.waitFor("Current mode: hotp")
        screen.waitFor("Generate next HOTP code")
        assertEquals(
            "755224",
            Vault.commandJson(VaultCommands.authenticatorCode(1), confirmed = true)
                .getString("code"),
        )
        scenario.onActivity { it.openTools() }
        screen.click("Password generator")
        screen.waitFor("Generate")
        screen.input("Password length", "37")
        screen.click("Generate")
        val deadline = android.os.SystemClock.elapsedRealtime() + 10000
        var generated = ""
        while (generated.length != 37 && android.os.SystemClock.elapsedRealtime() < deadline) {
            vault.drain()
            scenario.onActivity { activity ->
                generated =
                    screen
                        .views(activity.window.decorView)
                        .filterIsInstance<EditText>()
                        .first { it.hint?.toString() == "Generated value" }
                        .text
                        .toString()
            }
            if (generated.length != 37) Thread.sleep(50)
        }
        assertEquals(37, generated.length)
        scenario.onActivity { it.openTools() }
        screen.click("Files & backups")
        val uri = Uri.parse("content://dev.nelszack.passwordmanager.paritydocuments/fixture")
        val filter =
            IntentFilter(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                addDataType("*/*")
            }
        val monitor =
            instrumentation.addMonitor(
                filter,
                Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(uri)),
                true,
            )
        try {
            screen.click("Create complete encrypted backup")
            screen.waitFor("Protect backup")
            screen.input("Backup password (at least 14 characters)", "Synthetic-Backup-Key-5842!")
            screen.input("Confirm backup password", "Synthetic-Backup-Key-5842!")
            screen.click("Create password-protected backup")
            screen.waitFor("Tools & recovery")
            assertEquals(1, monitor.hits)
            val bytes =
                context.contentResolver.openInputStream(uri)!!.use { it.readBounded(1024 * 1024) }
            assertTrue(bytes.size > 100)
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("replacement-secret"))
            val restored =
                Vault.json(
                    "restore_backup",
                    "data" to DeviceKeys.encode(bytes),
                    "password" to "Synthetic-Backup-Key-5842!",
                )
            bytes.fill(0)
            assertNotEquals(created.getString("vault"), restored.getString("vault"))
            Vault.request(
                "unlock",
                "vault" to restored.getString("vault"),
                "password" to "Synthetic-Backup-Key-5842!",
            )
            assertEquals(
                2,
                Vault.commandJson(VaultCommands.item(1)).getJSONArray("urls").length(),
            )
            assertEquals(
                1,
                Vault.commandJson(VaultCommands.history(1)).getJSONArray("history").length(),
            )
        } finally {
            instrumentation.removeMonitor(monitor)
            context.contentResolver.delete(uri, null, null)
        }
    }
}
