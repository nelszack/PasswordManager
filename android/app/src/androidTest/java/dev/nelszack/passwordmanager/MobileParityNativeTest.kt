package dev.nelszack.passwordmanager

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Isolated JNI parity workflow. Run alone; no network, preferences, Keystore or personal vaults.
 */
@RunWith(AndroidJUnit4::class)
class MobileParityNativeTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("parity-native")
    }

    @Test
    fun recoveryAuthenticatorsImportsCredentialsAndPasskeysSurviveNativeRoundTrips() {
        val password = "Synthetic-Parity-Original-9274!"
        val key = Vault.json("new_key_file").getString("data")
        val created = Vault.json("create_key", "key_file" to key)
        val vault = created.getString("vault")
        Vault.command(
            VaultCommands.add(
                "Synthetic account",
                "synthetic-user",
                "original-secret",
                listOf("https://example.com", "https://alt.example.com"),
                fields = listOf(VaultCommands.Field("secret field", "synthetic-value", true)),
            )
        )
        Vault.command(
            VaultCommands.setAuthenticator(
                1,
                "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
            )
        )
        assertThrows(IllegalStateException::class.java) {
            Vault.command(VaultCommands.authenticatorCode(1))
        }
        assertEquals(
            "755224",
            Vault.commandJson(VaultCommands.authenticatorCode(1), confirmed = true)
                .getString("code"),
        )
        val original = Vault.commandJson(VaultCommands.item(1))
        Vault.command(
            VaultCommands.update(
                1,
                original.getString("name"),
                original.optString("username"),
                "changed-secret",
            ),
            original.getLong("revision"),
        )
        assertEquals(
            1,
            Vault.commandJson(VaultCommands.history(1)).getJSONArray("history").length(),
        )
        Vault.command(VaultCommands.restorePassword(1, 1))
        assertEquals(
            "original-secret",
            Vault.commandJson(VaultCommands.item(1)).getString("password"),
        )
        Vault.command(VaultCommands.delete(1))
        assertEquals(1, Vault.commandJson(VaultCommands.trash()).getJSONArray("trash").length())
        Vault.command(VaultCommands.restoreTrash(1))
        val options =
            JSONObject(
                """{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"synthetic","displayName":"Synthetic"},"challenge":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""
            )
        Vault.request("passkey_create", "request" to options, "origin" to "https://example.com")
        assertEquals(1, (Vault.request("passkeys") as JSONArray).length())
        val backup = Vault.json("backup_create", "key_file" to key).getString("data")
        Vault.request("lock")
        Vault.request("unlock", "vault" to vault, "key_file" to key)
        // Exports and imports use raw bytes; backups above and below use base64 JSON.
        val reply = Vault.transfer("export_items", null, "format" to "json", "confirmed" to true)
        val exported = java.io.ByteArrayOutputStream().also(reply::writeTo).toByteArray()
        reply.wipe()
        assertTrue(exported.isNotEmpty())
        val preview =
            Vault.transfer("import_items", exported, "conflicts" to "skip", "preview" to true)
                .data as JSONObject
        Vault.transfer(
            "import_items",
            exported,
            "conflicts" to "skip",
            "preview" to false,
            "review_token" to preview.getString("review_token"),
        )
        assertEquals(1, (Vault.request("passkeys") as JSONArray).length())
        val material = Vault.json("biometric_material").getString("material")
        Vault.request("lock")
        Vault.request("biometric_unlock", "vault" to vault, "material" to material)
        var rejected = false
        try {
            Vault.request("rekey", "password" to password)
        } catch (_: IllegalStateException) {
            rejected = true
        }
        assertTrue("Biometric-only sessions cannot rekey", rejected)
        Vault.request("unlock", "vault" to vault, "key_file" to key)
        Vault.request("rekey", "password" to password)
        assertFalse(Vault.json("status").getBoolean("unlocked"))
        Vault.request("unlock", "vault" to vault, "password" to password)
        assertEquals(2, Vault.commandJson(VaultCommands.item(1)).getJSONArray("urls").length())
        val restored =
            Vault.json("restore_backup", "data" to backup, "key_file" to key).getString("vault")
        assertNotEquals(vault, restored)
        Vault.request("unlock", "vault" to restored, "key_file" to key)
        assertEquals(
            "287082",
            Vault.commandJson(VaultCommands.authenticatorCode(1), confirmed = true)
                .getString("code"),
        )
        assertEquals(1, (Vault.request("passkeys") as JSONArray).length())
        assertEquals(1, Vault.commandJson(VaultCommands.item(1)).getJSONArray("fields").length())
        assertEquals(
            1,
            Vault.commandJson(VaultCommands.search(query = "Synthetic account", kind = "login"))
                .getInt("total"),
        )
        val audit =
            Vault.commandJson(
                VaultCommands.audit(staleDays = null, requireTotp = false, checkBreaches = false)
            )
        assertTrue(audit.has("score"))
        assertFalse(audit.toString().contains("original-secret"))
        Vault.command(VaultCommands.setAuthenticator(1, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        assertEquals(
            "totp",
            VaultCommands.authenticatorMode(Vault.commandJson(VaultCommands.item(1))),
        )
        assertEquals(
            6,
            Vault.commandJson(VaultCommands.authenticatorCode(1)).getString("code").length,
        )
        Vault.command(VaultCommands.removeAuthenticator(1))
        assertNull(VaultCommands.authenticatorMode(Vault.commandJson(VaultCommands.item(1))))
        Vault.command(VaultCommands.delete(1))
        assertThrows(IllegalStateException::class.java) {
            Vault.command(VaultCommands.purgeTrash(1))
        }
        Vault.command(VaultCommands.purgeTrash(1), confirmed = true)
        assertEquals(0, Vault.commandJson(VaultCommands.trash()).getJSONArray("trash").length())
    }
}
