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
        Vault.request(
            "save_item",
            "name" to "Synthetic account",
            "kind" to "login",
            "password" to "original-secret",
            "username" to "synthetic-user",
            "urls" to JSONArray(listOf("https://example.com", "https://alt.example.com")),
            "fields" to
                JSONArray()
                    .put(
                        JSONObject()
                            .put("name", "secret field")
                            .put("value", "synthetic-value")
                            .put("secret", true)
                    ),
        )
        Vault.request(
            "set_otp",
            "id" to 1,
            "configuration" to
                "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
        )
        assertEquals(
            "755224",
            Vault.json("next_otp", "id" to 1, "confirmed" to true).getString("code"),
        )
        val original = Vault.json("item", "id" to 1)
        val update =
            original.keys().asSequence().map { it to original.get(it) }.toList().toTypedArray()
        Vault.request(
            "save_item",
            *update.filter { it.first != "password" }.toTypedArray(),
            "password" to "changed-secret",
        )
        assertEquals(1, Vault.json("history", "id" to 1).getJSONArray("history").length())
        Vault.request("restore_password", "id" to 1, "revision" to 1)
        assertEquals("original-secret", Vault.json("item", "id" to 1).getString("password"))
        Vault.request("delete", "id" to 1)
        assertEquals(1, Vault.json("trash").getJSONArray("trash").length())
        Vault.request("restore_trash", "id" to 1)
        val options =
            JSONObject(
                """{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"synthetic","displayName":"Synthetic"},"challenge":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""
            )
        Vault.request("passkey_create", "request" to options, "origin" to "https://example.com")
        assertEquals(1, (Vault.request("passkeys") as JSONArray).length())
        val backup = Vault.json("backup_create", "key_file" to key).getString("data")
        Vault.request("lock")
        Vault.request("unlock", "vault" to vault, "key_file" to key)
        val exported =
            Vault.json("export_items", "format" to "json", "confirmed" to true).getString("data")
        val preview =
            Vault.json("import_items", "data" to exported, "conflicts" to "skip", "preview" to true)
        Vault.request(
            "import_items",
            "data" to exported,
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
        assertEquals(2, Vault.json("item", "id" to 1).getJSONArray("urls").length())
        val restored =
            Vault.json("restore_backup", "data" to backup, "key_file" to key).getString("vault")
        assertNotEquals(vault, restored)
        Vault.request("unlock", "vault" to restored, "key_file" to key)
        assertEquals(
            "287082",
            Vault.json("next_otp", "id" to 1, "confirmed" to true).getString("code"),
        )
        assertEquals(1, (Vault.request("passkeys") as JSONArray).length())
        assertEquals(1, Vault.json("item", "id" to 1).getJSONArray("fields").length())
        assertEquals(
            1,
            Vault.json("search", "kind" to "login", "query" to "Synthetic account").getInt("total"),
        )
        val audit = Vault.json("audit", "check_breaches" to false)
        assertTrue(audit.has("score"))
        assertFalse(audit.toString().contains("original-secret"))
        Vault.request("set_otp", "id" to 1, "configuration" to "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        assertEquals("totp", Vault.json("authenticator_info", "id" to 1).getString("mode"))
        assertEquals(6, Vault.json("otp", "id" to 1).getString("code").length)
        Vault.request("remove_otp", "id" to 1)
        assertTrue(Vault.json("authenticator_info", "id" to 1).isNull("mode"))
        Vault.request("delete", "id" to 1)
        Vault.request("purge_trash", "id" to 1, "confirmed" to true)
        assertEquals(0, Vault.json("trash").getJSONArray("trash").length())
    }
}
