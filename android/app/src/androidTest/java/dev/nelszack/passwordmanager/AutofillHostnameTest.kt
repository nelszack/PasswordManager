package dev.nelszack.passwordmanager

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Isolated JNI regression; run this class alone so no personal vault is opened. */
@RunWith(AndroidJUnit4::class)
class AutofillHostnameTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("autofill-regression")
    }

    @Test
    fun hostnameChoicesKeepExactSecretChecks() {
        assertFalse(
            vault
                .reply("hostname_logins", "origin" to "https://accounts.example.com")
                .getBoolean("ok")
        )
        assertTrue(
            vault.reply("create", "password" to "Synthetic-Autofill-Vault-9274!").getBoolean("ok")
        )
        for (port in listOf("", ":8443")) {
            assertTrue(
                vault
                    .reply(
                        "vault",
                        "command" to
                            VaultCommands.add(
                                "Synthetic account$port",
                                "synthetic-user",
                                "synthetic-secret",
                                listOf("https://accounts.example.com$port"),
                            ),
                    )
                    .getBoolean("ok")
            )
        }
        val choices = vault.reply("hostname_logins", "origin" to "https://accounts.example.com")
        assertTrue(choices.getBoolean("ok"))
        assertFalse(choices.toString().contains("synthetic-secret"))
        val entries = choices.getJSONArray("data")
        assertEquals(2, entries.length())
        val alternate =
            (0 until entries.length())
                .map { entries.getJSONObject(it) }
                .single { it.getString("origin") == "https://accounts.example.com:8443" }
        assertFalse(
            vault
                .reply(
                    "login",
                    "id" to alternate.getLong("id"),
                    "origin" to "https://accounts.example.com",
                )
                .getBoolean("ok")
        )
        assertTrue(
            vault
                .reply(
                    "login",
                    "id" to alternate.getLong("id"),
                    "origin" to alternate.getString("origin"),
                )
                .getBoolean("ok")
        )
        assertEquals(
            0,
            vault
                .reply("hostname_logins", "origin" to "https://accounts.example.com.evil.test")
                .getJSONArray("data")
                .length(),
        )
        vault.reply("lock")
        assertFalse(
            vault
                .reply("hostname_logins", "origin" to "https://accounts.example.com")
                .getBoolean("ok")
        )
    }
}
