package dev.nelszack.passwordmanager

import android.content.Context
import org.json.JSONObject

/**
 * Display names for vaults on this device, like the desktop app's and `pm vaults`. Encrypted vault
 * files keep their opaque names; only this label is stored, outside the vault.
 */
internal object VaultNames {
    private const val KEY = "vault_names"

    private fun names(context: Context): JSONObject =
        runCatching {
                JSONObject(
                    context
                        .getSharedPreferences("settings", Context.MODE_PRIVATE)
                        .getString(KEY, "{}")
                        .orEmpty()
                )
            }
            .getOrDefault(JSONObject())

    /** The name shown for [id]; unnamed vaults use the same defaults as the desktop app. */
    fun label(context: Context, id: String, all: List<String>): String =
        names(context).optString(id).ifBlank {
            if (all.size <= 1) "Personal vault" else "Vault ${all.indexOf(id).coerceAtLeast(0) + 1}"
        }

    /** Validation shared with the desktop: 1–80 characters on one line. */
    fun problem(name: String): String? {
        val trimmed = name.trim()
        return if (trimmed.isEmpty() || trimmed.length > 80 || trimmed.any { it.isISOControl() })
            "Choose a vault name with 1–80 characters and no line breaks."
        else null
    }

    fun save(context: Context, id: String, name: String) {
        problem(name)?.let { throw IllegalArgumentException(it) }
        val updated = names(context).put(id, name.trim())
        context
            .getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit()
            .putString(KEY, updated.toString())
            .apply()
    }
}
