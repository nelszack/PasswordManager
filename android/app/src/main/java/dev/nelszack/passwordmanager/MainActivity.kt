package dev.nelszack.passwordmanager

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : VaultActivity() {
    private var exportData: ByteArray? = null
    override fun onCreate(state: Bundle?) { super.onCreate(state); home() }
    override fun onSessionLocked() { home() }
    override fun onResume() { super.onResume(); if (layout.childCount == 0) home() }
    private fun home() {
        page("Password Manager")
        button("Unlock vault") { unlock({ syncAndOpen() }) }
        button("Import encrypted vault") { pickFile(128 * 1024 * 1024) { data ->
            task({ Vault.json("import_vault", "data" to DeviceKeys.encode(data)) }) {
                selectedVault = it.getString("vault"); home()
            }
        } }
        button("Create vault") { create() }
        button("Cloud sync settings / download vault") { connection() }
        button("Enable password autofill") {
            startActivity(Intent("android.settings.REQUEST_SET_AUTOFILL_SERVICE", Uri.parse("package:$packageName")))
        }
        if (android.os.Build.VERSION.SDK_INT >= 34) button("Enable password and passkey provider") {
            startActivity(Intent("android.settings.CREDENTIAL_PROVIDER", Uri.parse("package:$packageName")))
        }
        label("Android 9+ passwords · Android 14+ passkeys\nVaults remain encrypted on this device.")
    }
    private fun syncAndOpen() {
        task({
            if (settings.getString("server", "").isNullOrBlank()) "" else
                runCatching { Vault.request("sync", *syncArgs()); "Synchronized" }
                    .getOrElse { "Using local vault. Sync pending: ${it.message}" }
        }) { message -> items(message = message) }
    }
    private fun create() {
        page("Create vault")
        val password = edit("Master password (at least 14 characters)", secret = true)
        val confirmation = edit("Confirm password", secret = true)
        button("Create") {
            check(password.text.toString() == confirmation.text.toString()) { "Passwords do not match" }
            val supplied = password.text.toString(); password.text.clear(); confirmation.text.clear()
            task({ Vault.json("create", "password" to supplied) }) { selectedVault = it.getString("vault"); items() }
        }
        button("Back") { home() }
    }
    private fun items(query: String = "", message: String = "") {
        task({ Vault.json("list", "query" to query) }) { result ->
            page("Your vault")
            if (message.isNotEmpty()) label(message)
            val search = edit("Search", query)
            button("Search") { items(search.text.toString()) }
            val entries = result.getJSONArray("items")
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                button(entry.getString("name") + "\n" + entry.optString("username", "")) { detail(entry.getLong("id")) }
            }
            button("Add login") { editor(null) }
            button("Sync now") { task({ Vault.request("sync", *syncArgs()) }) { items(message = "Synchronized") } }
            button("Review sync conflicts") { conflicts() }
            button("Enable biometric unlock") {
                check(Vault.primaryUnlock) { "Lock and unlock with your original password or key file first" }
                task({ Vault.json("biometric_material") }) { data ->
                    DeviceKeys.enable(this, data.getString("vault"), DeviceKeys.decode(data.getString("material"))) {
                        items(message = "Biometric unlock enabled on this device")
                    }
                }
            }
            button("Disable biometric unlock") { DeviceKeys.disable(this, selectedVault); items(message = "Biometric unlock disabled") }
            button("Export encrypted vault") {
                task({ DeviceKeys.decode(Vault.json("snapshot").getString("data")) }) { data ->
                    exportData = data
                    startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        type = "application/octet-stream"; addCategory(Intent.CATEGORY_OPENABLE); putExtra(Intent.EXTRA_TITLE, "vault.enc")
                    }, 2)
                }
            }
            button("Lock") { Vault.lock(); home() }
        }
    }
    private fun conflicts() {
        task({ Vault.json("cloud_conflicts", *syncArgs()) }) { review ->
            page("Review sync conflicts")
            label("Choose which version to keep for every differing field. Protected values remain hidden. Both original vaults are backed up before applying.")
            val choices = mutableListOf<() -> JSONObject>()
            val entries = review.getJSONArray("items")
            for (i in 0 until entries.length()) {
                val item = entries.getJSONObject(i)
                label("${item.optString("local")} / ${item.optString("remote")}", 20f)
                val fields = item.getJSONArray("fields")
                for (j in 0 until fields.length()) {
                    val field = fields.getJSONObject(j)
                    label("${field.getString("field")}\nLocal: ${field.getString("local")}\nCloud: ${field.getString("remote")}")
                    val selection = android.widget.Spinner(this).apply {
                        adapter = android.widget.ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("Choose…", "Local", "Cloud"))
                    }
                    layout.addView(selection)
                    choices.add {
                        check(selection.selectedItemPosition > 0) { "Choose a version for every field" }
                        JSONObject().put("id", item.getLong("id")).put("field", field.getString("field"))
                            .put("side", if (selection.selectedItemPosition == 1) "local" else "remote")
                    }
                }
            }
            button("Apply choices and sync") {
                val selected = JSONArray().apply { choices.forEach { put(it()) } }
                task({ Vault.request("cloud_resolve", *syncArgs(), "review_token" to review.getString("token"), "choices" to selected) }) {
                    items(message = "Conflicts resolved; encrypted recovery copies saved")
                }
            }
            button("Cancel") { items() }
        }
    }
    private fun detail(id: Long) {
        task({ Vault.json("item", "id" to id) }) { entry ->
            page(entry.getString("name"))
            label("Username: ${entry.optString("username", "")}")
            label("Type: ${entry.getString("kind")}")
            label("Websites: ${entry.optJSONArray("urls") ?: JSONArray()}")
            val secret = label("Secret hidden")
            button("Reveal secret") { secret.text = entry.optString("password", "") }
            if (entry.optBoolean("has_totp")) button("Show authenticator code") {
                task({ Vault.json("otp", "id" to id) }) { code -> secret.text = "${code.getString("code")} (${code.getInt("expires_in")} seconds)" }
            }
            val fields = entry.optJSONArray("fields") ?: JSONArray()
            for (i in 0 until fields.length()) {
                val field = fields.getJSONObject(i)
                val value = label(field.optString("name") + ": " + if (field.optBoolean("secret")) "Hidden" else field.optString("value"))
                if (field.optBoolean("secret")) button("Reveal ${field.optString("name")}") { value.text = field.optString("value") }
            }
            label(entry.optString("notes", ""))
            if (entry.getString("kind") == "login" && !entry.getString("name").startsWith("Passkey:")) button("Edit login") { editor(entry) }
            button("Delete") { android.app.AlertDialog.Builder(this).setMessage("Move this item to encrypted trash?")
                .setNegativeButton("Cancel", null).setPositiveButton("Delete") { _, _ ->
                    task({ Vault.request("delete", "id" to id); syncAfterChange() }) { items(message = it) }
                }.show() }
            button("Back") { items() }
        }
    }
    private fun editor(entry: JSONObject?) {
        page(if (entry == null) "Add login" else "Edit login")
        val name = edit("Name", entry?.optString("name").orEmpty())
        val username = edit("Username", entry?.optString("username").orEmpty())
        val password = edit("Password", entry?.optString("password").orEmpty(), true)
        val url = edit("Website URL", entry?.optJSONArray("urls")?.optString(0).orEmpty())
        val notes = edit("Notes", entry?.optString("notes").orEmpty(), true)
        button("Generate password") { task({ Vault.json("generate") }) { password.setText(it.getString("password")) } }
        button("Save") {
            val args = arrayOf("id" to entry?.getLong("id"), "name" to name.text.toString(), "username" to username.text.toString(),
                "password" to password.text.toString(), "url" to url.text.toString(), "notes" to notes.text.toString())
            password.text.clear(); notes.text.clear()
            task({ Vault.request("save", *args); syncAfterChange() }) { items(message = it) }
        }
        button("Cancel") { items() }
    }
    private fun connection() {
        page("Encrypted cloud sync")
        val server = edit("HTTPS server URL", settings.getString("server", "").orEmpty())
        val token = edit("Per-device credential (leave blank to keep)", secret = true)
        button("Save connection") {
            val endpoint = server.text.toString().trim(); val supplied = token.text.toString().trim(); token.text.clear()
            check(Uri.parse(endpoint).scheme == "https") { "An HTTPS endpoint is required" }
            task({
                val credential = supplied.ifEmpty { DeviceKeys.token(this) }
                Vault.request("cloud_list", "server" to endpoint, "token" to credential)
                DeviceKeys.saveToken(this, credential)
                settings.edit().putString("server", endpoint).commit()
            }) { connection() }
        }
        button("List cloud vaults") { task({ Vault.request("cloud_list", *syncArgs()) as JSONArray }) { vaults ->
            for (i in 0 until vaults.length()) {
                val id = vaults.getJSONObject(i).getString("id")
                button("Download $id") { task({ Vault.json("cloud_download", *syncArgs(), "id" to id) }) {
                    selectedVault = it.getString("vault"); home()
                } }
            }
        } }
        label("Conflicts preserve both encrypted copies. Import the conflict copy to inspect it; use desktop conflict review to reconcile changes.")
        button("Back") { home() }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 2) {
            val bytes = exportData; exportData = null
            if (resultCode == RESULT_OK && data?.data != null && bytes != null) task({
                contentResolver.openOutputStream(requireNotNull(data.data))?.use { it.write(bytes) } ?: error("Could not export vault")
            }) { home() }
        }
    }
}
