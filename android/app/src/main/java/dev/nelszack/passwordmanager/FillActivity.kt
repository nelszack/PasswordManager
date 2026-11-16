package dev.nelszack.passwordmanager

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import org.json.JSONArray

class FillActivity : VaultActivity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setResult(RESULT_CANCELED)
        unlock({ if (intent.getStringExtra("mode") == "save") save() else fill() }, fresh = true)
    }
    private fun fill() {
        val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
            ?: return finish()
        task({ Forms.read(this, structure) ?: error("Unsupported login form") }) { form ->
            task({ Vault.request("logins", "origin" to form.origin) as JSONArray }) { entries ->
                page("Fill login")
                label("Website or app: ${form.origin}")
                if (entries.length() == 0) label("No matching logins. Add this website or app to a login in your vault first.")
                for (i in 0 until entries.length()) {
                    val entry = entries.getJSONObject(i)
                    button(entry.getString("name") + " · " + entry.optString("username")) {
                        task({ Vault.json("login", "origin" to form.origin, "id" to entry.getLong("id")) }) { login ->
                            val dataset = Dataset.Builder(Forms.presentation(this, entry.getString("name")))
                            form.username?.let { dataset.setValue(it, AutofillValue.forText(login.optString("username", ""))) }
                            form.password?.let { dataset.setValue(it, AutofillValue.forText(login.getString("password"))) }
                            val response = FillResponse.Builder().addDataset(dataset.build()).apply {
                                form.password?.let { password -> setSaveInfo(SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(password))
                                    .apply { form.username?.let { user -> setOptionalIds(arrayOf(user)) } }.build()) }
                            }.build()
                            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)); finish()
                        }
                    }
                }
                button("Cancel") { finish() }
            }
        }
    }
    private fun save() {
        val origin = intent.getStringExtra("origin") ?: return finish()
        val username = intent.getStringExtra("username").orEmpty()
        val password = intent.getStringExtra("password") ?: return finish()
        intent.removeExtra("password")
        task({ Vault.request("logins", "origin" to origin) as JSONArray }) { entries ->
            page("Save login")
            label("Website or app: $origin\nUsername: $username")
            val name = edit("Login name", origin)
            fun save(id: Long? = null, title: String = name.text.toString()) {
                task({ Vault.request("save", "id" to id, "name" to title, "username" to username, "password" to password, "url" to origin); syncAfterChange() }) {
                    setResult(RESULT_OK); finish()
                }
            }
            button("Save new login") { save() }
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                if (entry.optString("username") == username) button("Update ${entry.getString("name")}") {
                    android.app.AlertDialog.Builder(this).setMessage("Replace the password for ${entry.getString("name")} at $origin?")
                        .setNegativeButton("Cancel", null).setPositiveButton("Update") { _, _ -> save(entry.getLong("id"), entry.getString("name")) }.show()
                }
            }
            button("Cancel") { finish() }
        }
    }
}
