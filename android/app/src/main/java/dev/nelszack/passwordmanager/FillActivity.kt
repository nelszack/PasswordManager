package dev.nelszack.passwordmanager

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import org.json.JSONArray
import android.util.Log

class FillActivity : VaultActivity() {
    override fun automaticBiometrics() = true
    override fun contentScroller(): android.widget.ScrollView = object : android.widget.ScrollView(this) {
        override fun onMeasure(width: Int, height: Int) {
            val cap = (resources.displayMetrics.heightPixels * 0.65).toInt()
            val available = if (android.view.View.MeasureSpec.getMode(height) == android.view.View.MeasureSpec.UNSPECIFIED) cap else android.view.View.MeasureSpec.getSize(height)
            super.onMeasure(width, android.view.View.MeasureSpec.makeMeasureSpec(minOf(cap, available), android.view.View.MeasureSpec.AT_MOST))
        }
    }
    override fun onStart() {
        super.onStart()
        window.setLayout((resources.displayMetrics.widthPixels * 0.94).toInt(), android.view.ViewGroup.LayoutParams.WRAP_CONTENT)
        window.setGravity(android.view.Gravity.BOTTOM or android.view.Gravity.CENTER_HORIZONTAL)
    }
    private fun showSheet() { window.decorView.alpha = 1f; window.attributes = window.attributes.apply { dimAmount = 0.25f } }
    override fun showFailure(error: Throwable) {
        if (window.decorView.alpha == 0f) {
            showSheet()
            page("Autofill")
            button("Choose account") { intent.removeExtra("selected_id"); prepareFill() }
            button("Cancel") { finish() }
        }
        super.showFailure(error)
    }

    private var completedScope: AutofillScope? = null
    override fun retainVaultOnStop(): Boolean = isFinishing && completedScope?.let(Vault.autofillSession::allows) == true
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setResult(RESULT_CANCELED)
        val padding = (20 * resources.displayMetrics.density).toInt()
        layout.setPadding(padding, padding / 2, padding, padding / 2)
        if (intent.hasExtra("selected_id")) { window.decorView.alpha = 0f; window.attributes = window.attributes.apply { dimAmount = 0f } }
        if (intent.getStringExtra("mode") == "save") unlock({ save() }, fresh = true) else prepareFill()
    }
    private fun prepareFill() {
        val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
            ?: return finish()
        task({
            val form = Forms.read(this, structure) ?: error("Unsupported login form")
            val scope = AutofillScope(structure.activityComponent.packageName, form.origin, form.hostnameOnly)
            val reuse = Vault.autofillSession.allows(scope) && Vault.json("status").getBoolean("unlocked")
            Triple(form, scope, reuse)
        }) { (form, scope, reuse) ->
            Log.d("PMAutofill", "Unlock decision: reuse=$reuse code_only=${form.codeOnly}")
            if (!reuse || !intent.hasExtra("selected_id")) showSheet()
            unlock({ fill(form, scope) }, fresh = !reuse)
        }
    }
    private fun returnToSite(scope: AutofillScope, response: Dataset? = null) {
        completedScope = scope
        Vault.autofillSession.grant(scope)
        Vault.touch()
        if (response != null) setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        finish()
    }
    private fun fill(form: LoginForm, scope: AutofillScope) {
        task({ AutofillSuggestions.entries(form) }) { entries ->
            val chosen = (0 until entries.length()).map { entries.getJSONObject(it) }.firstOrNull {
                selectedVault == intent.getStringExtra("selected_vault") &&
                    it.getLong("id") == intent.getLongExtra("selected_id", -1) &&
                    AutofillSuggestions.token(form, it) == intent.getStringExtra("selection_token")
            }
            if (chosen != null) { fillChoice(form, scope, chosen); return@task }
            showSheet()
            page(if (form.codeOnly) "Choose verification code" else "Choose account")
            label(java.net.URI(form.origin).host ?: form.origin)
            if (form.hostnameOnly) label("Choose the saved address you want to use. Check any custom port.")
            if (entries.length() == 0) label(if (form.codeOnly) "No matching authenticator codes. Add this website address to the login that holds its code." else "No matching logins. Add this website or app to a login in your vault first.")
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                val selectedOrigin = if (form.hostnameOnly) CallerIdentity.websiteOrigin(entry.getString("origin")) else form.origin
                if (form.hostnameOnly) check(java.net.URI(selectedOrigin).host.trimEnd('.').equals(java.net.URI(form.origin).host.trimEnd('.'), ignoreCase = true)) { "Login hostname mismatch" }
                val address = if (form.hostnameOnly) "\nSaved address: $selectedOrigin" else ""
                button((if (form.codeOnly) "Fill verification code · " else "") + entry.getString("name") + " · " + entry.optString("username") + address) {
                    fillChoice(form, scope, entry)
                }
                if (entry.optBoolean("has_totp")) button("Copy verification code for ${entry.getString("name")} and return") {
                    task({ Vault.json("site_otp", "origin" to selectedOrigin, "id" to entry.getLong("id")) }) { code ->
                        SecretClipboard.copy(this, code.getString("code"), code.getInt("expires_in"))
                        returnToSite(scope)
                    }
                }
            }
            button("Cancel") { finish() }
        }
    }
    private fun fillChoice(form: LoginForm, scope: AutofillScope, entry: org.json.JSONObject) {
        val selectedOrigin = AutofillSuggestions.origin(form, entry)
        if (form.codeOnly) {
            task({ Vault.json("site_otp", "origin" to selectedOrigin, "id" to entry.getLong("id")) }) { code ->
                val dataset = Dataset.Builder(Forms.presentation(this, entry.getString("name")))
                    .setValue(requireNotNull(form.otp), AutofillValue.forText(code.getString("code"))).build()
                returnToSite(scope, dataset)
            }
            return
        }
        task({
            val login = Vault.json("login", "origin" to selectedOrigin, "id" to entry.getLong("id"))
            val code = if (form.otp != null && entry.optBoolean("has_totp")) Vault.json("site_otp", "origin" to selectedOrigin, "id" to entry.getLong("id")) else null
            Pair(login, code)
        }) { (login, code) ->
            val dataset = Dataset.Builder(Forms.presentation(this, entry.getString("name")))
            form.username?.let { dataset.setValue(it, AutofillValue.forText(login.optString("username", ""))) }
            form.password?.let { dataset.setValue(it, AutofillValue.forText(login.getString("password"))) }
            if (form.otp != null && code != null) dataset.setValue(form.otp, AutofillValue.forText(code.getString("code")))
            returnToSite(scope, dataset.build())
        }
    }
    private fun save() {
        val origin = intent.getStringExtra("origin") ?: return finish()
        val username = intent.getStringExtra("username").orEmpty()
        val password = intent.getStringExtra("password") ?: return finish()
        intent.removeExtra("password")
        val hostnameOnly = intent.getBooleanExtra("hostname_only", false)
        task({ Vault.request(if (hostnameOnly) "hostname_logins" else "logins", "origin" to origin) as JSONArray }) { entries ->
            page("Save login")
            label("Website or app: $origin\nUsername: $username")
            val address = if (hostnameOnly) {
                label("Chrome supplied the hostname but not the port. Check the saved website address and include a nonstandard port if needed.")
                edit("Saved website address", origin)
            } else null
            val name = edit("Login name", origin)
            fun save(id: Long? = null, title: String = name.text.toString(), previousOrigin: String? = null) {
                val savedOrigin = address?.let { CallerIdentity.addressBarOrigin(it.text.toString().trim(), origin) } ?: origin
                check(previousOrigin == null || previousOrigin == savedOrigin) { "Set the saved website address to match this login before updating it" }
                task({ Vault.request("save", "id" to id, "name" to title, "username" to username, "password" to password, "url" to savedOrigin); syncAfterChange() }) {
                    setResult(RESULT_OK); finish()
                }
            }
            button("Save new login") { save() }
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                val previousOrigin = if (hostnameOnly) entry.getString("origin") else origin
                if (entry.optString("username") == username) button("Update ${entry.getString("name")}\n$previousOrigin") {
                    android.app.AlertDialog.Builder(this).setMessage("Replace the password for ${entry.getString("name")} at $previousOrigin?")
                        .setNegativeButton("Cancel", null).setPositiveButton("Update") { _, _ -> guarded { save(entry.getLong("id"), entry.getString("name"), previousOrigin) } }.show()
                }
            }
            button("Cancel") { finish() }
        }
    }
}
