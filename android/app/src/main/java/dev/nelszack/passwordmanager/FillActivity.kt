package dev.nelszack.passwordmanager

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.util.Log
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import org.json.JSONArray

class FillActivity : VaultActivity() {
    // The same Material fields and buttons as the app, in the compact sheet.
    override val materialWidgets = true

    override fun automaticBiometrics() = true

    override fun contentScroller(): android.widget.ScrollView =
        object : android.widget.ScrollView(this) {
            override fun onMeasure(width: Int, height: Int) {
                val cap = (resources.displayMetrics.heightPixels * 0.65).toInt()
                val available =
                    if (
                        android.view.View.MeasureSpec.getMode(height) ==
                            android.view.View.MeasureSpec.UNSPECIFIED
                    )
                        cap
                    else android.view.View.MeasureSpec.getSize(height)
                super.onMeasure(
                    width,
                    android.view.View.MeasureSpec.makeMeasureSpec(
                        minOf(cap, available),
                        android.view.View.MeasureSpec.AT_MOST,
                    ),
                )
            }
        }

    override fun onStart() {
        super.onStart()
        window.setLayout(
            (resources.displayMetrics.widthPixels * 0.94).toInt(),
            android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
        )
        window.setGravity(android.view.Gravity.BOTTOM or android.view.Gravity.CENTER_HORIZONTAL)
    }

    private fun showSheet() {
        window.decorView.alpha = 1f
        window.attributes = window.attributes.apply { dimAmount = 0.25f }
    }

    override fun showFailure(error: Throwable) {
        if (window.decorView.alpha == 0f) {
            showSheet()
            page("Autofill")
            button("Choose account") {
                intent.removeExtra("selected_id")
                prepareFill()
            }
            button("Cancel") { finish() }
        }
        super.showFailure(error)
    }

    private var completedScope: AutofillScope? = null

    override fun retainVaultOnStop(): Boolean =
        isFinishing && completedScope?.let(Vault.autofillSession::allows) == true

    override fun delayLockOnLeave(): Boolean = false

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setResult(RESULT_CANCELED)
        val padding = (20 * resources.displayMetrics.density).toInt()
        layout.setPadding(padding, padding / 2, padding, padding / 2)
        if (intent.hasExtra("selected_id")) {
            window.decorView.alpha = 0f
            window.attributes = window.attributes.apply { dimAmount = 0f }
        }
        when (intent.getStringExtra("mode")) {
            "save" -> unlock({ save() }, fresh = true)
            "typed" -> prepareTyped()
            else -> prepareFill()
        }
    }

    /** Cards and identities: the person always chooses the item in this sheet. */
    private fun prepareTyped() {
        val structure =
            intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
                ?: return finish()
        task({
            val form = Forms.readTyped(this, structure) ?: error("Unsupported form")
            val scope =
                AutofillScope(
                    structure.activityComponent.packageName,
                    form.origin,
                    form.hostnameOnly,
                )
            val reuse =
                Vault.autofillSession.allows(scope) && Vault.json("status").getBoolean("unlocked")
            Triple(form, scope, reuse)
        }) { (form, scope, reuse) ->
            showSheet()
            unlock({ chooseTyped(form, scope) }, fresh = !reuse)
        }
    }

    /**
     * With more than five choices, adds a search box that narrows them as you type. Add each
     * choice's text and view to the returned list; a no-match message is announced.
     */
    private fun searchable(count: Int, hint: String): MutableList<Pair<String, android.view.View>> {
        val choices = mutableListOf<Pair<String, android.view.View>>()
        if (count <= 5) return choices
        val search = edit(hint)
        val none = label("")
        none.accessibilityLiveRegion = android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE
        search.addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun afterTextChanged(s: android.text.Editable?) {
                    val needle = s?.toString()?.trim().orEmpty()
                    var visible = 0
                    for ((text, view) in choices) {
                        val match = needle.isEmpty() || text.contains(needle, ignoreCase = true)
                        view.visibility = if (match) android.view.View.VISIBLE else android.view.View.GONE
                        if (match) visible++
                    }
                    none.text = if (visible == 0) "Nothing matches “$needle”." else ""
                }
            }
        )
        return choices
    }

    private fun chooseTyped(form: TypedForm, scope: AutofillScope) {
        task({ Vault.request("typed_choices", "kind" to form.kind) as JSONArray }) { choices ->
            page(if (form.card) "Choose a card" else "Choose an identity")
            label(java.net.URI(form.origin).host ?: form.origin)
            if (choices.length() == 0)
                label(
                    if (form.card) "No payment cards are saved in this vault."
                    else "No identities are saved in this vault."
                )
            val shown = searchable(choices.length(), if (form.card) "Search cards" else "Search identities")
            for (i in 0 until choices.length()) {
                val choice = choices.getJSONObject(i)
                val owner = choice.opt("username") as? String ?: ""
                val title = listOf(choice.getString("name"), owner).filter(String::isNotBlank).joinToString(" · ")
                button(title) {
                    fillTyped(form, scope, choice.getLong("id"))
                }
                    .also { shown += title to it }
            }
            if (choices.length() == 0)
                button(if (form.card) "Add a payment card" else "Add an identity") {
                    startActivity(
                        addRequestIntent(this)
                            .putExtra(EXTRA_ADD_ITEM_KIND, if (form.card) "payment-card" else "identity")
                    )
                    finish()
                }
            button("Cancel") { finish() }
        }
    }

    private fun fillTyped(form: TypedForm, scope: AutofillScope, id: Long) {
        task({
            Vault.json(
                "typed_values",
                "id" to id,
                "kind" to form.kind,
                "roles" to JSONArray(form.fields.values.distinct()),
            )
        }) { values ->
            val dataset = Dataset.Builder(Forms.presentation(this, "Password Manager"))
            var filled = 0
            for ((field, role) in form.fields) {
                val value = values.optString(role)
                if (value.isNotEmpty()) {
                    dataset.setValue(field, AutofillValue.forText(value))
                    filled++
                }
            }
            if (filled == 0) label("This item has nothing to fill in these fields.")
            else returnToSite(scope, dataset.build())
        }
    }

    private fun prepareFill() {
        val structure =
            intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
                ?: return finish()
        task({
            val form = Forms.read(this, structure) ?: error("Unsupported login form")
            val scope =
                AutofillScope(
                    structure.activityComponent.packageName,
                    form.origin,
                    form.hostnameOnly,
                )
            val reuse =
                Vault.autofillSession.allows(scope) && Vault.json("status").getBoolean("unlocked")
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
        if (response != null)
            setResult(
                RESULT_OK,
                Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response),
            )
        finish()
    }

    private fun fill(form: LoginForm, scope: AutofillScope) {
        task({ AutofillSuggestions.entries(form) }) { entries ->
            val chosen =
                (0 until entries.length())
                    .map { entries.getJSONObject(it) }
                    .firstOrNull {
                        selectedVault == intent.getStringExtra("selected_vault") &&
                            it.getLong("id") == intent.getLongExtra("selected_id", -1) &&
                            AutofillSuggestions.token(form, it) ==
                                intent.getStringExtra("selection_token")
                    }
            if (chosen != null) {
                fillChoice(form, scope, chosen)
                return@task
            }
            showSheet()
            page(if (form.codeOnly) "Choose one-time code" else "Choose account")
            label(java.net.URI(form.origin).host ?: form.origin)
            if (form.hostnameOnly)
                label("Choose the saved address you want to use. Check any custom port.")
            if (entries.length() == 0) {
                label(
                    if (form.codeOnly)
                        "No matching authenticator codes. Add this website address to the login that holds its code."
                    else
                        "No saved login matches this site yet. Add this website or app to a login, then try again."
                )
                if (!form.codeOnly)
                    button("Add a login for this site") {
                        startActivity(
                            addRequestIntent(this).putExtra(EXTRA_ADD_LOGIN_ORIGIN, form.origin)
                        )
                        finish()
                    }
                else
                    button("Open Password Manager") {
                        startActivity(
                            android.content.Intent(this, MainActivity::class.java)
                                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                        finish()
                    }
            }
            val choices = searchable(entries.length(), "Search accounts")
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                val selectedOrigin =
                    if (form.hostnameOnly) CallerIdentity.websiteOrigin(entry.getString("origin"))
                    else form.origin
                if (form.hostnameOnly)
                    check(
                        java.net
                            .URI(selectedOrigin)
                            .host
                            .trimEnd('.')
                            .equals(java.net.URI(form.origin).host.trimEnd('.'), ignoreCase = true)
                    ) {
                        "Login hostname mismatch"
                    }
                val address = if (form.hostnameOnly) "\nSaved address: $selectedOrigin" else ""
                val searchText = entry.getString("name") + " " + entry.optString("username")
                button(
                        (if (form.codeOnly) "Fill one-time code · " else "") +
                            entry.getString("name") +
                            " · " +
                            entry.optString("username") +
                            address
                    ) {
                        fillChoice(form, scope, entry)
                    }
                    .also { choices += searchText to it }
                if (entry.optBoolean("has_totp"))
                    button("Copy one-time code for ${entry.getString("name")} and return") {
                        task({
                            Vault.json(
                                "site_otp",
                                "origin" to selectedOrigin,
                                "id" to entry.getLong("id"),
                            )
                        }) { code ->
                            SecretClipboard.copy(
                                this,
                                code.getString("code"),
                                code.getInt("expires_in"),
                                what = "Code copied",
                            )
                            returnToSite(scope)
                        }
                    }
                        .also { choices += searchText to it }
            }
            button("Cancel") { finish() }
        }
    }

    private fun fillChoice(form: LoginForm, scope: AutofillScope, entry: org.json.JSONObject) {
        val selectedOrigin = AutofillSuggestions.origin(form, entry)
        if (form.codeOnly) {
            task({
                Vault.json("site_otp", "origin" to selectedOrigin, "id" to entry.getLong("id"))
            }) { code ->
                val dataset =
                    Dataset.Builder(Forms.presentation(this, entry.getString("name")))
                        .setValue(
                            requireNotNull(form.otp),
                            AutofillValue.forText(code.getString("code")),
                        )
                        .build()
                returnToSite(scope, dataset)
            }
            return
        }
        task({
            val login = Vault.json("login", "origin" to selectedOrigin, "id" to entry.getLong("id"))
            val code =
                if (form.otp != null && entry.optBoolean("has_totp"))
                    Vault.json("site_otp", "origin" to selectedOrigin, "id" to entry.getLong("id"))
                else null
            Pair(login, code)
        }) { (login, code) ->
            val dataset = Dataset.Builder(Forms.presentation(this, entry.getString("name")))
            form.username?.let {
                dataset.setValue(it, AutofillValue.forText(login.optString("username", "")))
            }
            form.password?.let {
                dataset.setValue(it, AutofillValue.forText(login.getString("password")))
            }
            if (form.otp != null && code != null)
                dataset.setValue(form.otp, AutofillValue.forText(code.getString("code")))
            returnToSite(scope, dataset.build())
        }
    }

    private fun save() {
        val origin = intent.getStringExtra("origin") ?: return finish()
        val username = intent.getStringExtra("username").orEmpty()
        val password = intent.getStringExtra("password") ?: return finish()
        intent.removeExtra("password")
        val hostnameOnly = intent.getBooleanExtra("hostname_only", false)
        task({
            val entries =
                Vault.request(if (hostnameOnly) "hostname_logins" else "logins", "origin" to origin)
                    as JSONArray
            // Typed or filled by another app: unchanged if the vault already holds it. Rust compares
            // and returns summaries only.
            val saved =
                Vault.request(
                    "saved_logins",
                    "origin" to origin,
                    "hostname_only" to hostnameOnly,
                    "username" to username,
                    "password" to password,
                ) as JSONArray
            entries to saved
        }) { (entries, saved) ->
            if (saved.length() > 0) {
                page("Login already saved")
                label(
                    "“${saved.getJSONObject(0).getString("name")}” already has this username and password. Nothing was changed."
                )
                MobileUi.button(this, "Done", primary = true) {
                        setResult(RESULT_OK)
                        finish()
                    }
                    .also(layout::addView)
                return@task
            }
            page("Save login")
            label(
                "Website or app: $origin\nUsername: ${username.ifBlank { "(not captured)" }}"
            )
            val address =
                if (hostnameOnly) {
                    label(
                        "Chrome supplied the hostname but not the port. Check the saved website address and include a nonstandard port if needed."
                    )
                    edit("Saved website address", origin)
                } else null
            // Suggest the site's name ("example.com"), not the full origin.
            val suggested =
                runCatching { java.net.URI(origin).host?.removePrefix("www.") }.getOrNull()
                    ?: origin
            val name = edit("Login name", suggested)
            fun save(
                id: Long? = null,
                title: String = name.text.toString(),
                previousOrigin: String? = null,
            ) {
                val savedOrigin =
                    address?.let {
                        CallerIdentity.addressBarOrigin(it.text.toString().trim(), origin)
                    } ?: origin
                check(previousOrigin == null || previousOrigin == savedOrigin) {
                    "Set the saved website address to match this login before updating it"
                }
                task({
                    Vault.command(
                        if (id == null)
                            VaultCommands.add(title, username, password, listOf(savedOrigin))
                        else
                            // No captured username keeps the saved one.
                            VaultCommands.update(
                                id,
                                title,
                                username.ifBlank { null },
                                password,
                                listOf(savedOrigin),
                            )
                    )
                    // The browser gets its result without waiting for sync.
                    Vault.queueSync()
                }) {
                    setResult(RESULT_OK)
                    finish()
                }
            }
            // Usernames match ignoring case and surrounding space, as sites do for emails. Without a
            // captured username (change-password forms rarely show one) every account may be updated.
            val captured = username.trim()
            val updatable =
                (0 until entries.length()).map(entries::getJSONObject).filter {
                    captured.isEmpty() ||
                        it.optString("username").trim().equals(captured, ignoreCase = true)
                }
            // With one saved login for the site and no username, the new password almost
            // certainly belongs to it.
            val preferUpdate = captured.isEmpty() && entries.length() == 1
            fun updateButton(entry: org.json.JSONObject, primary: Boolean) {
                val previousOrigin = if (hostnameOnly) entry.getString("origin") else origin
                val account =
                    entry.optString("username").takeIf { captured.isEmpty() && it.isNotBlank() }
                val title =
                    "Update ${entry.getString("name")}" +
                        (account?.let { " ($it)" } ?: "") +
                        "\n$previousOrigin"
                MobileUi.button(this, title, primary = primary) {
                        guarded {
                            com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                                .setMessage(
                                    "Replace the password for ${entry.getString("name")} at $previousOrigin?"
                                )
                                .setNegativeButton("Cancel", null)
                                .setPositiveButton("Update") { _, _ ->
                                    guarded {
                                        save(
                                            entry.getLong("id"),
                                            entry.getString("name"),
                                            previousOrigin,
                                        )
                                    }
                                }
                                .show()
                        }
                    }
                    .also(layout::addView)
            }
            if (preferUpdate) {
                label(
                    "Update the saved password for “${updatable[0].getString("name")}”, or save a new login."
                )
                updateButton(updatable[0], primary = true)
                button("Save new login") { save() }
            } else {
                button("Save new login") { save() }
                updatable.forEach { updateButton(it, primary = false) }
            }
            button("Cancel") { finish() }
        }
    }
}
