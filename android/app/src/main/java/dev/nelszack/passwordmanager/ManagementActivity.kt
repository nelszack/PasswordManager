package dev.nelszack.passwordmanager

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject

/** Native management workflows; all vault mutations and validation live in Rust. */
abstract class ManagementActivity : VaultActivity() {
    override val modernUi = true
    private lateinit var scaffold: MobileScaffold
    private var workCount = 0
    private val dialogs = mutableListOf<android.app.Dialog>()
    protected var pageBack: (() -> Unit)? = null
        set(value) {
            field = value
            if (::scaffold.isInitialized) scaffold.backAction = value
        }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        scaffold = MobileScaffold(this, layout, { navigate(it) }, { showHome() })
        onBackPressedDispatcher.addCallback(
            this,
            object : androidx.activity.OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    val back = pageBack
                    if (back != null) guarded(back)
                    else {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                        isEnabled = true
                    }
                }
            },
        )
    }

    protected open fun navigate(tab: String) {
        when (tab) {
            "Vault" -> showItems()
            "Tools" -> tools()
            else -> preferences()
        }
    }

    protected fun rootNavigation(tab: String, unlocked: Boolean = true) {
        pageBack =
            if (tab == "Vault") null
            else {
                { navigate("Vault") }
            }
        scaffold.root(tab, unlocked)
    }

    override fun onPageChanged(title: String) {
        scaffold.page(title)
        pageBack = { navigate("Tools") }
    }

    override fun onWorkStarted() {
        workCount++
        if (::scaffold.isInitialized) scaffold.working(true)
    }

    override fun onWorkFinished() {
        workCount = (workCount - 1).coerceAtLeast(0)
        if (::scaffold.isInitialized) scaffold.working(workCount > 0)
    }

    override fun clearSecrets() {
        super.clearSecrets()
        workCount = 0
        pageBack = null
        dialogs.toList().forEach { it.dismiss() }
        dialogs.clear()
        if (::scaffold.isInitialized) scaffold.clear()
    }

    protected fun section(title: String) {
        label(title, 18f)
    }

    protected fun primary(title: String, action: () -> Unit) =
        MobileUi.button(this, title, primary = true) { guarded(action) }.also(layout::addView)

    protected fun actionRow(
        title: String,
        subtitle: String,
        badge: String = "",
        action: () -> Unit,
    ) = MobileUi.row(this, title, subtitle, badge) { guarded(action) }.also(layout::addView)

    protected fun pairedActions(
        left: String,
        right: String,
        leftAction: () -> Unit,
        rightAction: () -> Unit,
    ): Pair<Button, Button> {
        val row = LinearLayout(this)
        val first = MobileUi.button(this, left) { guarded(leftAction) }
        val second = MobileUi.button(this, right) { guarded(rightAction) }
        row.addView(
            first,
            LinearLayout.LayoutParams(0, -2, 1f).apply {
                marginEnd = MobileUi.dp(this@ManagementActivity, 4)
            },
        )
        row.addView(
            second,
            LinearLayout.LayoutParams(0, -2, 1f).apply {
                marginStart = MobileUi.dp(this@ManagementActivity, 4)
            },
        )
        layout.addView(row, MobileUi.margins(this))
        return first to second
    }

    protected fun notice(message: String) {
        label(message).apply {
            background = MobileUi.shape(this@ManagementActivity, R.color.pm_accent_soft)
            val p = MobileUi.dp(this@ManagementActivity, 14)
            setPadding(p, p, p, p)
        }
    }

    protected abstract fun showItems(message: String = "")

    protected abstract fun showDetail(id: Long)

    protected abstract fun showHome()

    protected open fun afterToolChange() = syncAfterChange()

    private val kinds =
        listOf(
            "login",
            "secure-note",
            "payment-card",
            "identity",
            "wifi",
            "software-license",
            "ssh-key",
            "api-secret",
        )
    private var documentAction: ((Uri) -> Unit)? = null

    protected fun choice(title: String, values: List<String>, selected: String? = null): Spinner {
        label(title)
        return Spinner(this).apply {
            adapter =
                ArrayAdapter(
                    this@ManagementActivity,
                    android.R.layout.simple_spinner_dropdown_item,
                    values,
                )
            minimumHeight = MobileUi.dp(this@ManagementActivity, 52)
            background = MobileUi.shape(this@ManagementActivity, outline = true, radius = 12)
            setPadding(
                MobileUi.dp(this@ManagementActivity, 8),
                0,
                MobileUi.dp(this@ManagementActivity, 8),
                0,
            )
            layoutParams = MobileUi.margins(this@ManagementActivity, 16)
            setSelection(values.indexOf(selected).coerceAtLeast(0))
            this@ManagementActivity.layout.addView(this)
        }
    }

    protected fun toggle(title: String, checked: Boolean = false) =
        CheckBox(this).apply {
            text = title
            isChecked = checked
            minHeight = MobileUi.dp(this@ManagementActivity, 48)
            setTextColor(MobileUi.color(this@ManagementActivity, R.color.pm_text))
            buttonTintList =
                android.content.res.ColorStateList.valueOf(
                    MobileUi.color(this@ManagementActivity, R.color.pm_accent)
                )
            this@ManagementActivity.layout.addView(this)
        }

    protected fun confirm(message: String, action: () -> Unit) {
        val dialog =
            AlertDialog.Builder(this)
                .setMessage(message)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Confirm") { _, _ -> guarded(action) }
                .create()
        track(dialog)
        dialog.show()
    }

    /** Dialogs are dismissed with other secrets when the vault locks. */
    private fun track(dialog: AlertDialog) {
        dialogs.add(dialog)
        dialog.setOnDismissListener { dialogs.remove(dialog) }
    }

    /** Runs a shared vault command that changes the vault, then syncs. */
    private fun change(
        command: org.json.JSONObject,
        confirmed: Boolean = false,
        done: () -> Unit,
    ) {
        task({
            Vault.command(command, confirmed = confirmed)
            afterToolChange()
        }) {
            done()
        }
    }

    /** Runs a mobile-only operation that changes the vault, then syncs. */
    private fun changeLocal(op: String, done: () -> Unit) {
        task({
            Vault.request(op)
            afterToolChange()
        }) {
            done()
        }
    }

    protected fun tools() {
        page("Tools & recovery")
        rootNavigation("Tools")
        label("Everything you need to manage and recover your vault.")
        section("Everyday tools")
        actionRow("Add item", "Logins, notes, cards, keys and more", "+") { typedEditor(null) }
        actionRow("Advanced search", "Filter by type, website or password health", "S") {
            advancedSearch()
        }
        actionRow("Password generator", "Strong passwords and memorable passphrases", "G") {
            generator()
        }
        section("Security")
        actionRow("Vault health", "Review weak, reused or outdated passwords", "H") { auditForm() }
        actionRow("Vault credentials", "Change your master password or key", "K") { credentials() }
        section("Recovery & data")
        actionRow("Deleted items", "Restore items or review your trash", "R") { trash() }
        actionRow("Files & backups", "Encrypted backups and import / export", "B") { files() }
        actionRow("Sync controls", "Connection status and synchronization", "S") { syncControls() }
        actionRow("Mobile settings", "Locking, clipboard and generator preferences") {
            preferences(back = { tools() })
        }
    }

    protected fun typedEditor(entry: JSONObject?) {
        page(if (entry == null) "Add item" else "Edit item")
        val kind =
            choice(
                "Item type",
                kinds.map(MobileUi::kindLabel),
                entry?.optString("kind")?.let(MobileUi::kindLabel),
            )
        section("Item details")
        val name = edit("Name", entry?.optString("name").orEmpty())
        val username = edit("Username / owner", entry?.opt("username") as? String ?: "")
        val password =
            edit("Password / primary secret", entry?.opt("password") as? String ?: "", true)
        val urls = entry?.optJSONArray("urls") ?: JSONArray()
        val websites =
            edit(
                "Websites (one per line)",
                (0 until urls.length()).joinToString("\n") { urls.getString(it) },
            )
        websites.isSingleLine = false
        websites.minLines = 2
        val notes = edit("Notes", entry?.opt("notes") as? String ?: "", true)
        notes.isSingleLine = false
        notes.minLines = 3
        label("Custom fields")
        data class Field(
            val name: EditText,
            val value: EditText,
            val secret: CheckBox,
            val removed: CheckBox,
        )
        val rows = mutableListOf<Field>()
        val fieldRows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        layout.addView(fieldRows)
        fun field(value: JSONObject?) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            val fieldName =
                MobileUi.field(this, row, "Field name", value?.optString("name").orEmpty(), false)
            val fieldValue =
                MobileUi.field(this, row, "Field value", value?.opt("value") as? String ?: "", true)
            val secret =
                CheckBox(this).apply {
                    text = "Secret field"
                    isChecked = value?.optBoolean("secret") ?: true
                    minHeight = MobileUi.dp(this@ManagementActivity, 48)
                }
            val removed =
                CheckBox(this).apply {
                    text = "Remove this field"
                    minHeight = MobileUi.dp(this@ManagementActivity, 48)
                }
            row.addView(secret)
            row.addView(removed)
            fieldRows.addView(row)
            rows.add(Field(fieldName, fieldValue, secret, removed))
        }
        val fields = entry?.optJSONArray("fields") ?: JSONArray()
        for (i in 0 until fields.length()) field(fields.getJSONObject(i))
        button("Add custom field") { field(null) }
        button("Generate password") {
            task({ Vault.json("generate") }) { password.setText(it.getString("password")) }
        }
        var saving = false
        fun currentDraft() =
            listOf(
                kind.selectedItemPosition.toString(),
                name.text.toString(),
                username.text.toString(),
                password.text.toString(),
                websites.text.toString(),
                notes.text.toString(),
                rows.joinToString("\u0000") {
                    "${it.name.text}\u0001${it.value.text}\u0001${it.secret.isChecked}\u0001${it.removed.isChecked}"
                },
            )
        val original = currentDraft()
        fun leave() {
            if (saving) return
            if (currentDraft() != original) confirm("Discard your unsaved changes?") { showItems() }
            else showItems()
        }
        pageBack = { leave() }
        lateinit var save: Button
        lateinit var cancel: Button
        save =
            primary("Save item") {
                val savedFields =
                    rows
                        .filter { !it.removed.isChecked }
                        .map {
                            VaultCommands.Field(
                                it.name.text.toString().trim(),
                                it.value.text.toString(),
                                it.secret.isChecked,
                            )
                        }
                val urls =
                    websites.text.toString().lines().map(String::trim).filter(String::isNotEmpty)
                val itemKind = kinds[kind.selectedItemPosition]
                val command =
                    if (entry == null)
                        VaultCommands.add(
                            name.text.toString(),
                            username.text.toString(),
                            password.text.toString(),
                            urls,
                            notes.text.toString(),
                            itemKind,
                            savedFields,
                        )
                    else
                        VaultCommands.update(
                            entry.getLong("id"),
                            name.text.toString(),
                            username.text.toString(),
                            password.text.toString(),
                            urls,
                            notes.text.toString(),
                            itemKind,
                            savedFields,
                            replaceDetails = true,
                        )
                saving = true
                save.isEnabled = false
                cancel.isEnabled = false
                save.text = "Saving…"
                task({
                    runCatching {
                        Vault.command(command, entry?.getLong("revision"))
                        afterToolChange()
                    }
                }) { result ->
                    saving = false
                    result.fold(
                        { message ->
                            password.text.clear()
                            notes.text.clear()
                            rows.forEach { it.value.text.clear() }
                            showItems(message)
                        },
                        { error ->
                            save.isEnabled = true
                            cancel.isEnabled = true
                            save.text = "Save item"
                            showFailure(error)
                        },
                    )
                }
            }
        cancel = button("Cancel") { leave() }
        scaffold.pin(cancel, save)
    }

    protected fun history(id: Long) {
        task({ Vault.commandJson(VaultCommands.history(id)).getJSONArray("history") }) { revisions
            ->
            page("Password history")
            pageBack = { showDetail(id) }
            if (revisions.length() == 0) label("No saved password revisions")
            for (i in 0 until revisions.length()) button(
                "Restore revision ${i + 1} · ${MobileUi.date(revisions.getString(i))}"
            ) {
                confirm(
                    "Replace the current password with revision ${i + 1}? The current password will remain in history."
                ) {
                    change(VaultCommands.restorePassword(id, i + 1)) { showDetail(id) }
                }
            }
            button("Back to item") { showDetail(id) }
        }
    }

    private fun trash() {
        task({ Vault.commandJson(VaultCommands.trash()).getJSONArray("trash") }) { entries ->
            page("Deleted items")
            if (entries.length() == 0) label("Trash is empty")
            for (i in 0 until entries.length()) {
                val item = entries.getJSONObject(i)
                val id = item.getLong("id")
                label(
                    item.getString("name") +
                        "\nDeleted: " +
                        MobileUi.date(item.getString("deleted"))
                )
                button("Restore ${item.getString("name")}") {
                    change(VaultCommands.restoreTrash(id)) { trash() }
                }
                button("Permanently delete ${item.getString("name")}") {
                    confirm("Permanently erase this deleted item? This cannot be undone.") {
                        change(VaultCommands.purgeTrash(id), confirmed = true) { trash() }
                    }
                }
            }
            if (entries.length() > 0)
                button("Empty trash") {
                    confirm("Permanently erase every item in trash?") {
                        change(VaultCommands.purgeTrash(null), confirmed = true) { trash() }
                    }
                }
            button("Apply configured trash retention") {
                confirm(
                    "Permanently purge entries older than the configured retention? Zero days disables automatic age-based purging."
                ) {
                    changeLocal("purge_expired") { trash() }
                }
            }
            button("Back to tools") { tools() }
        }
    }

    protected fun authenticator(id: Long) {
        task({ Vault.commandJson(VaultCommands.item(id)) }) { item ->
            val mode = VaultCommands.authenticatorMode(item)
            page("Authenticator")
            pageBack = { showDetail(id) }
            label("Current mode: " + (mode ?: "None"))
            if (mode == "totp")
                button("Show current verification code") {
                    task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) { result ->
                        codeResult(result, id)
                    }
                }
            if (mode == "hotp")
                button("Generate next HOTP code") {
                    confirm(
                        "Generate the next code and permanently advance its counter? Use one device at a time for this counter-based authenticator."
                    ) {
                        task({
                            Vault.commandJson(VaultCommands.authenticatorCode(id), confirmed = true)
                                .also {
                                    afterToolChange()
                                }
                        }) { result ->
                            codeResult(result, id)
                        }
                    }
                }
            val config = edit("Base32 secret or otpauth URI", secret = true)
            button("Save authenticator") {
                val supplied = config.text.toString().trim()
                config.text.clear()
                confirm("Replace this item's authenticator configuration?") {
                    change(VaultCommands.setAuthenticator(id, supplied)) { authenticator(id) }
                }
            }
            if (mode != null)
                button("Remove authenticator") {
                    confirm(
                        "Remove the authenticator from this item? Disable it at the website separately if required."
                    ) {
                        change(VaultCommands.removeAuthenticator(id)) { authenticator(id) }
                    }
                }
            button("Duo enrollment & push") { duo(id) }
            button("Back to item") { showDetail(id) }
        }
    }

    private fun codeResult(result: JSONObject, id: Long) {
        page("Authenticator code")
        pageBack = { authenticator(id) }
        label(result.getString("code"), 28f)
        label(
            if (result.opt("counter") is Number)
                "Consumed HOTP counter: ${result.getLong("counter")}"
            else "Valid for ${result.getInt("expires_in")} seconds"
        )
        button("Copy verification code") {
            if (result.opt("counter") is Number)
                SecretClipboard.copy(this, result.getString("code"), 30)
            else
                task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) { fresh ->
                    SecretClipboard.copy(this, fresh.getString("code"), fresh.getInt("expires_in"))
                }
        }
        button("Back to authenticator") { authenticator(id) }
    }

    private fun duo(id: Long) {
        page("Duo enrollment & push")
        pageBack = { authenticator(id) }
        label(
            "Use a fresh activation link for a separate device. Enrollment consumes the link. Existing push credentials are never replaced without confirmation."
        )
        val activation = edit("Duo activation link", secret = true)
        val mode = choice("Passcode mode", listOf("hotp", "totp"))
        val push = toggle("Enroll push credentials", true)
        val replace = toggle("Replace existing enrollment")
        button("Enroll Duo") {
            val link = activation.text.toString().trim()
            activation.text.clear()
            confirm("Consume this activation link and enroll this item?") {
                task({
                    val enrollment =
                        VaultCommands.duoEnroll(
                            id,
                            link,
                            mode.selectedItem.toString(),
                            push.isChecked,
                            replace.isChecked,
                        )
                    (Vault.command(enrollment) as String).also { afterToolChange() }
                }) {
                    label(it)
                }
            }
        }
        button("Review pending push requests") { duoRequests(id) }
        button("Remove local push credentials") {
            confirm(
                "Remove this item's local push credentials? Passcodes remain; remove the device in Duo separately."
            ) {
                change(VaultCommands.duoRemove(id)) { duo(id) }
            }
        }
        button("Back to authenticator") { authenticator(id) }
    }

    private fun duoRequests(id: Long) {
        task({ Vault.command(VaultCommands.duoRequests(id)) as JSONArray }) { requests ->
            page("Review Duo requests")
            pageBack = { duo(id) }
            if (requests.length() == 0) label("No pending requests")
            for (i in 0 until requests.length()) {
                val request = requests.getJSONObject(i)
                label(
                    "${request.getString("application")}\n${request.getString("username")}\n${request.getString("location")}\n${request.getString("summary")}\nExpires: ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(request.getLong("expires_at") * 1000))}"
                )
                val code = edit("Verified Push code from the login page", secret = true)
                val unsupported = request.opt("unsupported") as? String
                if (unsupported != null) label(unsupported)
                for (approve in listOf(true, false)) button(
                    if (approve) "Approve request" else "Deny request"
                ) {
                    check(!approve || unsupported == null) {
                        "This request type cannot be approved"
                    }
                    val supplied = code.text.toString()
                    code.text.clear()
                    confirm(
                        if (approve) "Approve this exact reviewed login request?"
                        else "Deny this exact reviewed login request?"
                    ) {
                        task({
                            Vault.command(
                                VaultCommands.duoRespond(
                                    id,
                                    request.getString("id"),
                                    request.getString("fingerprint"),
                                    approve,
                                    supplied,
                                )
                            ) as String
                        }) {
                            label(it)
                        }
                    }
                }
            }
            button("Refresh requests") { duoRequests(id) }
            button("Back to Duo") { duo(id) }
        }
    }

    protected fun generator(use: ((String) -> Unit)? = null, back: (() -> Unit)? = null) {
        task({ Vault.json("settings_get") }) { defaults ->
            page("Password generator")
            pageBack = back ?: { navigate("Tools") }
            val phrase = toggle("Generate a passphrase")
            val length = edit("Password length", defaults.getInt("generator_length").toString())
            val words = edit("Passphrase words", defaults.getInt("passphrase_words").toString())
            val separator = edit("Word separator", "-")
            val upper = toggle("Uppercase", true)
            val lower = toggle("Lowercase", true)
            val digits = toggle("Digits", true)
            val symbols = toggle("Symbols", true)
            val symbolSet = edit("Allowed symbols", "!@#$%^&*-_=+")
            val ambiguous = toggle("Exclude ambiguous characters")
            val result = edit("Generated value", secret = true)
            val assessment = label("")
            button("Generate") {
                val usePhrase = phrase.isChecked
                val options =
                    arrayOf(
                        "passphrase" to usePhrase,
                        "length" to
                            (if (usePhrase) defaults.getInt("generator_length")
                            else length.text.toString().toInt()),
                        "words" to
                            (if (usePhrase) words.text.toString().toInt()
                            else defaults.getInt("passphrase_words")),
                        "separator" to separator.text.toString(),
                        "uppercase" to upper.isChecked,
                        "lowercase" to lower.isChecked,
                        "digits" to digits.isChecked,
                        "symbols_enabled" to symbols.isChecked,
                        "symbols" to symbolSet.text.toString(),
                        "exclude_ambiguous" to ambiguous.isChecked,
                    )
                task({ Vault.json("generate", *options) }) {
                    result.setText(it.getString("password"))
                    assessment.text = it.getString("assessment")
                }
            }
            button("Assess value locally") {
                val supplied = result.text.toString()
                task({ Vault.json("passcheck", "password" to supplied) }) {
                    assessment.text = it.getString("assessment")
                }
            }
            button("Copy generated value") {
                check(result.text.isNotEmpty())
                SecretClipboard.copy(this, result.text.toString())
            }
            if (use != null) button("Use generated value") { use(result.text.toString()) }
            button("Back") { (back ?: { navigate("Tools") })() }
        }
    }

    private fun advancedSearch() {
        page("Advanced search")
        val query = edit("Search text")
        val name = edit("Name contains")
        val user = edit("Username contains")
        val url = edit("Website contains")
        val notes = edit("Notes contain", secret = true)
        val kind = choice("Item type", listOf("all") + kinds)
        val otp = choice("Authenticator", listOf("any", "present", "missing"))
        val weak = toggle("Weak passwords only")
        val days = edit("Password age in days (optional)")
        val sort = choice("Sort by", listOf("id", "name", "created", "modified", "password-age"))
        val descending = toggle("Descending")
        button("Search items") {
            fun text(field: EditText) = field.text.toString().takeIf(String::isNotEmpty)
            val filter =
                VaultCommands.search(
                    query = text(query),
                    name = text(name),
                    username = text(user),
                    url = text(url),
                    notes = text(notes),
                    kind = kind.selectedItem.toString().takeUnless { it == "all" },
                    hasTotp =
                        when (otp.selectedItemPosition) {
                            1 -> true
                            2 -> false
                            else -> null
                        },
                    weak = weak.isChecked,
                    staleDays = days.text.toString().takeIf(String::isNotBlank)?.toLong(),
                    sort = sort.selectedItem.toString(),
                    descending = descending.isChecked,
                )
            task({ Vault.commandJson(filter).getJSONArray("items") }) { entries ->
                page("Search results")
                label("${entries.length()} matching items")
                for (i in 0 until entries.length()) {
                    val entry = entries.getJSONObject(i)
                    button(entry.getString("name")) { showDetail(entry.getLong("id")) }
                }
                button("Search again") { advancedSearch() }
                button("Back to tools") { tools() }
            }
        }
        button("Back to tools") { tools() }
    }

    private fun auditForm() {
        page("Vault health")
        val days = edit("Stale password age (days)", "180")
        val otp = toggle("Flag logins without authenticators", true)
        val breaches = toggle("Check breaches online (sends password hash prefixes)")
        button("Run health check") {
            val options =
                VaultCommands.audit(
                    staleDays = days.text.toString().toLong(),
                    requireTotp = otp.isChecked,
                    checkBreaches = breaches.isChecked,
                )
            task({ Vault.commandJson(options) }) { report ->
                page("Vault health results")
                label(
                    "${report.getInt("healthy")} healthy of ${report.getInt("total")} · score ${report.getInt("score")}"
                )
                for (key in
                    listOf(
                        "weak",
                        "reused",
                        "duplicates",
                        "stale",
                        "missing_totp",
                        "breached",
                        "unchecked",
                    )) {
                    label(key.replace('_', ' '), 20f)
                    fun findings(value: Any?) {
                        when (value) {
                            is JSONArray -> for (i in 0 until value.length()) findings(value.opt(i))
                            is JSONObject ->
                                if (value.has("id"))
                                    button(value.getString("name")) {
                                        showDetail(value.getLong("id"))
                                    }
                        }
                    }
                    findings(report.opt(key))
                }
                (report.opt("breach_error") as? String)?.let {
                    label("Breach check incomplete: $it")
                }
                button("Back to tools") { tools() }
            }
        }
        button("Back to tools") { tools() }
    }

    protected fun preferences(back: (() -> Unit)? = null) {
        task({ Vault.json("settings_get") }) { current ->
            page("Mobile settings")
            pageBack = back ?: { navigate("Settings") }
            label("Tap a preference to see what it means and change its value.")
            for ((title, keys) in
                listOf(
                    "Locking & clipboard" to setOf("unlock_seconds", "clipboard_seconds"),
                    "History & recovery" to setOf("history_limit", "trash_days"),
                    "Password generation" to setOf("generator_length", "passphrase_words"),
                )) {
                section(title)
                for (field in MobilePreferences.fields.filter { it.key in keys }) actionRow(
                    field.title,
                    MobilePreferences.summary(field.key, current.getLong(field.key)),
                ) {
                    editPreference(field, current, back)
                }
            }
            label(
                "Preferences save as you change them. Autofill sessions are limited to five minutes on the same site.",
                13f,
            )
            button("Reset mobile preferences") {
                confirm(
                    "Restore the default locking, clipboard, generator, history and trash preferences?"
                ) {
                    task({ Vault.json("settings_save", "settings" to JSONObject()) }) { saved ->
                        updatePreferenceCache(saved)
                        preferences(back)
                    }
                }
            }
        }
    }

    private fun updatePreferenceCache(saved: JSONObject) {
        settings
            .edit()
            .putLong("unlock_seconds", saved.getLong("unlock_seconds"))
            .putInt("clipboard_seconds", saved.getInt("clipboard_seconds"))
            .apply()
        Vault.touch()
    }

    private fun editPreference(field: MobilePreference, current: JSONObject, back: (() -> Unit)?) {
        val content =
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                val pad = MobileUi.dp(this@ManagementActivity, 20)
                setPadding(pad, pad, pad, 0)
            }
        content.addView(
            MobileUi.text(this, field.help, 14f, muted = true).apply {
                layoutParams = MobileUi.margins(this@ManagementActivity, 16)
            }
        )
        val input =
            MobileUi.field(
                    this,
                    content,
                    "Value (${field.unit})",
                    current.getLong(field.key).toString(),
                    false,
                )
                .apply {
                    inputType = android.text.InputType.TYPE_CLASS_NUMBER
                    setSingleLine(true)
                }
        val preview =
            MobileUi.text(
                this,
                MobilePreferences.summary(field.key, current.getLong(field.key)),
                14f,
                bold = true,
            )
        content.addView(preview)
        input.addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(
                    s: CharSequence?,
                    start: Int,
                    count: Int,
                    after: Int,
                ) {}

                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    preview.text =
                        s?.toString()
                            ?.toLongOrNull()
                            ?.takeIf { it in field.range }
                            ?.let { MobilePreferences.summary(field.key, it) }
                            ?: "Allowed: ${field.range.first}–${field.range.last} ${field.unit}"
                }

                override fun afterTextChanged(s: android.text.Editable?) {}
            }
        )
        if (field.key == "unlock_seconds") {
            val presets = LinearLayout(this)
            for ((title, value) in listOf("1 min" to 60, "5 min" to 300, "15 min" to 900)) presets
                .addView(
                    MobileUi.button(this, title) { input.setText(value.toString()) }
                        .apply {
                            textSize = 12f
                            setPadding(0, 0, 0, 0)
                            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                        }
                )
            content.addView(presets)
        }
        val dialog =
            AlertDialog.Builder(this)
                .setTitle(field.title)
                .setView(ScrollView(this).apply { addView(content) })
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", null)
                .create()
        track(dialog)
        dialog.setOnShowListener {
            input.requestFocus()
            input.selectAll()
            dialog.window?.setSoftInputMode(
                android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE
            )
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val value = input.text.toString().toLongOrNull()
                if (value == null || value !in field.range) {
                    input.error = "Enter ${field.range.first}–${field.range.last} ${field.unit}"
                    input.requestFocus()
                } else {
                    val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                    save.isEnabled = false
                    val body = JSONObject(current.toString()).put(field.key, value)
                    task({ runCatching { Vault.json("settings_save", "settings" to body) } }) {
                        result ->
                        result.fold(
                            { saved ->
                                updatePreferenceCache(saved)
                                dialog.dismiss()
                                preferences()
                            },
                            { error ->
                                save.isEnabled = true
                                input.error = error.message ?: "Could not save"
                            },
                        )
                    }
                }
            }
        }
        dialog.show()
    }

    private fun syncControls() {
        task({ Vault.json("sync_status") }) { state ->
            page("Sync controls")
            label(
                "Configured: ${state.getBoolean("configured")}\nEnabled: ${state.getBoolean("enabled")}\nLocal changes: ${state.getBoolean("local_changed")}"
            )
            button("Check server for changes") {
                task({ Vault.json("sync_check", *syncArgs()) }) { result ->
                    val remote = result.optJSONObject("remote")
                    val binding = result.optJSONObject("binding")
                    label(
                        if (remote == null) "No cloud copy found. Local vault preserved."
                        else if (remote.optString("version") != binding?.optString("version"))
                            "Cloud changes are available."
                        else "Cloud copy matches the last synchronization checkpoint."
                    )
                }
            }
            button(
                if (state.getBoolean("enabled")) "Disable sync for this vault"
                else "Enable sync for this vault"
            ) {
                task({
                    Vault.json(
                        "sync_enabled",
                        *syncArgs(),
                        "enabled" to !state.getBoolean("enabled"),
                    )
                }) {
                    syncControls()
                }
            }
            button("Synchronize now") {
                task({ Vault.request("sync", *syncArgs()) }) { syncControls() }
            }
            button("Back to tools") { tools() }
        }
    }

    private fun destination(name: String, action: (Uri) -> Unit) {
        documentAction = action
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                type = "application/octet-stream"
                addCategory(Intent.CATEGORY_OPENABLE)
                putExtra(Intent.EXTRA_TITLE, name)
            },
            CREATE_DOCUMENT,
        )
    }

    private fun source(action: (Uri) -> Unit) {
        documentAction = action
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            },
            OPEN_DOCUMENT,
        )
    }

    private fun read(uri: Uri): ByteArray =
        contentResolver.openInputStream(uri)?.use { it.readBounded(MAX_TRANSFER) }
            ?: error("Could not open selected file")

    /** Reads [uri], passes it base64url-encoded to [use], and wipes the raw bytes. */
    private fun <T> withEncodedFile(uri: Uri, use: (String) -> T): T {
        val bytes = read(uri)
        try {
            return use(DeviceKeys.encode(bytes))
        } finally {
            bytes.fill(0)
        }
    }

    /** Runs a native operation that returns file `data` and writes it to [uri]. */
    private fun writeResult(uri: Uri, op: String, vararg args: Pair<String, Any?>) =
        write(uri, DeviceKeys.decode(Vault.json(op, *args).getString("data")))

    private fun write(uri: Uri, bytes: ByteArray) {
        check(bytes.size <= MAX_TRANSFER) { "File exceeds the 16 MiB mobile transfer limit" }
        try {
            contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
                ?: error("Could not write selected file")
        } finally {
            bytes.fill(0)
        }
    }

    protected fun files() {
        page("Files & backups")
        label(
            "Mobile transfers support files up to 16 MiB. Encrypted vault snapshots and complete backup containers preserve recovery data. JSON/CSV exports contain plaintext secrets; CSV omits rich metadata and cannot contain passkeys."
        )
        button("Export encrypted vault snapshot") {
            destination("vault.enc") { uri ->
                unlock({
                    task({ writeResult(uri, "snapshot") }) { showHome() }
                })
            }
        }
        button("Create complete encrypted backup") {
            destination("vault.pmbackup") { uri -> unlock({ backupForm(uri) }) }
        }
        button("Restore complete encrypted backup") { restoreBackup() }
        button("Import CSV or JSON") { source { uri -> unlock({ importForm(uri) }) } }
        for (format in listOf("json", "csv")) button("Export plaintext ${format.uppercase()}") {
            confirm(
                "Export plaintext secrets to a file outside the app? Anyone who can read that file can read its passwords. CSV also omits non-CSV metadata."
            ) {
                destination("vault.$format") { uri ->
                    unlock({
                        task({
                            writeResult(
                                uri,
                                "export_items",
                                "format" to format,
                                "confirmed" to true,
                            )
                        }) {
                            showHome()
                        }
                    })
                }
            }
        }
        button("Back to tools") { tools() }
    }

    private fun backupForm(uri: Uri) {
        page("Protect backup")
        pageBack = { files() }
        label(
            "Choose a dedicated backup password, or an existing external key file. Keep it separately; it is required for restore."
        )
        val password = edit("Backup password (at least 14 characters)", secret = true)
        val confirmation = edit("Confirm backup password", secret = true)
        button("Create password-protected backup") {
            check(password.text.toString() == confirmation.text.toString()) {
                "Passwords do not match"
            }
            val supplied = password.text.toString()
            password.text.clear()
            confirmation.text.clear()
            task({ writeResult(uri, "backup_create", "password" to supplied) }) { showHome() }
        }
        button("Use existing backup key file") {
            pickFile { key ->
                // The file picker locks the vault; unlock again before creating the backup.
                val encoded = DeviceKeys.encode(key)
                key.fill(0)
                unlock({
                    task({ writeResult(uri, "backup_create", "key_file" to encoded) }) {
                        showHome()
                    }
                })
            }
        }
        button("Cancel") { showHome() }
    }

    protected fun restoreBackup() {
        source { uri ->
            page("Restore backup")
            pageBack = { showHome() }
            label(
                "Restores into a separate vault with a new identity. Existing vaults are preserved."
            )
            val password = edit("Backup password", secret = true)
            fun restore(key: ByteArray? = null) {
                val supplied = password.text.toString()
                password.text.clear()
                val encoded = key?.let(DeviceKeys::encode)
                key?.fill(0)
                task({
                    withEncodedFile(uri) { data ->
                        Vault.json(
                            "restore_backup",
                            "data" to data,
                            "password" to supplied,
                            "key_file" to encoded,
                        )
                    }
                }) {
                    selectedVault = it.getString("vault")
                    showHome()
                }
            }
            button("Restore with password") { restore() }
            button("Restore with key file") { pickFile { restore(it) } }
            button("Cancel") { showHome() }
        }
    }

    private fun importForm(uri: Uri) {
        page("Import items")
        pageBack = { files() }
        val policy = choice("Duplicate policy", listOf("skip", "replace", "keep-both"))
        button("Preview import") {
            val selected = policy.selectedItem.toString()
            task({
                withEncodedFile(uri) { data ->
                    Vault.json(
                        "import_items",
                        "data" to data,
                        "preview" to true,
                        "conflicts" to selected,
                    )
                }
            }) { preview ->
                page("Import preview")
                pageBack = { importForm(uri) }
                val report = preview.getJSONObject("report")
                label("Duplicate policy: $selected")
                for ((key, title) in
                    listOf(
                        "total" to "Source items",
                        "added" to "Will add",
                        "replaced" to "Will replace",
                        "skipped" to "Will skip",
                        "renamed" to "Will rename",
                        "unsupported" to "Unsupported items",
                    )) label("$title: ${report.getInt(key)}")
                val losses = report.optJSONArray("losses") ?: JSONArray()
                for (i in 0 until losses.length()) label(losses.getString(i))
                button("Apply reviewed import") {
                    task({
                        withEncodedFile(uri) { data ->
                            Vault.request(
                                "import_items",
                                "data" to data,
                                "preview" to false,
                                "conflicts" to selected,
                                "review_token" to preview.getString("review_token"),
                            )
                        }
                        afterToolChange()
                    }) {
                        showItems(it)
                    }
                }
                button("Cancel") { showItems() }
            }
        }
        button("Cancel") { showItems() }
    }

    protected fun createKeyVault() {
        page("External-key vault")
        pageBack = { showHome() }
        label(
            "First save a new key file, then select that saved file to create the vault. Cancelling the save does not create a vault."
        )
        button("Generate and save a new key file") {
            destination("vault.key") { uri ->
                task({ writeResult(uri, "new_key_file") }) { createKeyVault() }
            }
        }
        button("Create vault using saved key file") {
            pickFile { bytes ->
                task({
                    try {
                        Vault.json("create_key", "key_file" to DeviceKeys.encode(bytes))
                    } finally {
                        bytes.fill(0)
                    }
                }) {
                    selectedVault = it.getString("vault")
                    showItems("Created external-key vault")
                }
            }
        }
        button("Back") { showHome() }
    }

    private fun credentials() {
        page("Vault credentials")
        label(
            "Credential changes and vault deletion require an original password/key-file unlock. Create a backup first. Rekeying also preserves a local encrypted recovery snapshot; biometric unlock must be set up again afterward."
        )
        button("Change master password") { unlockOriginal { rekeyForm() } }
        button("Change to an external key file") {
            unlockOriginal {
                page("Choose replacement key")
                label(
                    "Use a saved key file. Generate one from the home screen's External-key vault tools if needed."
                )
                button("Choose replacement key file") {
                    pickFile { bytes ->
                        val encoded = DeviceKeys.encode(bytes)
                        bytes.fill(0)
                        // Reauthenticate after returning from the key picker.
                        unlockOriginal { performRekey("key_file", encoded) }
                    }
                }
                button("Cancel") { showHome() }
            }
        }
        button("Delete this vault from this phone") {
            unlockOriginal {
                confirm(
                    "Permanently delete the selected local vault? This does not delete cloud or exported copies. Make sure you have a tested backup."
                ) {
                    val name = selectedVault
                    task({
                        check(Vault.primaryUnlock) { "Original password/key unlock required" }
                        Vault.request("delete_vault", "confirmed" to true)
                    }) {
                        DeviceKeys.disable(this, name)
                        selectedVault = ""
                        Vault.lock()
                        showHome()
                    }
                }
            }
        }
        button("Back to tools") { tools() }
    }

    private fun rekeyForm() {
        page("Change master password")
        pageBack = { credentials() }
        val password = edit("New master password", secret = true)
        val confirmation = edit("Confirm new password", secret = true)
        button("Change password") {
            check(password.text.toString() == confirmation.text.toString()) {
                "Passwords do not match"
            }
            val supplied = password.text.toString()
            password.text.clear()
            confirmation.text.clear()
            confirm(
                "Re-encrypt this vault with the new password and disable its biometric enrollment?"
            ) {
                performRekey("password", supplied)
            }
        }
        button("Cancel") { showHome() }
    }

    private fun performRekey(key: String, value: String) {
        check(Vault.primaryUnlock) { "Unlock with the original password or key file first" }
        DeviceKeys.disable(this, selectedVault)
        task({ Vault.request("rekey", key to value) }) {
            Vault.lock()
            showHome()
        }
    }

    override fun onDestroy() {
        documentAction = null
        super.onDestroy()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CREATE_DOCUMENT || requestCode == OPEN_DOCUMENT) {
            val action = documentAction
            documentAction = null
            if (resultCode == RESULT_OK && data?.data != null)
                guarded { action?.invoke(requireNotNull(data.data)) }
            else showHome()
        }
    }

    private companion object {
        const val CREATE_DOCUMENT = 30
        const val OPEN_DOCUMENT = 31
        /** Matches the Rust mobile transfer limit. */
        const val MAX_TRANSFER = 16 * 1024 * 1024
    }
}
