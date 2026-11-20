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
    // Screens with their own controllers; this activity hosts them and their shared widgets.
    private val duoScreens = DuoScreens(this)
    private val preferenceScreens = PreferenceScreens(this)
    private val fileScreens = FileScreens(this)
    private val credentialScreens = CredentialScreens(this)
    private var workCount = 0
    private val dialogs = mutableListOf<android.app.Dialog>()
    internal var pageBack: (() -> Unit)? = null
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

    internal open fun navigate(tab: String) {
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

    internal fun section(title: String) {
        label(title, 18f)
    }

    internal fun primary(title: String, action: () -> Unit) =
        MobileUi.button(this, title, primary = true) { guarded(action) }.also(layout::addView)

    internal fun actionRow(
        title: String,
        subtitle: String,
        badge: String = "",
        action: () -> Unit,
    ) = MobileUi.row(this, title, subtitle, badge) { guarded(action) }.also(layout::addView)

    internal fun pairedActions(
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

    internal fun notice(message: String) {
        label(message).apply {
            background = MobileUi.shape(this@ManagementActivity, R.color.pm_accent_soft)
            val p = MobileUi.dp(this@ManagementActivity, 14)
            setPadding(p, p, p, p)
        }
    }

    internal abstract fun showItems(message: String = "")

    internal abstract fun showDetail(id: Long)

    internal abstract fun showHome()

    internal open fun afterToolChange() = syncAfterChange()

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

    /** Spinner showing plain-language labels; the getter returns the matching command value. */
    internal fun labeledChoice(
        title: String,
        options: List<Pair<String, String>>,
        selected: String? = null,
    ): () -> String {
        val spinner =
            choice(
                title,
                options.map { it.second },
                options.firstOrNull { it.first == selected }?.second,
            )
        return { options[spinner.selectedItemPosition.coerceIn(0, options.lastIndex)].first }
    }

    internal fun toggle(title: String, checked: Boolean = false) =
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

    internal fun confirm(message: String, action: () -> Unit) {
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
    internal fun track(dialog: AlertDialog) {
        dialogs.add(dialog)
        dialog.setOnDismissListener { dialogs.remove(dialog) }
    }

    /** Runs a shared vault command that changes the vault, then syncs. */
    internal fun change(
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

    internal fun tools() {
        page("Tools & recovery")
        rootNavigation("Tools")
        label("Everything you need to manage and recover your vault.")
        section("Everyday tools")
        actionRow("Add item", "Logins, notes, cards, keys and more", "add") { typedEditor(null) }
        actionRow("Advanced search", "Filter by type, website or password health", "search") {
            advancedSearch()
        }
        actionRow("Password generator", "Strong passwords and memorable passphrases", "G") {
            generator()
        }
        section("Security")
        actionRow("Vault health", "Review weak, reused or outdated passwords", "health") {
            auditForm()
        }
        actionRow("Vault credentials", "Change your master password or key", "key") {
            credentialScreens.show()
        }
        section("Recovery & data")
        actionRow("Deleted items", "Restore items or review your trash", "restore") { trash() }
        actionRow("Files & backups", "Encrypted backups and import / export", "B") { files() }
        actionRow("Sync controls", "Connection status and synchronization", "sync") { syncControls() }
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

    internal fun authenticator(id: Long) {
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
            button("Duo enrollment & push") { duoScreens.enrollment(id) }
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

    protected fun duoInbox(
        accounts: List<Pair<Long, String>>,
        back: () -> Unit,
        message: String = "",
    ) = duoScreens.inbox(accounts, back, message)

    /** Duo-enrolled items, by name, from an item list response. */
    protected fun duoAccounts(entries: JSONArray) = DuoScreens.enrolledAccounts(entries)

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
        val kind =
            labeledChoice(
                "Item type",
                listOf("all" to "All types") + kinds.map { it to MobileUi.kindLabel(it) },
            )
        val otp =
            labeledChoice(
                "Authenticator",
                listOf(
                    "any" to "Any",
                    "present" to "Has verification codes",
                    "missing" to "No verification codes",
                ),
            )
        val weak = toggle("Weak passwords only")
        val days = edit("Password older than (days, optional)")
        days.inputType = android.text.InputType.TYPE_CLASS_NUMBER
        val sort =
            labeledChoice(
                "Sort by",
                listOf(
                    "name" to "Name",
                    "modified" to "Recently changed",
                    "created" to "Date added",
                    "password-age" to "Password age",
                    "id" to "Item number",
                ),
            )
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
                    kind = kind().takeUnless { it == "all" },
                    hasTotp =
                        when (otp()) {
                            "present" -> true
                            "missing" -> false
                            else -> null
                        },
                    weak = weak.isChecked,
                    staleDays = days.text.toString().trim().toLongOrNull(),
                    sort = sort(),
                    descending = descending.isChecked,
                )
            task({ Vault.commandJson(filter).getJSONArray("items") }) { entries ->
                page("Search results")
                label(
                    if (entries.length() == 0) "No items match. Loosen a filter and try again."
                    else "${entries.length()} matching ${if (entries.length() == 1) "item" else "items"}"
                )
                for (i in 0 until entries.length()) {
                    val entry = entries.getJSONObject(i)
                    val type = entry.optString("kind")
                    val summary =
                        listOf(entry.opt("username") as? String ?: "", MobileUi.kindLabel(type))
                            .filter(String::isNotBlank)
                            .joinToString(" · ")
                    val title = entry.getString("name")
                    actionRow(title, summary, MobileUi.initial(title, type)) {
                        showDetail(entry.getLong("id"))
                    }
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

    protected fun preferences(back: (() -> Unit)? = null) = preferenceScreens.show(back)

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

    internal fun destination(name: String, action: (Uri) -> Unit) {
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

    internal fun source(action: (Uri) -> Unit) {
        documentAction = action
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            },
            OPEN_DOCUMENT,
        )
    }

    protected fun files() = fileScreens.show()

    protected fun restoreBackup() = fileScreens.restore()

    protected fun createKeyVault() = fileScreens.keyVault()

    /** After a credential change, offers once to delete the old-credential recovery copy. */
    protected fun offerRecoveryCleanup() = credentialScreens.offerRecoveryCleanup()

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
    }
}
