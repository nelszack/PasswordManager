package dev.nelszack.passwordmanager

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import org.json.JSONArray
import org.json.JSONObject

private const val ROW_PAGE_SIZE = 50
/** Matches the vault's per-attachment limit. */
private const val MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
/** Filter-chip value selecting favorites rather than an item type. */
private const val FAVORITES = "\u0000favorites"

open class MainActivity : ManagementActivity() {
    override fun showItems(message: String) {
        items(message = message)
    }

    override fun showDetail(id: Long) {
        detail(id)
    }

    override fun showHome() {
        Vault.lock()
        home()
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        home()
    }

    override fun onSessionLocked() {
        home()
    }

    override fun onResume() {
        super.onResume()
        // A browser-scoped grant does not unlock the vault-management screen.
        if (Vault.autofillSession.hasGrant()) Vault.lock()
        if (layout.childCount == 0) home()
    }

    private var searchText = ""
    private var selectedKind: String? = null
    private var queryVersion = 0L
    private var pendingSearch: Runnable? = null
    private var codeTick: Runnable? = null

    override fun onPageChanged(title: String) {
        super.onPageChanged(title)
        pendingSearch?.let(ui::removeCallbacks)
        pendingSearch = null
        codeTick?.let(ui::removeCallbacks)
        codeTick = null
        queryVersion++
    }

    override fun clearSecrets() {
        pendingSearch?.let(ui::removeCallbacks)
        pendingSearch = null
        codeTick?.let(ui::removeCallbacks)
        codeTick = null
        queryVersion++
        searchText = ""
        selectedKind = null
        super.clearSecrets()
    }

    override fun navigate(tab: String) {
        task({ Vault.json("status").getBoolean("unlocked") }) { unlocked ->
            when (tab) {
                "Vault" -> if (unlocked) items() else home()
                "Tools" -> if (unlocked) tools() else lockedTools()
                else -> settingsHome(unlocked)
            }
        }
    }

    private fun home() {
        page("Password Manager")
        rootNavigation("Vault", false)
        label("YOUR PRIVATE VAULT", 12f)
        label(if (selectedVault.isBlank()) "Bring your vault\nwith you." else "Welcome back.", 32f)
        label("Your passwords, verification codes and important details, together on this device.")
        if (selectedVault.isNotBlank()) {
            notice(
                if (DeviceKeys.enabled(this, selectedVault))
                    "Fingerprint unlock is set up on this device."
                else "Unlock with your master password or key file."
            )
            primary("Unlock vault") { unlock({ syncAndOpen() }) }
        } else primary("Set up your vault") { setupVault() }
        actionRow(
            "Add or restore a vault",
            "Import an existing vault, connect to sync or start fresh",
            "+",
        ) {
            setupVault()
        }
        section("Ready when you need them")
        actionRow(
            "Password generator",
            "Create a strong password without opening your vault",
            "G",
        ) {
            generator(back = { home() })
        }
        actionRow(
            "Autofill & security",
            "Set up autofill, biometrics and app preferences",
            "settings",
        ) {
            settingsHome(false)
        }
    }

    private fun setupVault() {
        page("Add your vault")
        pageBack = { home() }
        label("Choose how you want to get started.")
        actionRow(
            "Cloud sync settings / download vault",
            "Connect to your server and download an encrypted vault",
            "S",
        ) {
            connection()
        }
        actionRow("Open a local vault", "Choose a vault already stored on this device", "V") {
            unlock({ syncAndOpen() })
        }
        actionRow("Import encrypted vault", "Open an existing .enc vault from a file", "I") {
            pickFile(16 * 1024 * 1024) { bytes ->
                task({
                    try {
                        Vault.json("import_vault", "data" to DeviceKeys.encode(bytes))
                    } finally {
                        bytes.fill(0)
                    }
                }) {
                    selectedVault = it.getString("vault")
                    home()
                }
            }
        }
        actionRow("Create vault", "Start a new vault with a master password", "+") { create() }
        actionRow("Restore encrypted backup", "Recover a complete vault from a backup", "R") {
            restoreBackup()
        }
        actionRow(
            "External-key vault tools",
            "Generate or use a key file instead of a password",
            "K",
        ) {
            createKeyVault()
        }
    }

    private fun lockedTools() {
        page("Tools & recovery")
        rootNavigation("Tools", false)
        notice("Unlock your vault to use search, health checks and recovery tools.")
        primary("Unlock vault") { unlock({ tools() }) }
        actionRow(
            "Password generator",
            "Passwords and passphrases, generated on this device",
            "G",
        ) {
            generator(back = { lockedTools() })
        }
        actionRow("Add or restore a vault", "Import, download or restore encrypted data", "+") {
            setupVault()
        }
    }

    private fun settingsHome(unlocked: Boolean) {
        page("Settings")
        rootNavigation("Settings", unlocked)
        label("Make the app work the way you do.")
        section("Security")
        actionRow(
            "Biometric unlock",
            if (selectedVault.isNotBlank() && DeviceKeys.enabled(this, selectedVault))
                "Enabled on this device"
            else "Set up fingerprint unlock for your vault",
            "B",
        ) {
            unlock({
                rootNavigation("Settings", true)
                biometricSettings()
            })
        }
        actionRow(
            "Mobile settings",
            "Auto-lock, clipboard, history and generation defaults",
            "settings",
        ) {
            preferences { settingsHome(unlocked) }
        }
        section("Autofill")
        actionRow(
            "Enable password autofill",
            "Choose Password Manager as your Android autofill service",
            "A",
        ) {
            startActivity(
                Intent(
                    "android.settings.REQUEST_SET_AUTOFILL_SERVICE",
                    Uri.parse("package:$packageName"),
                )
            )
        }
        if (android.os.Build.VERSION.SDK_INT >= 34)
            actionRow(
                "Enable password and passkey provider",
                "Manage your Android credential provider",
            ) {
                startActivity(
                    Intent(
                        "android.settings.CREDENTIAL_PROVIDER",
                        Uri.parse("package:$packageName"),
                    )
                )
            }
        section("Sync & storage")
        actionRow(
            "Cloud sync settings / download vault",
            "Server connection and encrypted cloud vaults",
            "S",
        ) {
            connection()
        }
        if (unlocked) {
            actionRow("Review sync conflicts", "Compare and resolve changes from other devices") {
                conflicts()
            }
            actionRow("Files & backups", "Encrypted recovery and portable data transfers") {
                files()
            }
        }
        label("Password Manager · ${packageManager.getPackageInfo(packageName,0).versionName}", 12f)
    }

    private fun biometricSettings() {
        page("Biometric unlock")
        pageBack = { navigate("Settings") }
        val enabled = DeviceKeys.enabled(this, selectedVault)
        notice(if (enabled) "Enabled on this device" else "Not set up for this vault")
        label(
            "Use your fingerprint to unlock this vault. Your original master password or key file remains your recovery method."
        )
        if (enabled)
            button("Disable biometric unlock") {
                confirm("Disable fingerprint unlock for this vault on this device?") {
                    DeviceKeys.disable(this, selectedVault)
                    biometricSettings()
                }
            }
        else if (!Vault.primaryUnlock)
            primary("Unlock with password or key file") { unlockOriginal { biometricSettings() } }
        else
            primary("Enable biometric unlock") {
                task({ Vault.json("biometric_material") }) { data ->
                    DeviceKeys.enable(
                        this,
                        data.getString("vault"),
                        DeviceKeys.decode(data.getString("material")),
                    ) {
                        biometricSettings()
                    }
                }
            }
    }

    private fun syncAndOpen() {
        rootNavigation("Vault", true)
        page("Opening vault")
        label(
            "Checking for encrypted changes. Your local vault will stay available if the server is unreachable."
        )
        task({
            if (settings.getString("server", "").isNullOrBlank()) ""
            else
                runCatching {
                        val result = Vault.json("sync", *syncArgs(), "if_enabled" to true)
                        if (result.optBoolean("disabled")) "" else "Synchronized"
                    }
                    .getOrElse { "Using local vault. Sync pending: ${it.message}" }
        }) { message ->
            items(message = message)
            offerRecoveryCleanup()
        }
    }

    private fun create() {
        page("Create vault")
        pageBack = { setupVault() }
        label("Choose a master password you can remember. Use at least 14 characters.")
        val password = edit("Master password (at least 14 characters)", secret = true)
        val confirmation = edit("Confirm password", secret = true)
        primary("Create") {
            check(password.text.toString() == confirmation.text.toString()) {
                "Passwords do not match"
            }
            val supplied = password.text.toString()
            password.text.clear()
            confirmation.text.clear()
            task({ Vault.json("create", "password" to supplied) }) {
                selectedVault = it.getString("vault")
                items()
            }
        }
        button("Back") { home() }
    }

    private fun items(query: String = searchText, message: String = "") {
        searchText = query
        page("Your vault")
        rootNavigation("Vault")
        if (message.isNotBlank()) notice(message)
        val search = edit("Search your vault", searchText)
        search.setSingleLine(true)
        search.imeOptions = android.view.inputmethod.EditorInfo.IME_ACTION_SEARCH
        val filters =
            android.widget.HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false }
        val chips = android.widget.LinearLayout(this)
        filters.addView(chips)
        layout.addView(filters, MobileUi.margins(this, 12))
        val options =
            listOf(
                "All" to null,
                "★ Favorites" to FAVORITES,
                "Logins" to "login",
                "Notes" to "secure-note",
                "Cards" to "payment-card",
                "Identity" to "identity",
                "Wi-Fi" to "wifi",
                "Licenses" to "software-license",
                "SSH keys" to "ssh-key",
                "API secrets" to "api-secret",
            )
        val count = label("Loading your items…", 13f)
        primary("Add item") { typedEditor(null) }
        // Filled once the full list loads, when any item has Duo Push enrolled.
        val duoShortcut =
            android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
            }
        layout.addView(duoShortcut)
        val rows =
            android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
            }
        layout.addView(rows)
        // Build rows a page at a time: large vaults would otherwise inflate
        // every result on the UI thread before the first one is visible.
        fun addRows(entries: JSONArray, from: Int, version: Long) {
            if (version != queryVersion || rows.parent !== layout) return
            val end = minOf(entries.length(), from + ROW_PAGE_SIZE)
            for (i in from until end) {
                val entry = entries.getJSONObject(i)
                val name =
                    (if (entry.optBoolean("favorite")) "★ " else "") + entry.getString("name")
                val type = entry.getString("kind")
                val user = entry.opt("username") as? String ?: ""
                val host =
                    if (user.isBlank()) {
                        val url = entry.optJSONArray("urls")?.optString(0).orEmpty()
                        runCatching { java.net.URI(url).host }.getOrNull().orEmpty()
                    } else ""
                val summary =
                    listOf(
                            user.ifBlank { host },
                            MobileUi.kindLabel(type),
                            VaultCommands.tags(entry).joinToString(", "),
                        )
                        .filter(String::isNotBlank)
                        .joinToString(" · ")
                rows.addView(
                    MobileUi.row(
                        this,
                        name,
                        summary,
                        if (type == "login") name.take(1).uppercase()
                        else MobileUi.kindBadge(type),
                    ) {
                        guarded { detail(entry.getLong("id")) }
                    }
                )
            }
            if (end < entries.length()) {
                val remaining = entries.length() - end
                lateinit var more: android.widget.Button
                more =
                    MobileUi.button(this, "Show ${minOf(ROW_PAGE_SIZE, remaining)} more of $remaining") {
                        rows.removeView(more)
                        addRows(entries, end, version)
                    }
                rows.addView(more)
            }
        }
        fun load() {
            val needle = search.text.toString()
            searchText = needle
            val kind = selectedKind
            val favorites = kind == FAVORITES
            val version = ++queryVersion
            task({
                Vault.commandJson(
                    VaultCommands.search(
                        query = needle.ifBlank { null },
                        kind = kind.takeUnless { favorites },
                        sort = "name",
                        favorite = if (favorites) true else null,
                    )
                )
            }) { result ->
                if (version != queryVersion || rows.parent !== layout) return@task
                val entries = result.getJSONArray("items")
                rows.removeAllViews()
                if (needle.isBlank() && kind == null) {
                    duoShortcut.removeAllViews()
                    val accounts = duoAccounts(entries)
                    if (accounts.isNotEmpty())
                        duoShortcut.addView(
                            MobileUi.row(
                                this,
                                "Duo Push requests",
                                if (accounts.size == 1) "Approve or deny a login for ${accounts[0].second}"
                                else "Approve or deny logins for ${accounts.size} accounts",
                                "key",
                            ) {
                                guarded { duoInbox(accounts, back = { items() }) }
                            }
                        )
                }
                count.text =
                    "${entries.length()} ${if(entries.length()==1) "item" else "items"}" +
                        if (needle.isNotBlank() || kind != null) " found" else " in your vault"
                if (entries.length() == 0) {
                    rows.addView(
                        MobileUi.text(
                            this,
                            if (needle.isNotBlank() || kind != null) "No matching items"
                            else "Your vault is ready",
                            21f,
                            bold = true,
                        )
                    )
                    rows.addView(
                        MobileUi.text(
                            this,
                            if (needle.isNotBlank() || kind != null)
                                "Try another search or choose All."
                            else "Add your first login, note or other important detail.",
                            15f,
                            muted = true,
                        )
                    )
                }
                addRows(entries, 0, version)
            }
        }
        fun drawChips() {
            chips.removeAllViews()
            for ((title, kind) in options) chips.addView(
                MobileUi.button(this, title) {
                        selectedKind = kind
                        pendingSearch?.let(ui::removeCallbacks)
                        pendingSearch = null
                        // Rebuild only the chips; typing keeps its focus and selection.
                        for (i in 0 until chips.childCount) {
                            val chip = chips.getChildAt(i) as android.widget.Button
                            val active = chip.tag == kind.orEmpty()
                            chip.isSelected = active
                            chip.background =
                                MobileUi.shape(
                                    this,
                                    if (active) R.color.pm_accent_soft else R.color.pm_surface,
                                    outline = !active,
                                    radius = 20,
                                )
                        }
                        load()
                    }
                    .apply {
                        tag = kind.orEmpty()
                        isSelected = selectedKind == kind
                        minHeight = MobileUi.dp(this@MainActivity, 44)
                        minimumHeight = minHeight
                        background =
                            MobileUi.shape(
                                this@MainActivity,
                                if (isSelected) R.color.pm_accent_soft else R.color.pm_surface,
                                outline = !isSelected,
                                radius = 20,
                            )
                        layoutParams =
                            android.widget.LinearLayout.LayoutParams(-2, -2).apply {
                                marginEnd = MobileUi.dp(this@MainActivity, 8)
                            }
                    }
            )
        }
        drawChips()
        search.addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(
                    s: CharSequence?,
                    start: Int,
                    count: Int,
                    after: Int,
                ) {}

                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    pendingSearch?.let(ui::removeCallbacks)
                    pendingSearch =
                        Runnable { if (rows.parent === layout) load() }
                            .also { ui.postDelayed(it, 220) }
                }

                override fun afterTextChanged(s: android.text.Editable?) {}
            }
        )
        search.setOnEditorActionListener { _, action, _ ->
            if (action == android.view.inputmethod.EditorInfo.IME_ACTION_SEARCH) {
                pendingSearch?.let(ui::removeCallbacks)
                load()
                getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                    .hideSoftInputFromWindow(search.windowToken, 0)
                true
            } else false
        }
        load()
    }

    private fun conflicts() {
        task({ Vault.json("cloud_conflicts", *syncArgs()) }) { review ->
            page("Review sync conflicts")
            label(
                "Choose which version to keep for every differing field. Protected values remain hidden. Both original vaults are backed up before applying."
            )
            val choices = mutableListOf<() -> JSONObject>()
            val entries = review.getJSONArray("items")
            for (i in 0 until entries.length()) {
                val item = entries.getJSONObject(i)
                label("${item.optString("local")} / ${item.optString("remote")}", 20f)
                val fields = item.getJSONArray("fields")
                if (fields.length() == 0) label("Separate items: both are kept, nothing to choose.")
                for (j in 0 until fields.length()) {
                    val field = fields.getJSONObject(j)
                    label(
                        "${field.getString("field")}\nLocal: ${field.getString("local")}\nCloud: ${field.getString("remote")}"
                    )
                    val selection =
                        android.widget.Spinner(this).apply {
                            adapter =
                                android.widget.ArrayAdapter(
                                    this@MainActivity,
                                    android.R.layout.simple_spinner_dropdown_item,
                                    listOf("Choose…", "Local", "Cloud"),
                                )
                        }
                    layout.addView(selection)
                    choices.add {
                        check(selection.selectedItemPosition > 0) {
                            "Choose a version for every field"
                        }
                        JSONObject()
                            .put("id", item.getLong("id"))
                            .put("field", field.getString("field"))
                            .put(
                                "side",
                                if (selection.selectedItemPosition == 1) "local" else "remote",
                            )
                    }
                }
            }
            button("Apply choices and sync") {
                val selected = JSONArray().apply { choices.forEach { put(it()) } }
                task({
                    Vault.json(
                        "cloud_resolve",
                        *syncArgs(),
                        "review_token" to review.getString("token"),
                        "choices" to selected,
                    )
                }) { resolved ->
                    // The resolution and recovery copies are saved even if the follow-up sync is
                    // pending.
                    items(message = resolved.getString("message"))
                }
            }
            button("Cancel") { items() }
        }
    }

    /** Lists attachments with save/remove actions and offers to add a file. */
    private fun attachments(entry: JSONObject) {
        val id = entry.getLong("id")
        val attachments = entry.optJSONArray("attachments") ?: JSONArray()
        val passkey = entry.optBoolean("is_passkey")
        if (attachments.length() == 0 && passkey) return
        section("Attachments")
        for (i in 0 until attachments.length()) {
            val attachment = attachments.getJSONObject(i)
            val name = attachment.getString("name")
            actionRow(name, "${MobileUi.byteSize(attachment.getLong("size"))} · Save a copy", "F") {
                destination(name) { uri ->
                    unlock({
                        task({
                            val bytes =
                                DeviceKeys.decode(
                                    Vault.json("attachment_data", "id" to id, "name" to name)
                                        .getString("data")
                                )
                            try {
                                contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
                                    ?: error("Could not write selected file")
                            } finally {
                                bytes.fill(0)
                            }
                        }) { detail(id) }
                    })
                }
            }
            button("Remove $name") {
                confirm("Remove the attachment \"$name\"? This cannot be undone.") {
                    task({
                        runCatching {
                            Vault.command(
                                VaultCommands.removeAttachment(id, name),
                                entry.getLong("revision"),
                            )
                            afterToolChange()
                        }
                    }) { result ->
                        result.fold({ detail(id) }, { notice(it.message ?: "Could not remove") })
                    }
                }
            }
        }
        if (attachments.length() == 0) label("No attachments", 14f)
        if (!passkey) button("Add attachment") {
            source { uri ->
                unlock({
                    task({
                        runCatching {
                            val name =
                                contentResolver
                                    .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                                    ?.use { if (it.moveToFirst()) it.getString(0) else null }
                                    ?: "attachment"
                            val bytes =
                                contentResolver.openInputStream(uri)?.use {
                                    it.readBounded(MAX_ATTACHMENT_BYTES)
                                } ?: error("Could not open selected file")
                            try {
                                Vault.json(
                                    "attachment_add",
                                    "id" to id,
                                    "name" to name,
                                    "data" to DeviceKeys.encode(bytes),
                                    "expected_revision" to entry.getLong("revision"),
                                )
                            } finally {
                                bytes.fill(0)
                            }
                            afterToolChange()
                        }
                    }) { result ->
                        result.fold({ detail(id) }, { notice(it.message ?: "Could not attach file") })
                    }
                })
            }
        }
    }

    private fun detail(id: Long) {
        task({ Vault.commandJson(VaultCommands.item(id)) }) { entry ->
            page("Item details")
            pageBack = { items() }
            label(entry.getString("name"), 28f)
            label(MobileUi.kindLabel(entry.getString("kind")).uppercase(), 12f)
            val tags = VaultCommands.tags(entry)
            if (tags.isNotEmpty()) label("Tags: ${tags.joinToString(", ")}", 14f)
            if (!entry.optBoolean("is_passkey")) {
                val starred = entry.optBoolean("favorite")
                button(if (starred) "★ Remove from favorites" else "☆ Add to favorites") {
                    task({
                        runCatching {
                            Vault.command(
                                VaultCommands.setFavorite(id, !starred),
                                entry.getLong("revision"),
                            )
                        }
                    }) { result ->
                        result.fold({ detail(id) }, { notice(it.message ?: "Could not update") })
                    }
                }
            }
            val user = entry.opt("username") as? String ?: ""
            if (user.isNotBlank()) {
                section("Username / owner")
                label(user, 20f)
                button("Copy username") { SecretClipboard.copy(this, user) }
            }
            if (entry.optBoolean("has_secret")) {
                section(if (entry.getString("kind") == "login") "Password" else "Primary secret")
                val value = label("••••••••••••", 23f)
                var visible = false
                lateinit var reveal: android.widget.Button
                val actions =
                    pairedActions(
                        "Show password",
                        "Copy password",
                        {
                            if (visible) {
                                value.text = "••••••••••••"
                                visible = false
                                reveal.text = "Show password"
                            } else
                                task({
                                    Vault.commandJson(VaultCommands.item(id)).getString("password")
                                }) {
                                    value.text = it
                                    visible = true
                                    reveal.text = "Hide password"
                                }
                        },
                        {
                            task({
                                Vault.commandJson(VaultCommands.item(id)).getString("password")
                            }) {
                                SecretClipboard.copy(this, it)
                            }
                        },
                    )
                reveal = actions.first
            }
            if (VaultCommands.authenticatorMode(entry) == "totp") {
                section("Verification code")
                val codeView = label("••• •••", 28f)
                val lifetime = label("Tap to show a fresh code.", 13f)
                pairedActions(
                    "Show authenticator code",
                    "Copy verification code",
                    {
                        task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) { code ->
                            val expires =
                                android.os.SystemClock.elapsedRealtime() +
                                    code.getInt("expires_in") * 1000L
                            codeView.text = code.getString("code")
                            codeTick?.let(ui::removeCallbacks)
                            val tick =
                                sessionCallback<Unit> {
                                    val seconds =
                                        ((expires - android.os.SystemClock.elapsedRealtime() +
                                                999) / 1000)
                                            .coerceAtLeast(0)
                                    lifetime.text =
                                        if (seconds > 0) "$seconds seconds remaining"
                                        else "Expired — tap to refresh."
                                    if (seconds == 0L) codeView.text = "••• •••"
                                    else codeTick?.let { ui.postDelayed(it, 1000) }
                                }
                            codeTick = Runnable { tick(Unit) }
                            codeTick?.run()
                        }
                    },
                    {
                        task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) {
                            SecretClipboard.copy(
                                this,
                                it.getString("code"),
                                it.getInt("expires_in"),
                            )
                        }
                    },
                )
            }
            if (entry.optBoolean("has_duo")) {
                section("Duo Push")
                primary("Check Duo Push requests") {
                    duoInbox(listOf(id to entry.getString("name")), back = { detail(id) })
                }
            }
            val urls = entry.optJSONArray("urls") ?: JSONArray()
            if (urls.length() > 0) {
                section("Websites & apps")
                for (i in 0 until urls.length()) {
                    val url = urls.getString(i)
                    val uri = runCatching { Uri.parse(url) }.getOrNull()
                    // Web addresses open in the browser; app identifiers stay as text.
                    if (uri?.scheme == "https" || uri?.scheme == "http") {
                        actionRow(uri.host ?: url, "Open in browser · $url", "open") {
                            runCatching { startActivity(Intent(Intent.ACTION_VIEW, uri)) }
                                .onFailure { notice("No app can open this address.") }
                        }
                    } else label(url)
                }
            }
            attachments(entry)
            val fields = entry.optJSONArray("fields") ?: JSONArray()
            if (fields.length() > 0) section("Custom fields")
            for (i in 0 until fields.length()) {
                val field = fields.getJSONObject(i)
                val name = field.getString("name")
                val hidden = field.optBoolean("secret")
                label(name, 13f)
                val value = label(if (hidden) "••••••••" else field.optString("value"), 18f)
                if (hidden) {
                    var shown = false
                    lateinit var reveal: android.widget.Button
                    val actions =
                        pairedActions(
                            "Show $name",
                            "Copy $name",
                            {
                                shown = !shown
                                value.text = if (shown) field.optString("value") else "••••••••"
                                reveal.text = if (shown) "Hide $name" else "Show $name"
                            },
                            { SecretClipboard.copy(this, field.optString("value")) },
                        )
                    reveal = actions.first
                } else button("Copy $name") { SecretClipboard.copy(this, field.optString("value")) }
            }
            val notes = entry.opt("notes") as? String ?: ""
            if (notes.isNotBlank()) {
                section("Notes")
                val value = label("Notes hidden")
                var visible = false
                pairedActions(
                    "Show / hide notes",
                    "Copy notes",
                    {
                        visible = !visible
                        value.text = if (visible) notes else "Notes hidden"
                    },
                    { SecretClipboard.copy(this, notes) },
                )
            }
            section("Manage item")
            if (!entry.optBoolean("is_passkey")) primary("Edit item") { typedEditor(entry) }
            actionRow("Password history", "View and restore previous passwords") { history(id) }
            actionRow("Authenticator & Duo", "Manage codes, enrollment and push requests") {
                authenticator(id)
            }
            button("Delete item") {
                confirm(
                    "Move this item to encrypted trash? You can restore it from Deleted items."
                ) {
                    task({
                        Vault.command(VaultCommands.delete(id))
                        syncAfterChange()
                    }) {
                        items(message = it)
                    }
                }
            }
        }
    }

    private fun connection() {
        page("Encrypted cloud sync")
        pageBack = { navigate("Settings") }
        label("Connect to your sync server to keep encrypted vaults available across devices.")
        val server = edit("HTTPS server URL", settings.getString("server", "").orEmpty())
        val token = edit("Per-device credential (leave blank to keep)", secret = true)
        label(
            "The credential field clears when you connect. If the connection fails, paste the credential again to retry. A blank field keeps a previously saved credential."
        )
        primary("Save connection") {
            val endpoint = server.text.toString().trim()
            val supplied = token.text.toString().trim()
            token.text.clear()
            check(Uri.parse(endpoint).scheme == "https") { "An HTTPS endpoint is required" }
            task({
                val credential = supplied.ifEmpty { DeviceKeys.token(this) }
                try {
                    Vault.request("cloud_list", "server" to endpoint, "token" to credential)
                } catch (error: Exception) {
                    throw IllegalStateException(
                        "${error.message}\n\nConnection was not saved. Paste the device credential again to retry, or leave it blank to use a previously saved credential.",
                        error,
                    )
                }
                DeviceKeys.saveToken(this, credential)
                settings.edit().putString("server", endpoint).commit()
            }) {
                connection()
            }
        }
        button("List cloud vaults") {
            task({ Vault.request("cloud_list", *syncArgs()) as JSONArray }) { vaults ->
                for (i in 0 until vaults.length()) {
                    val id = vaults.getJSONObject(i).getString("id")
                    for (copy in listOf(false, true)) button(
                        if (copy) "Download comparison copy of $id" else "Download $id"
                    ) {
                        task({
                            Vault.json("cloud_download", *syncArgs(), "id" to id, "copy" to copy)
                        }) {
                            selectedVault = it.getString("vault")
                            home()
                        }
                    }
                }
            }
        }
        label(
            "Conflicts preserve both encrypted copies. Unlock the vault and use Review sync conflicts to reconcile changes."
        )
        button("Back") { home() }
    }
}
