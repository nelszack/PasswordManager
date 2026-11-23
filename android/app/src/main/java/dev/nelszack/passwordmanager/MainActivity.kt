package dev.nelszack.passwordmanager

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import org.json.JSONArray
import org.json.JSONObject

private const val ROW_PAGE_SIZE = 50
/** Set by the autofill sheet: the site to add a login for. */
internal const val EXTRA_ADD_LOGIN_ORIGIN = "dev.nelszack.passwordmanager.ADD_LOGIN_ORIGIN"
/** From an empty card or identity picker: open a new item of that type after unlocking. */
internal const val EXTRA_ADD_ITEM_KIND = "dev.nelszack.passwordmanager.ADD_ITEM_KIND"
/** Matches the vault's per-attachment limit. */
private const val MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024

open class MainActivity : ManagementActivity() {
    override fun showItems(message: String) {
        items(message = message)
    }

    override fun showDetail(id: Long) {
        detail(id)
    }

    // Returns to the vault list when unlocked, or the start screen when locked.
    // Only the Lock button locks (see lockNow).
    override fun showHome() {
        navigate("Vault")
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        takeAddRequest(intent)
        if (!openShortcut()) home()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeAddRequest(intent)
        if (openShortcut()) return
        if (pendingAddOrigin != null || pendingAddKind != null || pendingShortcut != null) home()
    }

    /** Launcher shortcut: "search" opens the vault with search focused after unlock. */
    private var pendingShortcut: String? = null

    /** The generator needs no unlock, so its shortcut opens it at once. */
    private fun openShortcut(): Boolean {
        if (pendingShortcut != "generate") return false
        pendingShortcut = null
        generator(back = { showHome() })
        return true
    }

    private var pendingAddKind: String? = null

    /** A site autofill couldn't fill: offer to add a login for it after unlocking. */
    private var pendingAddOrigin: String? = null

    private fun takeAddRequest(intent: Intent?) {
        when (intent?.action) {
            "dev.nelszack.passwordmanager.SHORTCUT_SEARCH" -> pendingShortcut = "search"
            "dev.nelszack.passwordmanager.SHORTCUT_GENERATE" -> pendingShortcut = "generate"
        }
        intent?.getStringExtra(EXTRA_ADD_ITEM_KIND)?.let { kind ->
            intent.removeExtra(EXTRA_ADD_ITEM_KIND)
            if (kind in setOf("payment-card", "identity")) pendingAddKind = kind
        }
        val origin = intent?.getStringExtra(EXTRA_ADD_LOGIN_ORIGIN) ?: return
        intent.removeExtra(EXTRA_ADD_LOGIN_ORIGIN)
        if (origin.length <= 2048 && origin.none(Char::isISOControl)) pendingAddOrigin = origin
    }

    override fun onSessionLocked() {
        home()
    }

    override fun onUnlockCancelled() {
        home()
    }

    // The unlock form starts the fingerprint prompt by itself. Opening the app goes
    // straight to it once; after Lock or Cancel you choose when to unlock.
    private var openedFresh = true

    override fun automaticBiometrics() = true

    override fun lockNow() {
        openedFresh = false
        super.lockNow()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) openedFresh = true
    }

    override fun onResume() {
        super.onResume()
        // A browser-scoped grant does not unlock the vault-management screen.
        if (Vault.autofillSession.hasGrant()) Vault.lock()
        if (layout.childCount == 0) home()
        // Returning from Android's autofill settings shows whether it is now on.
        else settingsShown?.let(::settingsHome)
    }

    private var searchText = ""
    private var selectedKind: String? = null
    /** Favorites combine with the type, tag, and text filters. */
    private var favoritesOnly = false
    private var selectedTag: String? = null
    private var queryVersion = 0L
    private var pendingSearch: Runnable? = null
    private var codeTick: Runnable? = null
    /** Where the list was scrolled when an item was opened. */
    private var listScroll: Int? = null
    /** Selection mode in the vault list, and the chosen item IDs (like the desktop app). */
    private var selecting = false
    private val selectedIds = linkedSetOf<Long>()

    /** Settings is showing (with its unlock state), so a return from system settings refreshes it. */
    private var settingsShown: Boolean? = null

    override fun onPageChanged(title: String) {
        super.onPageChanged(title)
        settingsShown = null
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
        selectedTag = null
        favoritesOnly = false
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
        if (selectedVault.isNotBlank())
            label(VaultNames.label(this, selectedVault, listOf(selectedVault)), 18f)
        label("Your passwords, one-time codes and important details, together on this device.")
        pendingAddOrigin?.let {
            notice("Unlock to add a login for ${Uri.parse(it).host ?: it}.")
        }
        pendingAddKind?.let {
            notice(if (it == "payment-card") "Unlock to add a payment card." else "Unlock to add an identity.")
        }
        if (selectedVault.isNotBlank()) {
            val fingerprint = DeviceKeys.enabled(this, selectedVault)
            notice(
                if (fingerprint) "Fingerprint unlock is set up on this device."
                else "Unlock with your master password or key file."
            )
            primary(if (fingerprint) "Unlock with fingerprint" else "Unlock vault") {
                allowAutomaticBiometrics()
                unlock({ syncAndOpen() })
            }
            // Opening the app goes straight to the fingerprint prompt.
            if (fingerprint && openedFresh) {
                openedFresh = false
                allowAutomaticBiometrics()
                val start = sessionCallback<Unit> { unlock({ syncAndOpen() }) }
                layout.post { start(Unit) }
            }
        } else primary("Set up your vault") { setupVault() }
        actionRow(
            "Add or restore a vault",
            "Import an existing vault, connect to sync or start fresh",
            "add",
        ) {
            setupVault()
        }
        section("Ready when you need them")
        actionRow(
            "Password generator",
            "Create a strong password without opening your vault",
            "generate",
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
        actionRow("Create a new vault", "Start fresh with a master password", "add") { create() }
        actionRow(
            "I already have a vault",
            "Download it from your sync server",
            "sync",
        ) {
            connection()
        }
        section("More options")
        actionRow("Open a vault on this device", "Choose a vault already stored here", "vault") {
            unlock({ syncAndOpen() })
        }
        actionRow("Import a vault file", "Open an existing .enc vault file", "open") {
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
        actionRow("Restore an encrypted backup", "Recover a complete vault from a backup", "restore") {
            restoreBackup()
        }
        actionRow(
            "Use a key file instead of a password",
            "Create or open a vault protected by a key file",
            "key",
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
            "generate",
        ) {
            generator(back = { lockedTools() })
        }
        actionRow("Add or restore a vault", "Import, download or restore encrypted data", "add") {
            setupVault()
        }
    }

    private fun settingsHome(unlocked: Boolean) {
        page("Settings")
        settingsShown = unlocked
        rootNavigation("Settings", unlocked)
        label("Make the app work the way you do.")
        section("Security")
        actionRow(
            "Biometric unlock",
            if (selectedVault.isNotBlank() && DeviceKeys.enabled(this, selectedVault))
                "Enabled on this device"
            else "Set up fingerprint unlock for your vault",
            "biometric",
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
        // Says whether setup worked, not just where to do it.
        val autofillOn =
            runCatching {
                    getSystemService(android.view.autofill.AutofillManager::class.java)
                        ?.hasEnabledAutofillServices() == true
                }
                .getOrDefault(false)
        actionRow(
            if (autofillOn) "Password autofill: on" else "Turn on password autofill",
            if (autofillOn) "Password Manager is your autofill service. Tap to change it."
            else "Not set up yet. Choose Password Manager as your Android autofill service.",
            "autofill",
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
            "sync",
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
        section("Help")
        actionRow("Help & tips", "Autofill, sync, backups, and what to do if you're stuck") {
            help(unlocked)
        }
        label("Password Manager · ${packageManager.getPackageInfo(packageName,0).versionName}", 12f)
    }

    private fun help(unlocked: Boolean) {
        page("Help & tips")
        pageBack = { settingsHome(unlocked) }
        for ((title, body) in
            listOf(
                "Copy without opening an item" to
                    "Long-press an item in your vault list to copy its username, password or one-time code.",
                "Autofill in apps and browsers" to
                    "In Settings, choose “Turn on password autofill” and pick Password Manager (the row then reads “Password autofill: on”). When you sign in, tap the suggestion above the keyboard. If nothing matches, add the website or app to the login.",
                "Switching apps" to
                    "The vault stays unlocked briefly after you leave the app (Mobile settings → Lock after leaving the app), so you can paste a code and come back. Turning off the screen always locks it.",
                "Clipboard" to
                    "Copied passwords and codes are cleared after the time in Mobile settings, and when the vault locks.",
                "Sync with other devices" to
                    "Sync stores only encrypted vaults on your own server. You need its HTTPS address and a device credential from whoever runs it.",
                "Backups" to
                    "Tools → Files & backups creates an encrypted backup that restores everything. Keep its password safe.",
                "Forgot the master password?" to
                    "There is no reset. A key-file vault opens with its key file, and an encrypted backup opens with its own backup password.",
            )) {
            section(title)
            label(body, 15f)
        }
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
                confirm("Disable fingerprint unlock for this vault on this device?", "Disable") {
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
                    .getOrElse { "Using the vault on this device; sync will retry. ${friendlyError(it.message)}" }
        }) { message ->
            items(message = message)
            offerRecoveryCleanup()
        }
    }

    /** Copy actions for a list row, so a value can be copied without opening the item. */
    private fun quickCopy(entry: JSONObject) {
        val id = entry.getLong("id")
        val name = entry.getString("name")
        val username = entry.opt("username") as? String ?: ""
        val profile = runCatching { Vault.itemProfiles()[entry.getString("kind")] }.getOrNull()
        val owner = profile?.optString("owner")?.substringBefore(" (")?.ifBlank { null } ?: "Username"
        val secret = profile?.optString("secret")?.substringBefore(" (")?.ifBlank { null } ?: "Password"
        val choices = mutableListOf<Pair<String, () -> Unit>>()
        if (username.isNotBlank())
            choices += "Copy ${owner.replaceFirstChar { it.lowercase() }}" to
                { SecretClipboard.copy(this, username, what = "$owner copied") }
        choices +=
            "Copy ${secret.replaceFirstChar { it.lowercase() }}" to
                {
                    task({ Vault.commandJson(VaultCommands.item(id)).optString("password") }) {
                        if (it.isNotEmpty()) SecretClipboard.copy(this, it, what = "$secret copied")
                        else notice("$name has nothing to copy.")
                    }
                }
        if (VaultCommands.authenticatorMode(entry) == "totp" || entry.optBoolean("has_totp"))
            choices +=
                "Copy one-time code" to
                    {
                        task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) {
                            SecretClipboard.copy(
                                this,
                                it.getString("code"),
                                it.getInt("expires_in"),
                                what = "Code copied",
                            )
                        }
                    }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setTitle(name)
            .setItems(choices.map { it.first }.toTypedArray()) { _, which ->
                guarded { choices[which].second() }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun create() {
        page("Create vault")
        pageBack = { setupVault() }
        val vaultName = edit("Vault name", "Personal vault")
        label("Choose a master password you can remember. Use at least 14 characters, such as several unrelated words.")
        val password = edit("Master password (at least 14 characters)", secret = true)
        val strength = label("", 13f)
        strength.accessibilityLiveRegion = android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE
        val confirmation = edit("Confirm master password", secret = true)
        var suggested = ""
        lateinit var suggestion: android.widget.TextView
        button("Suggest a passphrase") {
            task({ Vault.json("generate", "passphrase" to true, "words" to 6, "separator" to "-") }) {
                val phrase = it.getString("password")
                suggested = phrase
                password.setText(phrase)
                confirmation.setText(phrase)
                // One current suggestion, shown so it can be written down; a new one replaces it.
                suggestion.text = "Your new master password:\n$phrase\nWrite it down before you continue."
                suggestion.visibility = android.view.View.VISIBLE
            }
        }
        suggestion = label("", 16f).apply { visibility = android.view.View.GONE }
        password.addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun afterTextChanged(s: android.text.Editable?) {
                    // Editing the password retires the suggestion, so only the value in use shows.
                    if (suggested.isNotEmpty() && s?.toString() != suggested) {
                        suggested = ""
                        suggestion.text = ""
                        suggestion.visibility = android.view.View.GONE
                    }
                }
            }
        )
        var problem: String? = "Enter a master password."
        var check: Runnable? = null
        val checkLater = sessionCallback<String> { typed ->
            if (typed != password.text.toString()) return@sessionCallback
            task({ Vault.json("passcheck", "password" to typed) }) { result ->
                if (typed != password.text.toString()) return@task
                problem = result.optString("master_problem").takeIf { it.isNotBlank() && it != "null" }
                strength.text =
                    "Strength: ${result.optString("rating")}" +
                        (problem?.let { " · ${it.replaceFirstChar(Char::uppercase)}" } ?: " · Good to use")
            }
        }
        password.addTextChangedListener(
            object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}

                override fun afterTextChanged(s: android.text.Editable?) {
                    val typed = s?.toString().orEmpty()
                    check?.let(ui::removeCallbacks)
                    problem = if (typed.length < 14) "use at least 14 characters" else problem
                    strength.text = if (typed.isEmpty()) "" else if (typed.length < 14)
                        "${14 - typed.length} more characters needed" else "Checking strength…"
                    if (typed.length >= 14) {
                        check = Runnable { checkLater(typed) }
                        ui.postDelayed(check!!, 300)
                    }
                }
            }
        )
        notice(
            "There is no password reset. If you forget this password, the vault cannot be opened. Write it down somewhere safe, and create an encrypted backup once you add items (Tools → Files & backups)."
        )
        primary("Create vault") {
            VaultNames.problem(vaultName.text.toString())?.let {
                vaultName.error = it
                vaultName.requestFocus()
                return@primary
            }
            if (password.text.length < 14 || problem != null) {
                // Checked before submitting, so nothing typed is lost.
                password.error = (problem ?: "Use at least 14 characters").replaceFirstChar(Char::uppercase)
                password.requestFocus()
                return@primary
            }
            if (password.text.toString() != confirmation.text.toString()) {
                confirmation.error = "The passwords don't match yet."
                confirmation.requestFocus()
                return@primary
            }
            val supplied = password.text.toString()
            val label = vaultName.text.toString()
            task({ Vault.json("create", "password" to supplied) }) {
                password.text.clear()
                confirmation.text.clear()
                selectedVault = it.getString("vault")
                VaultNames.save(this, selectedVault, label)
                items(message = "Vault “${label.trim()}” is ready. Add your first item below.")
            }
        }
        button("Back") { home() }
    }

    private fun items(query: String = searchText, message: String = "") {
        pendingAddKind?.let { kind ->
            pendingAddKind = null
            typedEditor(null, JSONObject().put("kind", kind))
            return
        }
        pendingAddOrigin?.let { origin ->
            pendingAddOrigin = null
            val host = runCatching { Uri.parse(origin).host }.getOrNull()?.removePrefix("www.")
            typedEditor(
                null,
                JSONObject()
                    .put("kind", "login")
                    .put("name", host ?: origin)
                    .put("urls", JSONArray().put(origin)),
            )
            return
        }
        searchText = query
        page("Your vault")
        rootNavigation("Vault")
        if (message.isNotBlank()) notice(message)
        val search = edit("Search your vault", searchText)
        // Search stays pinned at the top while the list scrolls.
        pinHeader(MobileUi.layoutOf(search) ?: search)
        if (pendingShortcut == "search") {
            pendingShortcut = null
            search.post {
                search.requestFocus()
                getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                    .showSoftInput(search, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
            }
        }
        search.setSingleLine(true)
        search.imeOptions = android.view.inputmethod.EditorInfo.IME_ACTION_SEARCH
        val filters =
            android.widget.HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false }
        val chips = android.widget.LinearLayout(this)
        filters.addView(chips)
        layout.addView(filters, MobileUi.margins(this, 12))
        // Filled with a tag picker once the vault's tags are known.
        val tagFilter =
            android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
            }
        layout.addView(tagFilter)
        val options =
            listOf(
                "All" to null,
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
        // Selection mode: tap rows to choose them, then tag or trash them together.
        val chosen = MobileUi.text(this, "", 14f, muted = true)
        lateinit var tagChosen: android.widget.Button
        lateinit var trashChosen: android.widget.Button
        fun updateChosen() {
            val n = selectedIds.size
            chosen.text = if (n == 0) "Tap items to select them" else "$n selected"
            tagChosen.isEnabled = n > 0
            trashChosen.isEnabled = n > 0
            trashChosen.text = if (n == 0) "Move to trash" else "Move $n to trash"
        }
        if (selecting) {
            val bar = android.widget.LinearLayout(this).apply { gravity = android.view.Gravity.CENTER_VERTICAL }
            bar.addView(chosen, android.widget.LinearLayout.LayoutParams(0, -2, 1f))
            bar.addView(
                MobileUi.textButton(this, "Done") {
                    selecting = false
                    selectedIds.clear()
                    items()
                }
            )
            pinHeader(bar)
            tagChosen =
                MobileUi.button(this, "Add tag…", false) {
                    val ids = selectedIds.toList()
                    val input = android.widget.EditText(this).apply { hint = "Tag (separate several with commas)" }
                    track(
                        com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                            .setTitle("Add a tag to ${ids.size} items")
                            .setView(input)
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Add tag") { _, _ ->
                                val tags = VaultCommands.parseTags(input.text.toString())
                                if (tags.isEmpty()) return@setPositiveButton
                                task({
                                    ids.forEach { Vault.command(VaultCommands.addTags(it, tags)) }
                                    syncAfterChange()
                                }) {
                                    selecting = false
                                    selectedIds.clear()
                                    items(message = "Tagged ${ids.size} items “${tags.joinToString(", ")}”.")
                                }
                            }
                            .show()
                    )
                }
            trashChosen =
                MobileUi.button(this, "Move to trash", false, danger = true) {
                    val ids = selectedIds.toList()
                    confirm(
                        "Move ${ids.size} items to encrypted trash? You can restore them from Deleted items.",
                        "Move to trash",
                    ) {
                        task({
                            ids.forEach { Vault.command(VaultCommands.delete(it)) }
                            syncAfterChange()
                        }) {
                            selecting = false
                            selectedIds.clear()
                            items(message = "Moved ${ids.size} items to the trash. Restore them from Deleted items.")
                        }
                    }
                }
            pinActions(tagChosen, trashChosen)
            updateChosen()
        } else {
            pinHeader(
                MobileUi.textButton(this, "Select items") {
                    selecting = true
                    selectedIds.clear()
                    items()
                }.apply { contentDescription = "Select several items to tag or move to trash" }
            )
            floatingAction("Add item") { typedEditor(null) }
        }
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
                val itemId = entry.getLong("id")
                rows.addView(
                    MobileUi.row(
                            this,
                            name,
                            summary,
                            // The initial comes from the name itself, not the favorite star.
                            if (type == "login") MobileUi.initial(entry.getString("name"), type)
                            else MobileUi.kindBadge(type),
                        ) {
                            listScroll = scrollPosition()
                            guarded { detail(itemId) }
                        }
                        .apply {
                            val spoken = name + if (summary.isBlank()) "" else ", $summary"
                            if (selecting) {
                                val plain = background
                                fun show(picked: Boolean) {
                                    background =
                                        if (picked) MobileUi.shape(this@MainActivity, R.color.pm_accent_soft) else plain
                                    isActivated = picked
                                    contentDescription = (if (picked) "Selected, " else "Not selected, ") + spoken
                                }
                                show(itemId in selectedIds)
                                setOnClickListener {
                                    if (!selectedIds.remove(itemId)) selectedIds.add(itemId)
                                    show(itemId in selectedIds)
                                    updateChosen()
                                }
                                return@apply
                            }
                            // Long-press copies without opening the item.
                            setOnLongClickListener {
                                guarded { quickCopy(entry) }
                                true
                            }
                            contentDescription = spoken
                            // TalkBack offers the copy actions directly.
                            androidx.core.view.ViewCompat.addAccessibilityAction(this, "Copy…") { _, _ ->
                                guarded { quickCopy(entry) }
                                true
                            }
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
                // Load the next page as the list scrolls near it; the button stays for TalkBack.
                more.viewTreeObserver.addOnScrollChangedListener(
                    object : android.view.ViewTreeObserver.OnScrollChangedListener {
                        override fun onScrollChanged() {
                            if (more.parent !== rows) {
                                if (more.viewTreeObserver.isAlive)
                                    more.viewTreeObserver.removeOnScrollChangedListener(this)
                                return
                            }
                            val visible = android.graphics.Rect()
                            if (more.getGlobalVisibleRect(visible)) {
                                more.viewTreeObserver.removeOnScrollChangedListener(this)
                                more.post { if (more.parent === rows) more.performClick() }
                            }
                        }
                    }
                )
            }
        }
        lateinit var load: () -> Unit
        fun drawTags(entries: JSONArray) {
            val tags = sortedSetOf(String.CASE_INSENSITIVE_ORDER)
            for (i in 0 until entries.length()) tags.addAll(VaultCommands.tags(entries.getJSONObject(i)))
            selectedTag?.let(tags::add)
            tagFilter.removeAllViews()
            if (tags.isEmpty()) return
            val choices = listOf("All tags") + tags
            tagFilter.addView(
                android.widget.Spinner(this).apply {
                    contentDescription = "Filter by tag"
                    adapter =
                        android.widget.ArrayAdapter(
                            this@MainActivity,
                            android.R.layout.simple_spinner_dropdown_item,
                            choices,
                        )
                    minimumHeight = MobileUi.dp(this@MainActivity, 48)
                    background = MobileUi.shape(this@MainActivity, outline = true, radius = 12)
                    setSelection(choices.indexOfFirst { it == selectedTag }.coerceAtLeast(0))
                    onItemSelectedListener =
                        object : android.widget.AdapterView.OnItemSelectedListener {
                            override fun onItemSelected(
                                parent: android.widget.AdapterView<*>?,
                                view: android.view.View?,
                                position: Int,
                                id: Long,
                            ) {
                                val tag = if (position == 0) null else choices[position]
                                if (tag == selectedTag) return
                                selectedTag = tag
                                load()
                            }

                            override fun onNothingSelected(
                                parent: android.widget.AdapterView<*>?
                            ) {}
                        }
                },
                MobileUi.margins(this, 12),
            )
        }
        load = {
            val needle = search.text.toString()
            searchText = needle
            val kind = selectedKind
            val tag = selectedTag
            val favorites = favoritesOnly
            val filtered = needle.isNotBlank() || kind != null || tag != null || favorites
            val version = ++queryVersion
            task({
                Vault.commandJson(
                    VaultCommands.search(
                        query = needle.ifBlank { null },
                        kind = kind,
                        sort = "name",
                        tags = listOfNotNull(tag),
                        favorite = if (favorites) true else null,
                    )
                )
            }) { result ->
                if (version != queryVersion || rows.parent !== layout) return@task
                val entries = result.getJSONArray("items")
                rows.removeAllViews()
                if (!filtered) drawTags(entries)
                if (!filtered) {
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
                        if (filtered) " found" else " in your vault"
                if (entries.length() == 0) {
                    rows.addView(
                        MobileUi.text(
                            this,
                            if (filtered) "No matching items"
                            else "Your vault is ready",
                            21f,
                            bold = true,
                        )
                    )
                    rows.addView(
                        MobileUi.text(
                            this,
                            if (filtered) "Nothing matches the search and filters you chose."
                            else "Add your first login, note or other important detail.",
                            15f,
                            muted = true,
                        )
                    )
                    if (filtered)
                        rows.addView(
                            MobileUi.button(this, "Clear all filters") {
                                searchText = ""
                                selectedKind = null
                                selectedTag = null
                                favoritesOnly = false
                                items()
                            }
                        )
                }
                addRows(entries, 0, version)
                // Returning from an item keeps your place in the list.
                listScroll?.let(::restoreScroll)
                listScroll = null
            }
        }
        fun drawChips() {
            chips.removeAllViews()
            // Favorites is its own toggle; the type chips choose one type.
            chips.addView(
                MobileUi.chip(this, "★ Favorites", favoritesOnly) {
                        favoritesOnly = !favoritesOnly
                        load()
                    }
                    .apply {
                        contentDescription = "Favorites only"
                        layoutParams =
                            android.widget.LinearLayout.LayoutParams(-2, -2).apply {
                                marginEnd = MobileUi.dp(this@MainActivity, 8)
                            }
                    }
            )
            for ((title, kind) in options) chips.addView(
                MobileUi.chip(this, title, selectedKind == kind) {
                        selectedKind = kind
                        pendingSearch?.let(ui::removeCallbacks)
                        pendingSearch = null
                        // Update only the type chips; typing keeps its focus and selection.
                        for (i in 0 until chips.childCount) {
                            val chip = chips.getChildAt(i) as? com.google.android.material.chip.Chip
                            if (chip?.tag != null) chip.isChecked = chip.tag == kind.orEmpty()
                        }
                        load()
                    }
                    .apply {
                        tag = kind.orEmpty()
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
        // A filtered first load cannot list every tag, so read them separately.
        if (searchText.isNotBlank() || selectedKind != null || selectedTag != null || favoritesOnly)
            task({ Vault.commandJson(VaultCommands.search(sort = "name")).getJSONArray("items") }) {
                if (tagFilter.parent === layout) drawTags(it)
            }
        load()
    }

    /** Plain-language names for sync conflict fields, matching the desktop app. */
    private fun conflictFieldTitle(field: String) =
        when (field) {
            "password" -> "Password (or the item's main secret)"
            "notes" -> "Notes"
            "metadata" -> "Type, websites and custom fields"
            "history" -> "Password history"
            "authenticator" -> "Authenticator"
            "duo" -> "Duo enrollment"
            "lifecycle" -> "Active or deleted"
            "created" -> "Created"
            "item" -> "Item presence"
            "name" -> "Name"
            "username" -> "Username"
            "url" -> "Website"
            else -> field
        }

    private fun conflicts() {
        task({ Vault.json("cloud_conflicts", *syncArgs()) }) { review ->
            page("Review sync conflicts")
            label(
                "Choose which version to keep for every differing field. Protected values remain hidden. Both original vaults are backed up before applying."
            )
            val choices = mutableListOf<() -> JSONObject>()
            val groups = mutableListOf<Pair<com.google.android.material.button.MaterialButtonToggleGroup, IntArray>>()
            val entries = review.getJSONArray("items")
            if (entries.length() > 0) {
                val all = android.widget.LinearLayout(this).apply { orientation = android.widget.LinearLayout.HORIZONTAL }
                layout.addView(all, MobileUi.margins(this))
                fun chooseAll(side: Int) = groups.forEach { (group, ids) -> group.check(ids[side]) }
                all.addView(
                    MobileUi.textButton(this, "Keep all from this device") { chooseAll(0) },
                    android.widget.LinearLayout.LayoutParams(0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
                )
                all.addView(
                    MobileUi.textButton(this, "Keep all from cloud") { chooseAll(1) },
                    android.widget.LinearLayout.LayoutParams(0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
                )
            }
            for (i in 0 until entries.length()) {
                val item = entries.getJSONObject(i)
                // The same plain-language names the desktop app uses.
                section(item.optString("local").substringBefore(" · ").ifBlank { "Item ${item.getLong("id")}" })
                label("This device: ${item.optString("local")}\nCloud: ${item.optString("remote")}", 14f)
                val fields = item.getJSONArray("fields")
                if (fields.length() == 0) label("Separate items: both are kept, nothing to choose.")
                for (j in 0 until fields.length()) {
                    val field = fields.getJSONObject(j)
                    val title = conflictFieldTitle(field.getString("field"))
                    label("$title\nThis device: ${field.getString("local")}\nCloud: ${field.getString("remote")}")
                    val group =
                        com.google.android.material.button.MaterialButtonToggleGroup(this).apply {
                            isSingleSelection = true
                            contentDescription = "Version of $title to keep"
                        }
                    val ids =
                        listOf("Keep this device", "Keep cloud")
                            .map { text ->
                                com.google.android.material.button.MaterialButton(
                                        this,
                                        null,
                                        com.google.android.material.R.attr.materialButtonOutlinedStyle,
                                    )
                                    .apply {
                                        id = android.view.View.generateViewId()
                                        this.text = text
                                        group.addView(
                                            this,
                                            android.widget.LinearLayout.LayoutParams(
                                                0,
                                                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                                                1f,
                                            ),
                                        )
                                    }
                                    .id
                            }
                            .toIntArray()
                    layout.addView(group, MobileUi.margins(this))
                    groups.add(group to ids)
                    choices.add {
                        check(group.checkedButtonId != android.view.View.NO_ID) {
                            "Choose a version for every field ($title)"
                        }
                        JSONObject()
                            .put("id", item.getLong("id"))
                            .put("field", field.getString("field"))
                            .put("side", if (group.checkedButtonId == ids[0]) "local" else "remote")
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
            actionRow(name, "${MobileUi.byteSize(attachment.getLong("size"))} · Save a copy", "file") {
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
                confirm("Remove the attachment \"$name\"? This cannot be undone.", "Remove") {
                    task({
                        runCatching {
                            Vault.command(
                                VaultCommands.removeAttachment(id, name),
                                entry.getLong("revision"),
                            )
                            afterToolChange()
                        }
                    }) { result ->
                        result.fold({ detail(id) }, { showFailure(it) })
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
                        result.fold({ detail(id) }, { showFailure(it) })
                    }
                })
            }
        }
    }

    private fun detail(id: Long) {
        task({ Vault.commandJson(VaultCommands.item(id)) to Vault.itemProfiles() }) {
            (entry, profiles) ->
            page("Item details")
            val profile = profiles[entry.getString("kind")]
            // "Identity number (optional)" -> "Identity number"
            fun shortLabel(key: String, fallback: String) =
                profile?.optString(key)?.substringBefore(" (")?.ifBlank { null } ?: fallback
            val ownerLabel = shortLabel("owner", "Username")
            val secretLabel = shortLabel("secret", "Password")
            val secretWord =
                if (secretLabel.length > 1 && secretLabel[1].isUpperCase()) secretLabel
                else secretLabel.replaceFirstChar { it.lowercase() }
            pageBack = { items() }
            label(entry.getString("name"), 28f)
            label(MobileUi.kindLabel(entry.getString("kind")).uppercase(), 12f)
            val tags = VaultCommands.tags(entry)
            if (tags.isNotEmpty()) label("Tags: ${tags.joinToString(", ")}", 14f)
            if (!entry.optBoolean("is_passkey")) {
                val starred = entry.optBoolean("favorite")
                barAction(
                    if (starred) R.drawable.pm_icon_star else R.drawable.pm_icon_star_border,
                    if (starred) "Remove from favorites" else "Add to favorites",
                ) {
                    task({
                        runCatching {
                            Vault.command(
                                VaultCommands.setFavorite(id, !starred),
                                entry.getLong("revision"),
                            )
                        }
                    }) { result ->
                        result.fold({ detail(id) }, { showFailure(it) })
                    }
                }
            }
            val user = entry.opt("username") as? String ?: ""
            if (user.isNotBlank()) {
                section(ownerLabel)
                label(user, 20f)
                button("Copy ${ownerLabel.replaceFirstChar { it.lowercase() }}") {
                    SecretClipboard.copy(this, user, what = "$ownerLabel copied")
                }
            }
            if (entry.optBoolean("has_secret")) {
                section(secretLabel)
                val value = label("••••••••••••", 23f)
                var visible = false
                lateinit var reveal: android.widget.Button
                fun conceal() {
                    value.text = "••••••••••••"
                    visible = false
                    reveal.text = "Show $secretWord"
                }
                // Like the desktop app, a revealed secret hides itself after 15 seconds.
                val hideLater = sessionCallback<Unit>(acrossVisits = true) { if (visible) conceal() }
                val hideTask = Runnable { hideLater(Unit) }
                val actions =
                    pairedActions(
                        "Show $secretWord",
                        "Copy $secretWord",
                        {
                            if (visible) {
                                ui.removeCallbacks(hideTask)
                                conceal()
                            } else
                                task({
                                    Vault.commandJson(VaultCommands.item(id)).getString("password")
                                }) {
                                    value.text = it
                                    visible = true
                                    reveal.text = "Hide $secretWord"
                                    ui.removeCallbacks(hideTask)
                                    ui.postDelayed(hideTask, 15_000)
                                }
                        },
                        {
                            task({
                                Vault.commandJson(VaultCommands.item(id)).getString("password")
                            }) {
                                SecretClipboard.copy(this, it, what = "$secretLabel copied")
                            }
                        },
                    )
                reveal = actions.first
            }
            if (VaultCommands.authenticatorMode(entry) == "totp") {
                section("One-time code")
                val codeView = label("••• •••", 28f)
                val lifetime = label("Loading a fresh code…", 13f)
                codeView.importantForAccessibility =
                    android.view.View.IMPORTANT_FOR_ACCESSIBILITY_YES
                // Time-based codes show at once and refresh by themselves while visible.
                lateinit var showCode: () -> Unit
                showCode = {
                    task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) { code ->
                        val expires =
                            android.os.SystemClock.elapsedRealtime() +
                                code.getInt("expires_in") * 1000L
                        codeView.text = code.getString("code").chunked(3).joinToString(" ")
                        codeTick?.let(ui::removeCallbacks)
                        val tick =
                            sessionCallback<Unit>(acrossVisits = true) {
                                val seconds =
                                    ((expires - android.os.SystemClock.elapsedRealtime() + 999) /
                                            1000)
                                        .coerceAtLeast(0)
                                lifetime.text = "Changes in $seconds seconds"
                                if (seconds == 0L) showCode()
                                else codeTick?.let { ui.postDelayed(it, 1000) }
                            }
                        codeTick = Runnable { tick(Unit) }
                        codeTick?.run()
                    }
                }
                showCode()
                button("Copy one-time code") {
                    task({ Vault.commandJson(VaultCommands.authenticatorCode(id)) }) {
                        SecretClipboard.copy(
                            this,
                            it.getString("code"),
                            it.getInt("expires_in"),
                            what = "Code copied",
                        )
                    }
                }
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
                    // Revealed values hide again after 15 seconds, like the password.
                    val hideField = sessionCallback<Unit>(acrossVisits = true) {
                        if (shown) {
                            shown = false
                            value.text = "••••••••"
                            reveal.text = "Show $name"
                        }
                    }
                    val hideFieldTask = Runnable { hideField(Unit) }
                    val actions =
                        pairedActions(
                            "Show $name",
                            "Copy $name",
                            {
                                shown = !shown
                                value.text = if (shown) field.optString("value") else "••••••••"
                                reveal.text = if (shown) "Hide $name" else "Show $name"
                                ui.removeCallbacks(hideFieldTask)
                                if (shown) ui.postDelayed(hideFieldTask, 15_000)
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
                lateinit var toggleNotes: android.widget.Button
                val hideNotes = sessionCallback<Unit>(acrossVisits = true) {
                    if (visible) {
                        visible = false
                        value.text = "Notes hidden"
                        toggleNotes.text = "Show notes"
                    }
                }
                val hideNotesTask = Runnable { hideNotes(Unit) }
                toggleNotes = pairedActions(
                    "Show notes",
                    "Copy notes",
                    {
                        visible = !visible
                        value.text = if (visible) notes else "Notes hidden"
                        toggleNotes.text = if (visible) "Hide notes" else "Show notes"
                        ui.removeCallbacks(hideNotesTask)
                        if (visible) ui.postDelayed(hideNotesTask, 60_000)
                    },
                    { SecretClipboard.copy(this, notes) },
                ).first
            }
            section("Manage item")
            if (!entry.optBoolean("is_passkey")) primary("Edit item") { typedEditor(entry) }
            actionRow("Password history", "View and restore previous passwords") { history(id) }
            actionRow("Authenticator & Duo", "Manage codes, enrollment and push requests") {
                authenticator(id)
            }
            MobileUi.button(this, "Move to trash", danger = true) {
                    guarded {
                        confirm(
                            "Move this item to encrypted trash? You can restore it from Deleted items.",
                            "Move to trash",
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
                .also(layout::addView)
        }
    }

    private fun connection() {
        page("Encrypted cloud sync")
        pageBack = { navigate("Settings") }
        label("Connect to your sync server to keep encrypted vaults available across devices.")
        label(
            "You need the server's HTTPS address and a device credential. Whoever runs your sync server creates one credential per device (see “Cloud sync” in the user guide). The server only ever stores encrypted vaults.",
            13f,
        )
        val server = edit("HTTPS server URL", settings.getString("server", "").orEmpty())
        val token = edit("Device credential (leave blank to keep the saved one)", secret = true)
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
                if (vaults.length() == 0) notice("No vaults on this server yet. Turn on sync for a vault on another device first.")
                for (i in 0 until vaults.length()) {
                    val vault = vaults.getJSONObject(i)
                    val id = vault.getString("id")
                    // Names stay on each device, so the server only knows a short ID and size.
                    val title = "Cloud vault ${id.take(8)}"
                    fun download(copy: Boolean) =
                        task({
                            Vault.json("cloud_download", *syncArgs(), "id" to id, "copy" to copy)
                        }) {
                            selectedVault = it.getString("vault")
                            home()
                        }
                    actionRow(title, "${MobileUi.byteSize(vault.optLong("size"))} · Tap to download", "sync") {
                        download(false)
                    }
                    layout.addView(
                        MobileUi.textButton(this, "Download a comparison copy instead") { download(true) }
                            .apply { contentDescription = "Download a comparison copy of $title" },
                        MobileUi.margins(this),
                    )
                }
            }
        }
        label(
            "Conflicts preserve both encrypted copies. Unlock the vault and use Review sync conflicts to reconcile changes."
        )
        button("Back") { navigate("Settings") }
    }
}
