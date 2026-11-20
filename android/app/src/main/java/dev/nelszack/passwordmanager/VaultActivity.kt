package dev.nelszack.passwordmanager

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.*
import androidx.core.view.ViewCompat
import org.json.JSONArray

abstract class VaultActivity : SecureActivity() {
    protected lateinit var layout: LinearLayout
    protected open val modernUi = false
    @Volatile private var screenRevision = 0L

    override fun uiRevision() = screenRevision

    protected open fun onPageChanged(title: String) {}

    private var picked: ((ByteArray) -> Unit)? = null
    private var pickedLimit = 1024 * 1024
    private var unlockContinuation: (() -> Unit)? = null
    private var offeredBiometrics = false
    private var originalUnlockOnly = false

    protected open fun automaticBiometrics() = false

    protected open fun contentScroller(): ScrollView = ScrollView(this)

    internal val settings
        get() = getSharedPreferences("settings", MODE_PRIVATE)

    internal var selectedVault: String
        get() = settings.getString("vault", "").orEmpty()
        set(value) {
            settings.edit().putString("vault", value).apply()
        }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        layout =
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(24, 40, 24, 24)
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            }
        setContentView(contentScroller().apply { addView(layout) })
    }

    internal fun page(title: String) {
        screenRevision++
        layout.removeAllViews()
        if (modernUi) {
            onPageChanged(title)
            layout.requestFocus()
            ViewCompat.setAccessibilityPaneTitle(layout, title)
        } else label(title, 24f)
    }

    internal fun label(value: String, size: Float = 16f): TextView {
        if (modernUi)
            return MobileUi.text(this, value, size, muted = size < 18f, bold = size >= 18f).apply {
                layoutParams = MobileUi.margins(this@VaultActivity, 12)
                this@VaultActivity.layout.addView(this)
            }
        return TextView(this).apply {
            text = value
            textSize = size
            setPadding(0, 12, 0, 12)
            this@VaultActivity.layout.addView(this)
        }
    }

    internal fun button(title: String, action: () -> Unit): Button {
        if (modernUi)
            return MobileUi.button(
                    this,
                    title,
                    danger =
                        listOf("Delete", "Permanently", "Empty trash", "Remove ").any {
                            title.startsWith(it)
                        },
                ) {
                    guarded(action)
                }
                .also(layout::addView)
        return Button(this).apply {
            text = title
            setOnClickListener { guarded(action) }
            this@VaultActivity.layout.addView(this)
        }
    }

    internal fun edit(hint: String, value: String = "", secret: Boolean = false): EditText {
        if (modernUi) return MobileUi.field(this, layout, hint, value, secret)
        return EditText(this).apply {
            this.hint = hint
            setText(value)
            isSaveEnabled = false
            inputType =
                if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            this@VaultActivity.layout.addView(this)
        }
    }

    protected fun guarded(action: () -> Unit) {
        runCatching(action).onFailure(::showFailure)
    }

    protected fun biometricStatusText(vault: String): String =
        if (DeviceKeys.enabled(this, vault)) "Biometric unlock: Enabled on this device"
        else "Biometric unlock: Disabled on this device"

    internal fun unlockOriginal(done: () -> Unit) {
        originalUnlockOnly = true
        unlock(done, fresh = true)
    }

    internal fun unlock(done: () -> Unit, fresh: Boolean = false) {
        val complete = {
            unlockContinuation = null
            originalUnlockOnly = false
            done()
        }
        task({
            if (fresh) Vault.request("lock")
            Vault.json("status").getBoolean("unlocked")
        }) { unlocked ->
            if (unlocked) complete() else unlockForm(complete)
        }
    }

    private fun unlockForm(done: () -> Unit) {
        unlockContinuation = done
        task({ Vault.request("vaults") as JSONArray }) { vaults ->
            page("Unlock vault")
            if (originalUnlockOnly)
                label("Use your original password or key file for this operation.")
            if (vaults.length() == 0) {
                label("Open Password Manager and import or download your encrypted vault first.")
                button("Open vault manager") {
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                }
                return@task
            }
            val names = (0 until vaults.length()).map { vaults.getString(it) }
            val spinner =
                Spinner(this).apply {
                    adapter =
                        ArrayAdapter(
                            this@VaultActivity,
                            android.R.layout.simple_spinner_dropdown_item,
                            names,
                        )
                    setSelection(names.indexOf(selectedVault).coerceAtLeast(0))
                }
            layout.addView(spinner)
            val biometricStatus = label("")
            val password = edit("Master password", secret = true)
            fun chosen() = names[spinner.selectedItemPosition].also { selectedVault = it }
            button("Unlock with password") {
                val name = chosen()
                val supplied = password.text.toString()
                password.text.clear()
                task({ Vault.request("unlock", "vault" to name, "password" to supplied) }) {
                    done()
                }
            }
            button("Unlock with key file") {
                val name = chosen()
                pickFile { bytes ->
                    task({
                        try {
                            Vault.request(
                                "unlock",
                                "vault" to name,
                                "key_file" to DeviceKeys.encode(bytes),
                            )
                        } finally {
                            bytes.fill(0)
                        }
                    }) {
                        done()
                    }
                }
            }
            val biometricUnlock =
                button("Unlock with biometrics") {
                    val name = chosen()
                    DeviceKeys.unlock(this, name) { material ->
                        task({
                            try {
                                Vault.request(
                                    "biometric_unlock",
                                    "vault" to name,
                                    "material" to DeviceKeys.encode(material),
                                )
                            } finally {
                                material.fill(0)
                            }
                        }) {
                            done()
                        }
                    }
                }
            fun refreshBiometricStatus() {
                val name = names[spinner.selectedItemPosition]
                biometricStatus.text = biometricStatusText(name)
                biometricUnlock.isEnabled = !originalUnlockOnly && DeviceKeys.enabled(this, name)
            }
            spinner.onItemSelectedListener =
                object : AdapterView.OnItemSelectedListener {
                    override fun onItemSelected(
                        parent: AdapterView<*>?,
                        view: View?,
                        position: Int,
                        id: Long,
                    ) {
                        refreshBiometricStatus()
                    }

                    override fun onNothingSelected(parent: AdapterView<*>?) {}
                }
            refreshBiometricStatus()
            button("Cancel") {
                setResult(RESULT_CANCELED)
                finish()
            }
            if (
                !originalUnlockOnly &&
                    automaticBiometrics() &&
                    !offeredBiometrics &&
                    selectedVault in names &&
                    DeviceKeys.enabled(this, selectedVault)
            ) {
                offeredBiometrics = true
                val begin = sessionCallback<Unit> { biometricUnlock.performClick() }
                layout.post { begin(Unit) }
            }
        }
    }

    internal fun pickFile(maxBytes: Int = 1024 * 1024, done: (ByteArray) -> Unit) {
        require(maxBytes in 1..(16 * 1024 * 1024))
        pickedLimit = maxBytes
        picked = done
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            },
            1,
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val callback = picked
        val limit = pickedLimit
        if (requestCode == 1) picked = null
        if (requestCode == 1 && resultCode == RESULT_OK && data?.data != null) {
            val uri = requireNotNull(data.data)
            taskDiscarding(
                {
                    contentResolver.openInputStream(uri)?.use { stream ->
                        stream.readBounded(limit)
                    } ?: error("Could not open file")
                },
                onDiscard = { it.fill(0) },
            ) { bytes ->
                guarded { callback?.invoke(bytes) }
            }
        } else if (requestCode == 1 && unlockContinuation != null) {
            unlockForm(requireNotNull(unlockContinuation))
        }
    }

    protected fun syncArgs(): Array<Pair<String, Any?>> =
        arrayOf(
            "server" to settings.getString("server", "").orEmpty(),
            "token" to DeviceKeys.token(this),
        )

    /** Syncs after an in-app change and describes the outcome. Run on a task thread. */
    protected fun syncAfterChange(): String {
        if (settings.getString("server", "").isNullOrBlank()) return "Saved locally"
        return runCatching {
                // Rust reports a disabled vault itself, so no separate status read is needed.
                val result = Vault.json("sync", *syncArgs(), "if_enabled" to true)
                if (result.optBoolean("disabled")) "Saved locally (sync disabled)"
                else "Saved and synchronized"
            }
            .getOrElse { "Saved locally. Sync pending: ${it.message}" }
    }

    override fun onDestroy() {
        picked = null
        unlockContinuation = null
        super.onDestroy()
    }

    override fun clearSecrets() {
        screenRevision++
        if (::layout.isInitialized) layout.removeAllViews()
    }
}
