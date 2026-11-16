package dev.nelszack.passwordmanager

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject

abstract class VaultActivity : SecureActivity() {
    protected lateinit var layout: LinearLayout
    private var picked: ((ByteArray) -> Unit)? = null
    private var unlockContinuation: (() -> Unit)? = null
    protected val settings get() = getSharedPreferences("settings", MODE_PRIVATE)
    protected var selectedVault: String
        get() = settings.getString("vault", "").orEmpty()
        set(value) { settings.edit().putString("vault", value).apply() }
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(24, 40, 24, 24)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        setContentView(ScrollView(this).apply { addView(layout) })
    }
    protected fun page(title: String) { layout.removeAllViews(); label(title, 24f) }
    protected fun label(value: String, size: Float = 16f): TextView = TextView(this).apply {
        text = value; textSize = size; setPadding(0, 12, 0, 12); this@VaultActivity.layout.addView(this)
    }
    protected fun button(title: String, action: () -> Unit) = Button(this).apply {
        text = title; setOnClickListener { guarded(action) }; this@VaultActivity.layout.addView(this)
    }
    protected fun edit(hint: String, value: String = "", secret: Boolean = false): EditText = EditText(this).apply {
        this.hint = hint; setText(value); isSaveEnabled = false
        inputType = if (secret) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        this@VaultActivity.layout.addView(this)
    }
    protected fun guarded(action: () -> Unit) {
        runCatching(action).onFailure(::showFailure)
    }
    protected fun unlock(done: () -> Unit, fresh: Boolean = false) {
        task({ if (fresh) Vault.request("lock"); Vault.json("status").getBoolean("unlocked") }) { unlocked ->
            if (unlocked) done() else unlockForm(done)
        }
    }
    private fun unlockForm(done: () -> Unit) {
        unlockContinuation = done
        task({ Vault.request("vaults") as JSONArray }) { vaults ->
            page("Unlock vault")
            if (vaults.length() == 0) {
                label("Open Password Manager and import or download your encrypted vault first.")
                button("Open vault manager") { startActivity(Intent(this, MainActivity::class.java)); finish() }
                return@task
            }
            val names = (0 until vaults.length()).map { vaults.getString(it) }
            val spinner = Spinner(this).apply {
                adapter = ArrayAdapter(this@VaultActivity, android.R.layout.simple_spinner_dropdown_item, names)
                setSelection(names.indexOf(selectedVault).coerceAtLeast(0))
            }
            layout.addView(spinner)
            val password = edit("Master password", secret = true)
            fun chosen() = names[spinner.selectedItemPosition].also { selectedVault = it }
            button("Unlock with password") {
                val name = chosen(); val supplied = password.text.toString(); password.text.clear()
                task({ Vault.request("unlock", "vault" to name, "password" to supplied) }) { done() }
            }
            button("Unlock with key file") {
                val name = chosen()
                pickFile { bytes -> task({
                    try { Vault.request("unlock", "vault" to name, "key_file" to DeviceKeys.encode(bytes)) }
                    finally { bytes.fill(0) }
                }) { done() } }
            }
            button("Unlock with biometrics") {
                val name = chosen()
                DeviceKeys.unlock(this, name) { material -> task({
                    try { Vault.request("biometric_unlock", "vault" to name, "material" to DeviceKeys.encode(material)) }
                    finally { material.fill(0) }
                }) { done() } }
            }
            button("Cancel") { setResult(RESULT_CANCELED); finish() }
        }
    }
    protected fun pickFile(maxBytes: Int = 1024 * 1024, done: (ByteArray) -> Unit) {
        picked = { bytes -> check(bytes.size <= maxBytes) { "File exceeds size limit" }; done(bytes) }
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) }, 1)
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val callback = picked; picked = null
        if (requestCode == 1 && resultCode == RESULT_OK && data?.data != null) {
            val uri = requireNotNull(data.data)
            task({ contentResolver.openInputStream(uri)?.use { stream ->
                val bytes = stream.readBounded(128 * 1024 * 1024)
                check(bytes.size <= 128 * 1024 * 1024) { "File exceeds size limit" }; bytes
            } ?: error("Could not open file") }) { bytes -> guarded { callback?.invoke(bytes) } }
        } else if (requestCode == 1 && unlockContinuation != null) {
            unlockForm(requireNotNull(unlockContinuation))
        }
    }
    protected fun syncArgs(): Array<Pair<String, Any?>> = arrayOf(
        "server" to settings.getString("server", "").orEmpty(), "token" to DeviceKeys.token(this)
    )
    protected fun syncAfterChange(): String {
        if (settings.getString("server", "").isNullOrBlank()) return "Saved locally"
        return runCatching { Vault.request("sync", *syncArgs()); "Saved and synchronized" }
            .getOrElse { "Saved locally. Sync pending: ${it.message}" }
    }
    override fun clearSecrets() {
        if (::layout.isInitialized) layout.removeAllViews()
    }
}
