package dev.nelszack.passwordmanager

import android.app.AlertDialog
import android.widget.LinearLayout
import android.widget.ScrollView
import org.json.JSONObject

/** Mobile preference list and editors, shown inside a [ManagementActivity]. */
internal class PreferenceScreens(private val host: ManagementActivity) {
    fun show(back: (() -> Unit)? = null) {
        with(host) {
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
                        editor(field, current, back)
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
                            remember(saved)
                            show(back)
                        }
                    }
                }
            }
        }
    }

    private fun remember(saved: JSONObject) {
        with(host) {
            settings
                .edit()
                .putLong("unlock_seconds", saved.getLong("unlock_seconds"))
                .putInt("clipboard_seconds", saved.getInt("clipboard_seconds"))
                .apply()
            Vault.touch()
        }
    }

    private fun editor(field: MobilePreference, current: JSONObject, back: (() -> Unit)?) {
        with(host) {
            val content =
                LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    val pad = MobileUi.dp(host, 20)
                    setPadding(pad, pad, pad, 0)
                }
            content.addView(
                MobileUi.text(this, field.help, 14f, muted = true).apply {
                    layoutParams = MobileUi.margins(host, 16)
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
                                    remember(saved)
                                    dialog.dismiss()
                                    show()
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
    }
}
