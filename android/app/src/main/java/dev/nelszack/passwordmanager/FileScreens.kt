package dev.nelszack.passwordmanager

import android.net.Uri
import org.json.JSONArray

/** Backups, restores, imports, exports and key files, shown inside a [ManagementActivity]. */
internal class FileScreens(private val host: ManagementActivity) {
    private fun readFile(uri: Uri): ByteArray =
        host.contentResolver.openInputStream(uri)?.use { it.readBounded(MAX_TRANSFER) }
            ?: error("Could not open selected file")

    /** Sends the file at [uri] as the raw content of [op], wiping the bytes afterwards. */
    private fun sendFile(uri: Uri, op: String, vararg args: Pair<String, Any?>): Any {
        val bytes = readFile(uri)
        try {
            val reply = Vault.transfer(op, bytes, *args)
            reply.wipe()
            return reply.data
        } finally {
            bytes.fill(0)
        }
    }

    /** Runs a native operation that returns file content and writes it to [uri]. */
    private fun writeResult(uri: Uri, op: String, vararg args: Pair<String, Any?>) {
        val reply = Vault.transfer(op, null, *args)
        try {
            check(reply.size <= MAX_TRANSFER) { "File exceeds the 16 MiB mobile transfer limit" }
            host.contentResolver.openOutputStream(uri, "wt")?.use { reply.writeTo(it) }
                ?: error("Could not write selected file")
        } finally {
            reply.wipe()
        }
    }

    fun show() {
        with(host) {
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
            button("Restore complete encrypted backup") { restore() }
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
    }

    private fun backupForm(uri: Uri) {
        with(host) {
            page("Protect backup")
            pageBack = { show() }
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
    }

    fun restore() {
        with(host) {
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
                        sendFile(
                            uri,
                            "restore_backup",
                            "password" to supplied,
                            "key_file" to encoded,
                        ) as org.json.JSONObject
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
    }

    private fun importForm(uri: Uri) {
        with(host) {
            page("Import items")
            pageBack = { show() }
            val policy =
                labeledChoice(
                    "When an item already exists",
                    listOf(
                        "skip" to "Keep the existing item",
                        "replace" to "Replace it with the imported item",
                        "keep-both" to "Keep both",
                    ),
                )
            button("Preview import") {
                val selected = policy()
                task({
                    sendFile(uri, "import_items", "preview" to true, "conflicts" to selected)
                        as org.json.JSONObject
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
                            sendFile(
                                uri,
                                "import_items",
                                "preview" to false,
                                "conflicts" to selected,
                                "review_token" to preview.getString("review_token"),
                            )
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
    }

    fun keyVault() {
        with(host) {
            page("External-key vault")
            pageBack = { showHome() }
            label(
                "First save a new key file, then select that saved file to create the vault. Cancelling the save does not create a vault."
            )
            button("Generate and save a new key file") {
                destination("vault.key") { uri ->
                    task({ writeResult(uri, "new_key_file") }) { keyVault() }
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
    }

    private companion object {
        /** Matches the Rust mobile transfer limit. */
        const val MAX_TRANSFER = 16 * 1024 * 1024
    }
}
