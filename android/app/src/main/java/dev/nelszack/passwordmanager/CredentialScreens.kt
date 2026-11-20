package dev.nelszack.passwordmanager

/** Vault credential changes and local vault deletion, shown inside a [ManagementActivity]. */
internal class CredentialScreens(private val host: ManagementActivity) {
    fun show() {
        with(host) {
            page("Vault credentials")
            label(
                "Credential changes and vault deletion require an original password/key-file unlock. Create a backup first. Rekeying also preserves a local recovery copy that the old credentials still open; you are offered its deletion after the new credentials work. Biometric unlock must be set up again afterward."
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
                            unlockOriginal { rekey("key_file", encoded) }
                        }
                    }
                    button("Cancel") { showHome() }
                }
            }
            button("Delete old-password recovery copies") {
                unlockOriginal {
                    show()
                    task({ Vault.json("rekey_recovery").getInt("copies") }) { copies ->
                        if (copies == 0)
                            notice(
                                "No recovery copies from earlier credential changes of this vault remain on this phone."
                            )
                        else confirmCleanup(copies)
                    }
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
    }

    private fun rekeyForm() {
        with(host) {
            page("Change master password")
            pageBack = { show() }
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
                    rekey("password", supplied)
                }
            }
            button("Cancel") { showHome() }
        }
    }

    private fun rekey(key: String, value: String) {
        with(host) {
            check(Vault.primaryUnlock) { "Unlock with the original password or key file first" }
            DeviceKeys.disable(this, selectedVault)
            val vault = selectedVault
            task({ Vault.request("rekey", key to value) }) {
                // Offer to delete the old-credential copy once the new credentials unlock it.
                settings.edit().putString(RECOVERY_PROMPT, vault).apply()
                Vault.lock()
                showHome()
            }
        }
    }

    /**
     * Once per credential change, after the new credentials have unlocked the vault, offers to
     * delete the recovery copy that the old credentials still open.
     */
    fun offerRecoveryCleanup() {
        with(host) {
            val vault = selectedVault
            if (settings.getString(RECOVERY_PROMPT, null) != vault || !Vault.primaryUnlock) return
            settings.edit().remove(RECOVERY_PROMPT).apply()
            task({ Vault.json("rekey_recovery").getInt("copies") }) { copies ->
                if (copies > 0 && selectedVault == vault) confirmCleanup(copies)
            }
        }
    }

    private fun confirmCleanup(copies: Int) {
        with(host) {
            confirm(
                (if (copies == 1) "Delete the recovery copy"
                else "Delete the $copies recovery copies") +
                    " saved when this vault's password or key file was changed?\n\n" +
                    "Each copy is a complete vault still encrypted with the OLD password or key " +
                    "file. Anyone who has, or later learns, the old credentials can open it. " +
                    "Delete it once you are sure the new credentials work.\n\n" +
                    "If this vault syncs, the server also keeps up to two earlier versions; " +
                    "versions uploaded before the change stay encrypted with the old " +
                    "credentials until newer uploads replace them."
            ) {
                task({ Vault.json("delete_rekey_recovery", "confirmed" to true).getInt("deleted") }) {
                    deleted ->
                    notice(
                        if (deleted == 1) "Deleted the old-credential recovery copy."
                        else "Deleted $deleted old-credential recovery copies."
                    )
                }
            }
        }
    }

    private companion object {
        /** Preference naming the vault whose next primary unlock offers cleanup. */
        const val RECOVERY_PROMPT = "rekey_recovery_prompt"
    }
}
