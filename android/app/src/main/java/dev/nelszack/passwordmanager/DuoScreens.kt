package dev.nelszack.passwordmanager

import android.widget.Button
import org.json.JSONArray

/** Duo enrollment and push approval screens, shown inside a [ManagementActivity]. */
internal class DuoScreens(private val host: ManagementActivity) {
    fun enrollment(id: Long) {
        with(host) {
            page("Duo enrollment & push")
            pageBack = { authenticator(id) }
            label(
                "Use a fresh activation link for a separate device. Enrollment consumes the link. Existing push credentials are never replaced without confirmation."
            )
            val activation = edit("Duo activation link", secret = true)
            val mode =
                labeledChoice(
                    "Passcode mode",
                    listOf("hotp" to "Counter-based codes (HOTP)", "totp" to "Time-based codes (TOTP)"),
                )
            val push = toggle("Enroll push credentials", true)
            val replace = toggle("Replace existing enrollment")
            button("Enroll Duo") {
                val link = activation.text.toString().trim()
                activation.text.clear()
                confirm("Consume this activation link and enroll this item?", "Enroll") {
                    task({
                        val command =
                            VaultCommands.duoEnroll(
                                id,
                                link,
                                mode(),
                                push.isChecked,
                                replace.isChecked,
                            )
                        (Vault.command(command) as String).also { afterToolChange() }
                    }) {
                        label(it)
                    }
                }
            }
            button("Check Duo Push requests") { inbox(listOf(id to ""), back = { enrollment(id) }) }
            button("Remove local push credentials") {
                confirm(
                    "Remove this item's local push credentials? Passcodes remain; remove the device in Duo separately."
                ) {
                    change(VaultCommands.duoRemove(id)) { enrollment(id) }
                }
            }
            button("Back to authenticator") { authenticator(id) }
        }
    }

    /**
     * Every pending push for [accounts] on one page. The card is the review, so Approve or
     * Deny answers it in one tap; the buttons wake after a short pause so a tap meant for the
     * previous screen cannot answer a request, and the server re-checks the request's
     * fingerprint before responding.
     */
    fun inbox(
        accounts: List<Pair<Long, String>>,
        back: () -> Unit,
        message: String = "",
    ) {
        with(host) {
            task({
                accounts.map { (id, name) ->
                    Triple(id, name, runCatching { Vault.command(VaultCommands.duoRequests(id)) as JSONArray })
                }
            }) { results ->
                page("Duo Push")
                pageBack = back
                if (message.isNotBlank()) notice(message)
                val now = System.currentTimeMillis() / 1000
                val guarded = mutableListOf<Button>()
                var pending = 0
                for ((id, name, result) in results) {
                    val requests = result.getOrNull()
                    if (requests == null) {
                        label("$name: ${result.exceptionOrNull()?.message ?: "Could not check requests"}")
                        continue
                    }
                    for (i in 0 until requests.length()) {
                        val request = requests.getJSONObject(i)
                        val expires = request.getLong("expires_at")
                        if (expires <= now) continue
                        pending++
                        section(request.getString("application").ifBlank { name.ifBlank { "Duo login" } })
                        label(
                            listOfNotNull(
                                "Account: ${request.getString("username").ifBlank { "Not provided" }}",
                                "Location: ${request.getString("location").ifBlank { "Not provided" }}",
                                request.getString("summary").ifBlank { null },
                                name.takeIf { it.isNotBlank() }?.let { "Saved login: $it" },
                                "Expires ${java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(expires * 1000))}",
                            ).joinToString("\n")
                        )
                        val unsupported = request.opt("unsupported") as? String
                        val digits = (request.opt("code_digits") as? Number)?.toInt()
                        val code =
                            if (digits != null && unsupported == null)
                                edit("$digits-digit code shown on the login page", secret = true).apply {
                                    inputType =
                                        android.text.InputType.TYPE_CLASS_NUMBER or
                                            android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
                                }
                            else null
                        if (unsupported != null) notice("This request can't be approved here: $unsupported")
                        fun respond(approve: Boolean) {
                            val supplied = code?.text?.toString().orEmpty()
                            if (approve && digits != null && !Regex("[0-9]{$digits}").matches(supplied)) {
                                code?.requestFocus()
                                error("Enter the $digits-digit code shown on the login page.")
                            }
                            code?.text?.clear()
                            guarded.forEach { it.isEnabled = false }
                            task({
                                Vault.command(
                                    VaultCommands.duoRespond(
                                        id,
                                        request.getString("id"),
                                        request.getString("fingerprint"),
                                        approve,
                                        if (approve) supplied else "",
                                    )
                                ) as String
                            }) { outcome -> inbox(accounts, back, outcome) }
                        }
                        val (approve, deny) =
                            pairedActions("Approve", "Deny", { respond(true) }, { respond(false) })
                        if (unsupported == null) guarded.add(approve) else approve.isEnabled = false
                        guarded.add(deny)
                    }
                }
                if (pending == 0) {
                    label("No pending Duo Push requests.", 18f)
                    label("Start the login on your other device, then check again.", 13f)
                } else label("Approve only a login you started.", 13f)
                primary("Check again") { inbox(accounts, back) }
                guarded.forEach { it.isEnabled = false }
                ui.postDelayed({ guarded.forEach { it.isEnabled = true } }, DUO_INPUT_GUARD_MS)
            }
        }
    }

    companion object {
        /** Approve/Deny stay disabled this long after a Duo page appears. */
        private const val DUO_INPUT_GUARD_MS = 600L

        /** Duo-enrolled items, by name, from an item list response. */
        fun enrolledAccounts(entries: JSONArray): List<Pair<Long, String>> =
            (0 until entries.length())
                .map(entries::getJSONObject)
                .filter { it.optBoolean("has_duo") }
                .map { it.getLong("id") to it.getString("name") }
    }
}
