package dev.nelszack.passwordmanager

import org.json.JSONArray
import org.json.JSONObject

/**
 * Typed vault commands shared with the desktop service (`ServerCommand` in pm-contracts). The
 * native bridge runs them through the same Rust code as the desktop, so field names here follow
 * that contract exactly.
 */
object VaultCommands {
    /** A new or edited custom field. */
    data class Field(val name: String, val value: String, val secret: Boolean) {
        fun json(): JSONObject =
            JSONObject().put("name", name).put("value", value).put("secret", secret)
    }

    private fun command(operation: String, arguments: Any? = null): JSONObject =
        JSONObject().put("operation", operation).apply {
            if (arguments != null) put("arguments", arguments)
        }

    private fun target(id: Long) = JSONObject().put("Id", id)

    private fun nullable(value: Any?): Any = value ?: JSONObject.NULL

    fun item(id: Long) = command("management_item", JSONObject().put("id", id).put("reveal", true))

    fun delete(id: Long) = command("delete", target(id))

    fun history(id: Long) = command("history", target(id))

    fun restorePassword(id: Long, revision: Int) =
        command(
            "restore_password",
            JSONObject().put("target", target(id)).put("revision", revision),
        )

    fun trash() = command("trash")

    fun restoreTrash(id: Long) = command("restore_trash", id)

    /** Permanently erases one trashed item, or every trashed item when [id] is null. */
    fun purgeTrash(id: Long?) = command("purge_trash", nullable(id))

    /** Reads the current code. Counter-based (HOTP) codes advance their counter. */
    fun authenticatorCode(id: Long) = command("authenticator_data", target(id))

    fun setAuthenticator(id: Long, configuration: String) =
        command(
            "totp",
            JSONObject()
                .put(
                    "Set",
                    JSONObject().put("target", target(id)).put("configuration", configuration),
                ),
        )

    fun removeAuthenticator(id: Long) =
        command("totp", JSONObject().put("Remove", JSONObject().put("target", target(id))))

    fun search(
        query: String? = null,
        name: String? = null,
        username: String? = null,
        url: String? = null,
        notes: String? = null,
        kind: String? = null,
        hasTotp: Boolean? = null,
        weak: Boolean = false,
        staleDays: Long? = null,
        sort: String = "id",
        descending: Boolean = false,
    ) =
        command(
            "list",
            JSONObject()
                .put("query", nullable(query))
                .put("name", nullable(name))
                .put("username", nullable(username))
                .put("url", nullable(url))
                .put("notes", nullable(notes))
                .put(
                    "list",
                    JSONObject()
                        .put("kind", nullable(kind))
                        .put("has_totp", nullable(hasTotp))
                        .put("weak", weak)
                        .put("stale_days", nullable(staleDays))
                        .put("sort", sort)
                        .put("descending", descending),
                ),
        )

    fun audit(staleDays: Long?, requireTotp: Boolean, checkBreaches: Boolean) =
        command(
            "audit",
            JSONObject()
                .put("stale_days", nullable(staleDays))
                .put("require_totp", requireTotp)
                .put("check_breaches", checkBreaches),
        )

    /** Adds an item. The first website is primary; the rest are additional. */
    fun add(
        name: String,
        username: String?,
        password: String,
        urls: List<String> = emptyList(),
        notes: String? = null,
        kind: String = "login",
        fields: List<Field> = emptyList(),
    ) =
        command(
            "add",
            JSONObject()
                .put(
                    "entry",
                    JSONObject()
                        .put(
                            "entry",
                            JSONObject()
                                .put("name", name)
                                .put("username", nullable(username))
                                .put("password", password)
                                .put("url", nullable(urls.firstOrNull()))
                                .put("notes", nullable(notes))
                                .put("copy", false),
                        )
                        .put("kind", kind)
                        .put("additional_urls", JSONArray(urls.drop(1)))
                        .put("custom_fields", JSONArray(fields.map(Field::json))),
                )
                .put("copy_timeout", 0),
        )

    /**
     * Replaces an item's details. With [replaceDetails], websites and custom fields are replaced by
     * [urls] and [fields]; otherwise they are left unchanged.
     */
    fun update(
        id: Long,
        name: String,
        username: String?,
        password: String,
        urls: List<String> = emptyList(),
        notes: String? = null,
        kind: String? = null,
        fields: List<Field> = emptyList(),
        replaceDetails: Boolean = false,
    ) =
        command(
            "update",
            JSONObject()
                .put(
                    "entry",
                    JSONObject()
                        .put("target", target(id))
                        .put(
                            "update",
                            JSONObject()
                                .put("name", name)
                                .put("username", nullable(username))
                                .put("url", nullable(urls.firstOrNull()))
                                .put("notes", nullable(notes)),
                        )
                        .put("password", password),
                )
                .put("kind", nullable(kind))
                .put("add_url", JSONArray(urls.drop(1)))
                .put("remove_url", JSONArray())
                .put("clear_urls", replaceDetails)
                .put("set_fields", JSONArray(fields.map(Field::json)))
                .put("remove_fields", JSONArray())
                .put("clear_fields", replaceDetails),
        )

    /** Enrolls Duo passcodes, and push approvals when [push] is set. */
    fun duoEnroll(id: Long, activation: String, mode: String, push: Boolean, replace: Boolean) =
        if (push) {
            command(
                "duo",
                JSONObject()
                    .put(
                        "Enroll",
                        JSONObject()
                            .put("target", target(id))
                            .put("activation", activation)
                            .put("mode", otpMode(mode))
                            .put("replace", replace),
                    ),
            )
        } else {
            command(
                "totp",
                JSONObject()
                    .put(
                        "Duo",
                        JSONObject()
                            .put("target", target(id))
                            .put("activation", activation)
                            .put("mode", otpMode(mode)),
                    ),
            )
        }

    fun duoRequests(id: Long) =
        command("duo", JSONObject().put("Requests", JSONObject().put("target", target(id))))

    fun duoRespond(
        id: Long,
        requestId: String,
        fingerprint: String,
        approve: Boolean,
        code: String,
    ) =
        command(
            "duo",
            JSONObject()
                .put(
                    "Respond",
                    JSONObject()
                        .put("target", target(id))
                        .put("request_id", requestId)
                        .put("fingerprint", fingerprint)
                        .put("approve", approve)
                        .put("code", code),
                ),
        )

    fun duoRemove(id: Long) =
        command("duo", JSONObject().put("Remove", JSONObject().put("target", target(id))))

    private fun otpMode(mode: String) =
        if (mode.equals("totp", ignoreCase = true)) "Totp" else "Hotp"

    /** "totp", "hotp", or null, read from an item without consuming a code. */
    fun authenticatorMode(item: JSONObject): String? =
        (item.opt("otp_mode") as? String)?.lowercase()
}
