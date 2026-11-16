package dev.nelszack.passwordmanager

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.*
import android.text.InputType
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import android.util.Log
import android.view.View
import java.util.UUID

data class LoginForm(val origin: String, val username: AutofillId?, val password: AutofillId?, val userValue: String?, val passwordValue: String?, val hostnameOnly: Boolean = false, val otp: AutofillId? = null) {
    val ids get() = listOfNotNull(username, password, otp).toTypedArray()
    val codeOnly get() = otp != null && username == null && password == null
}

object Forms {
    class Rejected(val reason: String) : IllegalStateException(reason)
    fun read(context: Context, structure: AssistStructure): LoginForm? {
        val packageName = structure.activityComponent.packageName
        if (packageName == context.packageName) return null
        data class Field(val id: AutofillId, val user: Boolean, val code: Boolean, val value: String?, val origin: String?)
        val fields = mutableListOf<Field>()
        val addresses = mutableListOf<String>()
        fun walk(node: AssistStructure.ViewNode, depth: Int = 0, inheritedOrigin: String? = null) {
            if (depth > 100 || fields.size > 1000 || node.visibility != View.VISIBLE) return
            // Framework webDomain drops the port. Only native browser chrome,
            // never page HTML attributes, can supplement it with a full URL.
            if (node.idPackage == packageName && node.idEntry in setOf("url_bar", "mozac_browser_toolbar_url_view")
                && node.htmlInfo == null && !node.isFocused) {
                node.text?.toString()?.takeIf { it.isNotBlank() }?.let(addresses::add)
            }
            val nodeOrigin = node.webDomain?.let { domain ->
                val scheme = node.webScheme ?: throw Rejected("missing_website_scheme")
                CallerIdentity.websiteOrigin("$scheme://$domain")
            } ?: inheritedOrigin
            val html = node.htmlInfo?.attributes?.associate { it.first to it.second }.orEmpty()
            val hints = listOfNotNull(node.idEntry, node.hint, html["autocomplete"], html["type"], html["name"], html["id"], html["label"], html["ua-autofill-hints"], html["computed-autofill-hints"])
                .plus(node.autofillHints?.toList().orEmpty()).joinToString(" ").lowercase()
            val code = VerificationFields.isCode(hints)
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            val password = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD && node.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER || hints.contains("password")
            val username = !password && !code && (hints.contains("username") || hints.contains("email") || hints.contains("user_name"))
            if ((password || username || code) && node.autofillId != null) fields.add(Field(requireNotNull(node.autofillId), username, code, node.autofillValue?.takeIf { it.isText }?.textValue?.toString(), nodeOrigin))
            for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1, nodeOrigin)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        val domains = fields.mapNotNull { it.origin }.toSet()
        // Counts and fixed reason codes only: never log a structure, origin,
        // username, password, or field value.
        Log.d("PMAutofill", "Parsed fields=${fields.size} web_origins=${domains.size} native_addresses=${addresses.size}")
        var hostnameOnly = false
        val origin = if (domains.isEmpty()) CallerIdentity.appOrigin(context, packageName) else {
            if (domains.size != 1 || fields.any { it.origin != domains.single() }) throw Rejected("ambiguous_website_origin")
            if (!CallerIdentity.trustedBrowser(context, packageName)) throw Rejected("untrusted_browser")
            val site = CallerIdentity.browserSite(domains.single(), addresses)
            if (site.hostnameOnly && packageName != "com.android.chrome") throw Rejected("missing_full_website_address")
            hostnameOnly = site.hostnameOnly
            site.origin
        }
        val passwords = fields.filter { !it.user && !it.code }.distinctBy { it.id }
        val users = fields.filter { it.user }.distinctBy { it.id }
        val codes = fields.filter { it.code }.distinctBy { it.id }
        if (passwords.size > 1 || users.size > 1 || codes.size > 1) return null // don't combine login/signup/frame partitions
        if (passwords.isEmpty() && users.isEmpty() && codes.isEmpty()) return null
        return LoginForm(origin, users.firstOrNull()?.id, passwords.firstOrNull()?.id, users.firstOrNull()?.value, passwords.firstOrNull()?.value, hostnameOnly, codes.firstOrNull()?.id)
    }
    fun presentation(context: Context, title: String) = RemoteViews(context.packageName, android.R.layout.simple_list_item_1).apply { setTextViewText(android.R.id.text1, title) }
    fun pending(context: Context, mode: String, extras: Intent.() -> Unit = {}): PendingIntent {
        val intent = Intent(context, FillActivity::class.java).apply {
            action = UUID.randomUUID().toString(); putExtra("mode", mode); extras()
        }
        return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT)
    }
}

class VaultAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, signal: CancellationSignal, callback: FillCallback) {
        Vault.worker.execute {
            if (signal.isCanceled) return@execute
            val response = runCatching {
                val structure = request.fillContexts.lastOrNull()?.structure ?: return@runCatching null
                val form = Forms.read(this, structure) ?: return@runCatching null
                val scope = AutofillScope(structure.activityComponent.packageName, form.origin, form.hostnameOnly)
                val reusable = Vault.autofillSession.allows(scope) && Vault.json("status").getBoolean("unlocked")
                val builder = FillResponse.Builder()
                val entries = if (reusable) AutofillSuggestions.entries(form) else null
                if (entries == null || entries.length() == 0) {
                    builder.addDataset(AutofillSuggestions.suggestion(this, request, form, 0,
                        if (reusable) "Choose account" else "Unlock", "Password Manager"))
                } else {
                    val capacity = if (android.os.Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.maxSuggestionCount?.coerceIn(1, 20) ?: 20 else 20
                    val more = entries.length() > capacity
                    val count = if (more) capacity - 1 else entries.length()
                    for (i in 0 until count) {
                        val entry = entries.getJSONObject(i)
                        val origin = AutofillSuggestions.origin(form, entry)
                        val port = java.net.URI(origin).port
                        val name = entry.getString("name")
                        val username = entry.opt("username") as? String ?: ""
                        val subtitle = (if (port > 0 && port != 443) "Port $port · " else "") +
                            (if (form.codeOnly) "Verification code · " else "") + name
                        builder.addDataset(AutofillSuggestions.suggestion(this, request, form, i, username.ifBlank { name }, subtitle, entry))
                    }
                    if (more) builder.addDataset(AutofillSuggestions.suggestion(this, request, form, count, "More accounts", "Password Manager"))
                }
                form.password?.let { password ->
                    builder.setSaveInfo(SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(password))
                        .apply { form.username?.let { setOptionalIds(arrayOf(it)) } }.build())
                }
                Log.d("PMAutofill", "Suggestions prepared: unlocked=$reusable code_only=${form.codeOnly}")
                builder.build()
            }.onFailure { error -> Log.w("PMAutofill", "Fill rejected: ${(error as? Forms.Rejected)?.reason ?: error.javaClass.simpleName}") }.getOrNull()
            if (!signal.isCanceled) callback.onSuccess(response)
        }
    }
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Vault.worker.execute {
            runCatching {
                val structure = request.fillContexts.lastOrNull()?.structure ?: error("Missing login form")
                val form = Forms.read(this, structure) ?: error("Unsupported login form")
                check(!form.passwordValue.isNullOrEmpty()) { "No password to save" }
                val pending = Forms.pending(this, "save") {
                    putExtra("origin", form.origin); putExtra("hostname_only", form.hostnameOnly); putExtra("username", form.userValue.orEmpty()); putExtra("password", form.passwordValue)
                }
                callback.onSuccess(pending.intentSender)
            }.onFailure { callback.onFailure("Could not prepare login saving") }
        }
    }
}
