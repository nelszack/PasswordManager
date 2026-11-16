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
import java.util.UUID

data class LoginForm(val origin: String, val username: AutofillId?, val password: AutofillId?, val userValue: String?, val passwordValue: String?) {
    val ids get() = listOfNotNull(username, password).toTypedArray()
}

object Forms {
    fun read(context: Context, structure: AssistStructure): LoginForm? {
        val packageName = structure.activityComponent.packageName
        if (packageName == context.packageName) return null
        data class Field(val id: AutofillId, val user: Boolean, val value: String?, val origin: String?)
        val fields = mutableListOf<Field>()
        val addresses = mutableListOf<String>()
        fun walk(node: AssistStructure.ViewNode, depth: Int = 0, inheritedOrigin: String? = null) {
            if (depth > 100 || fields.size > 1000) return
            // Framework webDomain drops the port. Only native browser chrome,
            // never page HTML attributes, can supplement it with a full URL.
            if (node.idPackage == packageName && node.idEntry in setOf("url_bar", "mozac_browser_toolbar_url_view")
                && node.htmlInfo == null && !node.isFocused) {
                node.text?.toString()?.takeIf { it.isNotBlank() }?.let(addresses::add)
            }
            val nodeOrigin = node.webDomain?.let { domain ->
                val scheme = node.webScheme ?: error("Missing website scheme")
                CallerIdentity.websiteOrigin("$scheme://$domain")
            } ?: inheritedOrigin
            val html = node.htmlInfo?.attributes?.associate { it.first to it.second }.orEmpty()
            val hints = listOfNotNull(node.idEntry, node.hint, html["autocomplete"], html["type"], html["name"])
                .plus(node.autofillHints?.toList().orEmpty()).joinToString(" ").lowercase()
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            val password = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD && node.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER || hints.contains("password")
            val username = !password && (hints.contains("username") || hints.contains("email") || hints.contains("user_name"))
            if ((password || username) && node.autofillId != null) fields.add(Field(requireNotNull(node.autofillId), username, node.autofillValue?.takeIf { it.isText }?.textValue?.toString(), nodeOrigin))
            for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1, nodeOrigin)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        val domains = fields.mapNotNull { it.origin }.toSet()
        val origin = if (domains.isEmpty()) CallerIdentity.appOrigin(context, packageName) else {
            check(domains.size == 1 && fields.all { it.origin == domains.single() } && CallerIdentity.trustedBrowser(context, packageName)) { "Untrusted or ambiguous website origin" }
            val origins = addresses.mapNotNull { address -> runCatching { CallerIdentity.addressBarOrigin(address, domains.single()) }.getOrNull() }.toSet()
            check(origins.size == 1) { "Browser did not expose a verifiable full HTTPS address" }
            origins.single()
        }
        val passwords = fields.filter { !it.user }.distinctBy { it.id }
        val users = fields.filter { it.user }.distinctBy { it.id }
        if (passwords.size > 1 || users.size > 1) return null // don't combine login/signup/frame partitions
        if (passwords.isEmpty() && users.isEmpty()) return null
        return LoginForm(origin, users.firstOrNull()?.id, passwords.firstOrNull()?.id, users.firstOrNull()?.value, passwords.firstOrNull()?.value)
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
                FillResponse.Builder().setAuthentication(form.ids, Forms.pending(this, "fill").intentSender,
                    Forms.presentation(this, "Unlock Password Manager for ${form.origin}"))
                    .apply { form.password?.let { setSaveInfo(SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(it))
                        .apply { form.username?.let { user -> setOptionalIds(arrayOf(user)) } }.build()) } }.build()
            }.getOrNull()
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
                    putExtra("origin", form.origin); putExtra("username", form.userValue.orEmpty()); putExtra("password", form.passwordValue)
                }
                callback.onSuccess(pending.intentSender)
            }.onFailure { callback.onFailure("Could not prepare login saving") }
        }
    }
}
