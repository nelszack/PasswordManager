package dev.nelszack.passwordmanager

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.*
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import java.util.UUID

data class LoginForm(
    val origin: String,
    val username: AutofillId?,
    val password: AutofillId?,
    val userValue: String?,
    val passwordValue: String?,
    val hostnameOnly: Boolean = false,
    val otp: AutofillId? = null,
) {
    val ids
        get() = listOfNotNull(username, password, otp).toTypedArray()

    val codeOnly
        get() = otp != null && username == null && password == null
}

/** A payment-card or identity form: each field's role, as classified by the vault library. */
data class TypedForm(
    val origin: String,
    val hostnameOnly: Boolean,
    val kind: String,
    val fields: Map<AutofillId, String>,
) {
    val ids
        get() = fields.keys.toTypedArray()

    val card
        get() = kind == "payment-card"
}

/** How a field takes part in signing in. */
enum class LoginRole {
    USERNAME,
    PASSWORD,
    CODE,
}

object Forms {
    class Rejected(val reason: String) : IllegalStateException(reason)

    private val BROWSER_ADDRESS_BARS = setOf("url_bar", "mozac_browser_toolbar_url_view")

    /**
     * The website origin [node] and its children belong to. Also records the browser's own
     * address bar text in [addresses]: framework webDomain drops the port, and only native
     * browser chrome, never page HTML attributes, can supplement it with a full URL.
     */
    private fun visitOrigin(
        node: AssistStructure.ViewNode,
        packageName: String,
        inheritedOrigin: String?,
        addresses: MutableList<String>,
    ): String? {
        if (
            node.idPackage == packageName &&
                node.idEntry in BROWSER_ADDRESS_BARS &&
                node.htmlInfo == null &&
                !node.isFocused
        ) {
            node.text?.toString()?.takeIf { it.isNotBlank() }?.let(addresses::add)
        }
        return node.webDomain?.let { domain ->
            val scheme = node.webScheme ?: throw Rejected("missing_website_scheme")
            CallerIdentity.websiteOrigin("$scheme://$domain")
        } ?: inheritedOrigin
    }

    private val CARD_CODE = Regex("""\b(cvv2?|cvc2?|csc|cc-csc)\b|card[ _-]?(security|verification)""")

    /**
     * The sign-in role of a field from its lowercase descriptions (view ID, hint, HTML attributes
     * and autofill hints, joined by spaces) and input type, or null when it plays none.
     */
    fun loginRole(hints: String, inputType: Int): LoginRole? {
        if (VerificationFields.isCode(hints)) return LoginRole.CODE
        // Checkout pages often mask a card's security code like a password.
        if (CARD_CODE.containsMatchIn(hints)) return null
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val password =
            variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD &&
                    inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER ||
                hints.contains("password")
        if (password) return LoginRole.PASSWORD
        return if (
            hints.contains("username") || hints.contains("email") || hints.contains("user_name")
        )
            LoginRole.USERNAME
        else null
    }

    /** One text field's identity, origin, and the text that describes its role. */
    private data class Described(
        val id: AutofillId,
        val description: String,
        val origin: String?,
        val focused: Boolean,
    )

    /**
     * Card and identity fields, used when the structure has no login fields. The shared vault
     * library assigns roles so the rules match the browser extension's.
     */
    fun readTyped(context: Context, structure: AssistStructure): TypedForm? {
        val packageName = structure.activityComponent.packageName
        if (packageName == context.packageName) return null
        val fields = mutableListOf<Described>()
        val addresses = mutableListOf<String>()
        fun walk(node: AssistStructure.ViewNode, depth: Int = 0, inheritedOrigin: String? = null) {
            if (depth > 100 || fields.size > 200 || node.visibility != View.VISIBLE) return
            val nodeOrigin = visitOrigin(node, packageName, inheritedOrigin, addresses)
            val html = node.htmlInfo?.attributes?.associate { it.first to it.second }.orEmpty()
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            val password =
                variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            val id = node.autofillId
            if (id != null && !password && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                val description =
                    listOfNotNull(
                            html["autocomplete"],
                            node.idEntry,
                            node.hint,
                            html["name"],
                            html["id"],
                            html["label"],
                            html["placeholder"],
                        )
                        .plus(node.autofillHints?.toList().orEmpty())
                        .joinToString(" ")
                        .take(4096)
                if (description.isNotBlank())
                    fields.add(Described(id, description, nodeOrigin, node.isFocused))
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1, nodeOrigin)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        if (fields.isEmpty()) return null
        val roles =
            Vault.request(
                "typed_fields",
                "fields" to org.json.JSONArray(fields.map(Described::description)),
            ) as org.json.JSONArray
        data class Classified(val field: Described, val kind: String, val role: String)
        val classified =
            fields.indices.mapNotNull { i ->
                roles.optJSONObject(i)?.let {
                    Classified(fields[i], it.getString("kind"), it.getString("role"))
                }
            }
        if (classified.isEmpty()) return null
        // Fill the kind the person is typing into; otherwise prefer a card.
        val kind =
            classified.firstOrNull { it.field.focused }?.kind
                ?: if (classified.any { it.kind == "payment-card" }) "payment-card" else "identity"
        val chosen = classified.filter { it.kind == kind }
        val (origin, hostnameOnly) =
            siteOrigin(context, packageName, chosen.map { it.field.origin }, addresses)
        Log.d("PMAutofill", "Parsed typed form kind=$kind fields=${chosen.size}")
        return TypedForm(origin, hostnameOnly, kind, chosen.associate { it.field.id to it.role })
    }

    /** The app, or the single trusted-browser website, that owns every field. */
    private fun siteOrigin(
        context: Context,
        packageName: String,
        origins: List<String?>,
        addresses: List<String>,
    ): Pair<String, Boolean> {
        val domains = origins.filterNotNull().toSet()
        if (domains.isEmpty()) return CallerIdentity.appOrigin(context, packageName) to false
        if (domains.size != 1 || origins.any { it != domains.single() })
            throw Rejected("ambiguous_website_origin")
        if (!CallerIdentity.trustedBrowser(context, packageName)) throw Rejected("untrusted_browser")
        val site = CallerIdentity.browserSite(domains.single(), addresses)
        if (site.hostnameOnly && packageName != "com.android.chrome")
            throw Rejected("missing_full_website_address")
        return site.origin to site.hostnameOnly
    }

    fun read(context: Context, structure: AssistStructure): LoginForm? {
        val packageName = structure.activityComponent.packageName
        if (packageName == context.packageName) return null
        data class Field(
            val id: AutofillId,
            val user: Boolean,
            val code: Boolean,
            val value: String?,
            val origin: String?,
        )
        val fields = mutableListOf<Field>()
        val addresses = mutableListOf<String>()
        fun walk(node: AssistStructure.ViewNode, depth: Int = 0, inheritedOrigin: String? = null) {
            if (depth > 100 || fields.size > 1000 || node.visibility != View.VISIBLE) return
            val nodeOrigin = visitOrigin(node, packageName, inheritedOrigin, addresses)
            val html = node.htmlInfo?.attributes?.associate { it.first to it.second }.orEmpty()
            val hints =
                listOfNotNull(
                        node.idEntry,
                        node.hint,
                        html["autocomplete"],
                        html["type"],
                        html["name"],
                        html["id"],
                        html["label"],
                        html["ua-autofill-hints"],
                        html["computed-autofill-hints"],
                    )
                    .plus(node.autofillHints?.toList().orEmpty())
                    .joinToString(" ")
                    .lowercase()
            val role = loginRole(hints, node.inputType)
            if (role != null && node.autofillId != null)
                fields.add(
                    Field(
                        requireNotNull(node.autofillId),
                        role == LoginRole.USERNAME,
                        role == LoginRole.CODE,
                        node.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
                        nodeOrigin,
                    )
                )
            for (i in 0 until node.childCount) walk(node.getChildAt(i), depth + 1, nodeOrigin)
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        val domains = fields.mapNotNull { it.origin }.toSet()
        // Counts and fixed reason codes only: never log a structure, origin,
        // username, password, or field value.
        Log.d(
            "PMAutofill",
            "Parsed fields=${fields.size} web_origins=${domains.size} native_addresses=${addresses.size}",
        )
        var hostnameOnly = false
        val origin =
            if (domains.isEmpty()) CallerIdentity.appOrigin(context, packageName)
            else {
                if (domains.size != 1 || fields.any { it.origin != domains.single() })
                    throw Rejected("ambiguous_website_origin")
                if (!CallerIdentity.trustedBrowser(context, packageName))
                    throw Rejected("untrusted_browser")
                val site = CallerIdentity.browserSite(domains.single(), addresses)
                if (site.hostnameOnly && packageName != "com.android.chrome")
                    throw Rejected("missing_full_website_address")
                hostnameOnly = site.hostnameOnly
                site.origin
            }
        val passwords = fields.filter { !it.user && !it.code }.distinctBy { it.id }
        val users = fields.filter { it.user }.distinctBy { it.id }
        val codes = fields.filter { it.code }.distinctBy { it.id }
        if (passwords.size > 1 || users.size > 1 || codes.size > 1)
            return null // don't combine login/signup/frame partitions
        if (passwords.isEmpty() && users.isEmpty() && codes.isEmpty()) return null
        return LoginForm(
            origin,
            users.firstOrNull()?.id,
            passwords.firstOrNull()?.id,
            users.firstOrNull()?.value,
            passwords.firstOrNull()?.value,
            hostnameOnly,
            codes.firstOrNull()?.id,
        )
    }

    fun presentation(context: Context, title: String) =
        RemoteViews(context.packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, title)
        }

    fun pending(context: Context, mode: String, extras: Intent.() -> Unit = {}): PendingIntent {
        val intent =
            Intent(context, FillActivity::class.java).apply {
                action = UUID.randomUUID().toString()
                putExtra("mode", mode)
                extras()
            }
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
        )
    }
}

class VaultAutofillService : AutofillService() {
    override fun onFillRequest(
        request: FillRequest,
        signal: CancellationSignal,
        callback: FillCallback,
    ) {
        Vault.services.execute {
            if (signal.isCanceled) return@execute
            val response = runCatching {
                val structure =
                    request.fillContexts.lastOrNull()?.structure ?: return@runCatching null
                val form =
                    Forms.read(this, structure)
                        ?: return@runCatching Forms.readTyped(this, structure)?.let { typed ->
                            FillResponse.Builder()
                                .addDataset(AutofillSuggestions.typedSuggestion(this, request, typed))
                                .build()
                        }
                val scope =
                    AutofillScope(
                        structure.activityComponent.packageName,
                        form.origin,
                        form.hostnameOnly,
                    )
                val reusable =
                    Vault.autofillSession.allows(scope) &&
                        Vault.json("status").getBoolean("unlocked")
                val builder = FillResponse.Builder()
                val entries = if (reusable) AutofillSuggestions.entries(form) else null
                if (entries == null || entries.length() == 0) {
                    builder.addDataset(
                        AutofillSuggestions.suggestion(
                            this,
                            request,
                            form,
                            0,
                            if (reusable) "Choose account"
                            else
                                "Unlock to fill " +
                                    (runCatching { java.net.URI(form.origin).host }
                                            .getOrNull()
                                            ?.removePrefix("www.") ?: "this app"),
                            "Password Manager",
                        )
                    )
                } else {
                    val capacity =
                        if (android.os.Build.VERSION.SDK_INT >= 30)
                            request.inlineSuggestionsRequest?.maxSuggestionCount?.coerceIn(1, 20)
                                ?: 20
                        else 20
                    val more = entries.length() > capacity
                    val count = if (more) capacity - 1 else entries.length()
                    for (i in 0 until count) {
                        val entry = entries.getJSONObject(i)
                        val origin = AutofillSuggestions.origin(form, entry)
                        val port = java.net.URI(origin).port
                        val name = entry.getString("name")
                        val username = entry.opt("username") as? String ?: ""
                        val subtitle =
                            (if (port > 0 && port != 443) "Port $port · " else "") +
                                (if (form.codeOnly) "One-time code · " else "") +
                                name
                        builder.addDataset(
                            AutofillSuggestions.suggestion(
                                this,
                                request,
                                form,
                                i,
                                username.ifBlank { name },
                                subtitle,
                                entry,
                            )
                        )
                    }
                    if (more)
                        builder.addDataset(
                            AutofillSuggestions.suggestion(
                                this,
                                request,
                                form,
                                count,
                                "More accounts",
                                "Password Manager",
                            )
                        )
                }
                form.password?.let { password ->
                    builder.setSaveInfo(
                        SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(password))
                            .apply { form.username?.let { setOptionalIds(arrayOf(it)) } }
                            .build()
                    )
                }
                Log.d(
                    "PMAutofill",
                    "Suggestions prepared: unlocked=$reusable code_only=${form.codeOnly}",
                )
                builder.build()
            }
                .onFailure { error ->
                    Log.w(
                        "PMAutofill",
                        "Fill rejected: ${(error as? Forms.Rejected)?.reason ?: error.javaClass.simpleName}",
                    )
                }
                .getOrNull()
            if (!signal.isCanceled) callback.onSuccess(response)
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Vault.services.execute {
            runCatching {
                val structure =
                    request.fillContexts.lastOrNull()?.structure ?: error("Missing login form")
                val form = Forms.read(this, structure) ?: error("Unsupported login form")
                check(!form.passwordValue.isNullOrEmpty()) { "No password to save" }
                val pending =
                    Forms.pending(this, "save") {
                        putExtra("origin", form.origin)
                        putExtra("hostname_only", form.hostnameOnly)
                        putExtra("username", form.userValue.orEmpty())
                        putExtra("password", form.passwordValue)
                    }
                callback.onSuccess(pending.intentSender)
            }
                .onFailure { callback.onFailure("Could not prepare login saving") }
        }
    }
}
