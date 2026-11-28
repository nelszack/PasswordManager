package dev.nelszack.passwordmanager

import android.app.PendingIntent
import android.content.Context
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillRequest
import android.service.autofill.InlinePresentation
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

internal object AutofillSuggestions {
    fun entries(form: LoginForm): JSONArray =
        when {
            form.codeOnly ->
                Vault.request(
                    "otp_logins",
                    "origin" to form.origin,
                    "hostname_only" to form.hostnameOnly,
                )
            form.hostnameOnly -> Vault.request("hostname_logins", "origin" to form.origin)
            else -> Vault.request("logins", "origin" to form.origin)
        }
            as JSONArray

    fun origin(form: LoginForm, entry: JSONObject): String {
        if (!form.hostnameOnly) return form.origin
        val origin = CallerIdentity.websiteOrigin(entry.getString("origin"))
        check(
            java.net
                .URI(origin)
                .host
                .trimEnd('.')
                .equals(java.net.URI(form.origin).host.trimEnd('.'), true)
        ) {
            "Login hostname mismatch"
        }
        return origin
    }

    fun token(id: Long, name: String, username: String, origin: String): String {
        val fields = listOf(id.toString(), name, username, origin)
        val encoded = fields.joinToString("") { "${it.length}:$it" }
        return MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray()).joinToString("") {
            "%02x".format(it)
        }
    }

    fun token(form: LoginForm, entry: JSONObject) =
        token(
            entry.getLong("id"),
            entry.getString("name"),
            entry.opt("username") as? String ?: "",
            origin(form, entry),
        )

    fun suggestion(
        context: Context,
        request: FillRequest,
        form: LoginForm,
        index: Int,
        title: String,
        subtitle: String,
        selected: JSONObject? = null,
    ): Dataset {
        val pending =
            Forms.pending(context, "fill") {
                if (selected != null) {
                    putExtra("selected_id", selected.getLong("id"))
                    putExtra(
                        "selected_vault",
                        context
                            .getSharedPreferences("settings", Context.MODE_PRIVATE)
                            .getString("vault", ""),
                    )
                    putExtra("selection_token", token(form, selected))
                }
            }
        return authenticated(context, request, form.ids, index, pending, title, subtitle)
    }

    /** One suggestion that opens the card or identity chooser; it carries no values. */
    fun typedSuggestion(context: Context, request: FillRequest, form: TypedForm): Dataset {
        val pending = Forms.pending(context, "typed")
        val title = if (form.card) "Fill a saved card" else "Fill a saved identity"
        return authenticated(context, request, form.ids, 0, pending, title, "Password Manager")
    }

    /** Matches any value, so a suggestion applies to its fields without holding their values. */
    private val ANY_VALUE = java.util.regex.Pattern.compile(".*", java.util.regex.Pattern.DOTALL)

    /**
     * A suggestion for [ids] that opens [pending] when tapped. No secrets are given to the
     * framework before the user taps a suggestion.
     */
    private fun authenticated(
        context: Context,
        request: FillRequest,
        ids: Array<android.view.autofill.AutofillId>,
        index: Int,
        pending: PendingIntent,
        title: String,
        subtitle: String,
    ): Dataset {
        val dataset =
            Dataset.Builder(Forms.presentation(context, "$title\n$subtitle"))
                .setAuthentication(pending.intentSender)
        ids.forEach { dataset.setValue(it, null, ANY_VALUE) }
        if (Build.VERSION.SDK_INT >= 30)
            inlinePresentation(context, request.inlineSuggestionsRequest, index, pending, title, subtitle)
                ?.let { dataset.setInlinePresentation(it) }
        return dataset.build()
    }

    @RequiresApi(30)
    fun inlinePresentation(
        context: Context,
        request: android.view.inputmethod.InlineSuggestionsRequest?,
        index: Int,
        pending: PendingIntent,
        title: String,
        subtitle: String,
    ): InlinePresentation? {
        val inline = request ?: return null
        if (index >= inline.maxSuggestionCount || inline.inlinePresentationSpecs.isEmpty())
            return null
        val spec =
            inline.inlinePresentationSpecs[
                    index.coerceAtMost(inline.inlinePresentationSpecs.lastIndex)]
        if (UiVersions.INLINE_UI_VERSION_1 !in UiVersions.getVersions(spec.style)) return null
        return runCatching {
            val content: UiVersions.Content =
                InlineSuggestionUi.newContentBuilder(pending)
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setStartIcon(Icon.createWithResource(context, R.drawable.ic_key))
                    .setContentDescription("$title, $subtitle, Password Manager")
                    .build()
            InlinePresentation(content.slice, spec, false)
        }
            .getOrNull()
    }
}
