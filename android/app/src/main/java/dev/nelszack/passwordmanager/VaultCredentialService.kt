package dev.nelszack.passwordmanager

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.*
import androidx.credentials.provider.*
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

@RequiresApi(34)
class VaultCredentialService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        signal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (signal.isCanceled) return
        if (
            request !is BeginCreatePublicKeyCredentialRequest &&
                request !is BeginCreatePasswordCredentialRequest
        ) {
            callback.onError(CreateCredentialUnsupportedException("Unsupported credential type"))
            return
        }
        callback.onResult(
            BeginCreateCredentialResponse(
                listOf(CreateEntry("Encrypted vault", pending(this, "create")))
            )
        )
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        signal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        Vault.services.execute {
            if (signal.isCanceled) return@execute
            runCatching {
                    if (!Vault.json("status").getBoolean("unlocked"))
                        BeginGetCredentialResponse(
                            authenticationActions =
                                listOf(
                                    AuthenticationAction(
                                        "Unlock Password Manager",
                                        pending(this, "unlock"),
                                    )
                                )
                        )
                    else entries(this, request)
                }
                .fold(
                    { if (!signal.isCanceled) callback.onResult(it) },
                    {
                        if (!signal.isCanceled)
                            callback.onError(
                                GetCredentialUnknownException("Could not query the encrypted vault")
                            )
                    },
                )
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        signal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        Vault.lock()
        callback.onResult(null)
    }

    companion object {
        fun pending(context: Context, mode: String, id: Long? = null): PendingIntent =
            PendingIntent.getActivity(
                context,
                0,
                Intent(context, CredentialActivity::class.java).apply {
                    action = UUID.randomUUID().toString()
                    putExtra("mode", mode)
                    id?.let { putExtra("id", it) }
                },
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
            )

        fun entries(
            context: Context,
            request: BeginGetCredentialRequest,
        ): BeginGetCredentialResponse {
            val entries = mutableListOf<CredentialEntry>()
            for (option in request.beginGetCredentialOptions) {
                when (option) {
                    is BeginGetPublicKeyCredentialOption -> {
                        val options = JSONObject(option.requestJson)
                        val keys = Vault.request("passkeys", "request" to options) as JSONArray
                        for (i in 0 until keys.length()) {
                            val key = keys.getJSONObject(i)
                            entries.add(
                                PublicKeyCredentialEntry(
                                    context = context,
                                    username = key.getString("user_name"),
                                    pendingIntent = pending(context, "get", key.getLong("id")),
                                    beginGetPublicKeyCredentialOption = option,
                                    displayName = key.getString("display_name"),
                                )
                            )
                        }
                    }
                    is BeginGetPasswordOption -> {
                        val info = request.callingAppInfo ?: continue
                        val origin = CallerIdentity.passwordOrigin(context, info)
                        val logins = Vault.request("logins", "origin" to origin) as JSONArray
                        for (i in 0 until logins.length()) {
                            val login = logins.getJSONObject(i)
                            val username = login.optString("username", "")
                            if (
                                username.isEmpty() ||
                                    (option.allowedUserIds.isNotEmpty() &&
                                        username !in option.allowedUserIds)
                            )
                                continue
                            entries.add(
                                PasswordCredentialEntry(
                                    context = context,
                                    username = username,
                                    pendingIntent = pending(context, "get", login.getLong("id")),
                                    beginGetPasswordOption = option,
                                    displayName = login.getString("name"),
                                )
                            )
                        }
                    }
                }
            }
            return BeginGetCredentialResponse(credentialEntries = entries)
        }
    }
}
