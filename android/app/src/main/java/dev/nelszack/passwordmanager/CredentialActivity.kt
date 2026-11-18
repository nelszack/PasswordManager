package dev.nelszack.passwordmanager

import android.content.Intent
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.credentials.*
import androidx.credentials.exceptions.*
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.provider.PendingIntentHandler
import org.json.JSONArray
import org.json.JSONObject

@RequiresApi(34)
class CredentialActivity : VaultActivity() {
    private var handlingCredential = false

    private fun clientHash(origin: String, hash: ByteArray?): String? {
        if (!origin.startsWith("https://")) return null
        check(hash != null && hash.size == 32) {
            "The browser did not provide a valid client-data hash"
        }
        return DeviceKeys.encode(hash)
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setResult(RESULT_CANCELED)
        unlock({ guarded { handle() } }, fresh = true)
    }

    private fun handle() {
        handlingCredential = true
        when (intent.getStringExtra("mode")) {
            "unlock" -> {
                val request =
                    PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
                        ?: return finish()
                task({ VaultCredentialService.entries(this, request) }) { response ->
                    val result = Intent()
                    PendingIntentHandler.setBeginGetCredentialResponse(result, response)
                    setResult(RESULT_OK, result)
                    finish()
                }
            }
            "create" -> create()
            "get" -> get()
            else -> finish()
        }
    }

    override fun showFailure(error: Throwable) {
        if (!handlingCredential) {
            super.showFailure(error)
            return
        }
        val result = Intent()
        if (intent.getStringExtra("mode") == "create") {
            val exception =
                when {
                    error.message == "CredentialExcluded" ->
                        CreatePublicKeyCredentialDomException(InvalidStateError())
                    error.message?.contains("supported", ignoreCase = true) == true ->
                        CreatePublicKeyCredentialDomException(NotSupportedError())
                    else -> CreateCredentialUnknownException("Could not create credential")
                }
            PendingIntentHandler.setCreateCredentialException(result, exception)
        } else
            PendingIntentHandler.setGetCredentialException(
                result,
                GetCredentialUnknownException("Could not retrieve credential"),
            )
        setResult(RESULT_OK, result)
        finish()
    }

    private fun create() {
        val provider =
            PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return finish()
        when (val request = provider.callingRequest) {
            is CreatePublicKeyCredentialRequest -> {
                val options = JSONObject(request.requestJson)
                val rp = options.getJSONObject("rp").getString("id")
                task({ CallerIdentity.passkeyOrigin(this, provider.callingAppInfo, rp) }) { origin
                    ->
                    page("Create passkey")
                    label(
                        "Website: $rp\nRequested by: $origin\nAccount: ${options.getJSONObject("user").getString("name")}"
                    )
                    button("Create and save passkey") {
                        task({
                            val response =
                                Vault.request(
                                    "passkey_create",
                                    "origin" to origin,
                                    "request" to options,
                                    "client_hash" to clientHash(origin, request.clientDataHash),
                                ) as JSONObject
                            syncAfterChange()
                            response
                        }) { response ->
                            val result = Intent()
                            PendingIntentHandler.setCreateCredentialResponse(
                                result,
                                CreatePublicKeyCredentialResponse(response.toString()),
                            )
                            setResult(RESULT_OK, result)
                            finish()
                        }
                    }
                    button("Cancel") { finish() }
                }
            }
            is CreatePasswordRequest -> {
                task({ CallerIdentity.passwordOrigin(this, provider.callingAppInfo) }) { origin ->
                    page("Save login")
                    label("Website or app: $origin\nAccount: ${request.id}")
                    val name = edit("Login name", origin)
                    button("Save login") {
                        val title = name.text.toString()
                        task({
                            Vault.command(
                                VaultCommands.add(
                                    title,
                                    request.id,
                                    request.password,
                                    listOf(origin),
                                )
                            )
                            syncAfterChange()
                        }) {
                            val result = Intent()
                            PendingIntentHandler.setCreateCredentialResponse(
                                result,
                                CreatePasswordResponse(),
                            )
                            setResult(RESULT_OK, result)
                            finish()
                        }
                    }
                    button("Cancel") { finish() }
                }
            }
            else -> {
                val result = Intent()
                PendingIntentHandler.setCreateCredentialException(
                    result,
                    CreateCredentialUnsupportedException(),
                )
                setResult(RESULT_OK, result)
                finish()
            }
        }
    }

    private fun get() {
        val provider =
            PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return finish()
        val id = intent.getLongExtra("id", -1L)
        check(id > 0) { "Missing selected credential" }
        val publicKey =
            provider.credentialOptions
                .filterIsInstance<GetPublicKeyCredentialOption>()
                .firstOrNull()
        if (publicKey != null) {
            val options = JSONObject(publicKey.requestJson)
            val rp = options.getString("rpId")
            task({
                val origin = CallerIdentity.passkeyOrigin(this, provider.callingAppInfo, rp)
                val keys = Vault.request("passkeys", "request" to options) as JSONArray
                check((0 until keys.length()).any { keys.getJSONObject(it).getLong("id") == id }) {
                    "Selected passkey does not match the request"
                }
                origin
            }) { origin ->
                page("Sign in with passkey")
                label("Website: $rp\nRequested by: $origin")
                button("Approve sign-in") {
                    task({
                        Vault.request(
                            "passkey_get",
                            "id" to id,
                            "request" to options,
                            "origin" to origin,
                            "client_hash" to clientHash(origin, publicKey.clientDataHash),
                        ) as JSONObject
                    }) { response ->
                        val result = Intent()
                        PendingIntentHandler.setGetCredentialResponse(
                            result,
                            GetCredentialResponse(PublicKeyCredential(response.toString())),
                        )
                        setResult(RESULT_OK, result)
                        finish()
                    }
                }
                button("Cancel") { finish() }
            }
        } else {
            val option =
                provider.credentialOptions.filterIsInstance<GetPasswordOption>().firstOrNull()
                    ?: return finish()
            task({
                val origin = CallerIdentity.passwordOrigin(this, provider.callingAppInfo)
                val login = Vault.json("login", "origin" to origin, "id" to id)
                check(
                    option.allowedUserIds.isEmpty() ||
                        login.getString("username") in option.allowedUserIds
                ) {
                    "Login is excluded by the requester"
                }
                origin to login
            }) { (origin, login) ->
                page("Sign in")
                label("Website or app: $origin\nAccount: ${login.getString("username")}")
                button("Fill selected login") {
                    task({ Vault.json("login", "origin" to origin, "id" to id) }) { current ->
                        val result = Intent()
                        PendingIntentHandler.setGetCredentialResponse(
                            result,
                            GetCredentialResponse(
                                PasswordCredential(
                                    current.getString("username"),
                                    current.getString("password"),
                                )
                            ),
                        )
                        setResult(RESULT_OK, result)
                        finish()
                    }
                }
                button("Cancel") { finish() }
            }
        }
    }
}
