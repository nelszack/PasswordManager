package dev.nelszack.passwordmanager

import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.credentials.provider.CallingAppInfo
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import org.json.JSONArray
import org.json.JSONObject

object CallerIdentity {
    data class BrowserSite(val origin: String, val hostnameOnly: Boolean)

    /** The bundled browser allowlist, reduced to release signatures, parsed once. */
    private class Allowlist(val json: String, val signatures: Map<String, Set<String>>)

    /** Signing-certificate digests, valid while the installed package is unchanged. */
    private class Signers(
        val version: Long,
        val installed: Long,
        val updated: Long,
        val digests: List<ByteArray>,
    )

    /** An asset-links verdict; [error] is null when the app is authorized. */
    private class Association(val error: String?, val until: Long)

    private const val MAX_CACHED = 64
    private const val ASSOCIATED_MS = 60 * 60 * 1000L
    private const val REFUSED_MS = 3 * 60 * 1000L

    @Volatile private var parsedAllowlist: Allowlist? = null
    private val signers = bounded<Signers>()
    private val associations = bounded<Association>()

    private fun <V> bounded(): MutableMap<String, V> =
        object : LinkedHashMap<String, V>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, V>?) =
                size > MAX_CACHED
        }

    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hex(digest: ByteArray) = digest.joinToString(":") { "%02X".format(it) }

    private fun fingerprints(context: Context, packageName: String): List<ByteArray> {
        val manager = context.packageManager
        val current = manager.getPackageInfo(packageName, 0)
        synchronized(signers) {
            signers[packageName]
                ?.takeIf {
                    it.version == current.longVersionCode &&
                        it.installed == current.firstInstallTime &&
                        it.updated == current.lastUpdateTime
                }
                ?.let {
                    return it.digests
                }
        }
        val info = manager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val digests =
            requireNotNull(info.signingInfo).apkContentsSigners.map { digest(it.toByteArray()) }
        synchronized(signers) {
            signers[packageName] =
                Signers(info.longVersionCode, info.firstInstallTime, info.lastUpdateTime, digests)
        }
        return digests
    }

    private fun trusted(context: Context): Allowlist =
        parsedAllowlist
            ?: synchronized(this) {
                parsedAllowlist
                    ?: run {
                        val original =
                            JSONObject(
                                context.assets.open("trusted-browsers.json").bufferedReader().use {
                                    it.readText()
                                }
                            )
                        val apps = original.getJSONArray("apps")
                        val signatures = mutableMapOf<String, Set<String>>()
                        for (i in 0 until apps.length()) {
                            val info = apps.getJSONObject(i).getJSONObject("info")
                            val all = info.getJSONArray("signatures")
                            val release = JSONArray()
                            for (j in 0 until all.length()) if (
                                all.getJSONObject(j).optString("build") == "release"
                            )
                                release.put(all.getJSONObject(j))
                            info.put("signatures", release)
                            // The first entry for a package decides, as before.
                            val packageName = info.getString("package_name")
                            if (packageName !in signatures)
                                signatures[packageName] =
                                    (0 until release.length())
                                        .map {
                                            release
                                                .getJSONObject(it)
                                                .getString("cert_fingerprint_sha256")
                                        }
                                        .toSet()
                        }
                        Allowlist(original.toString(), signatures).also { parsedAllowlist = it }
                    }
            }

    fun allowlist(context: Context): String = trusted(context).json

    fun trustedBrowser(context: Context, packageName: String): Boolean {
        val signatures = trusted(context).signatures[packageName] ?: return false
        return signatures.isNotEmpty() &&
            fingerprints(context, packageName).all { hex(it) in signatures }
    }

    fun appOrigin(context: Context, packageName: String): String {
        val certs = fingerprints(context, packageName)
        check(certs.size == 1) { "Multiple-signature apps require explicit support" }
        return "androidapp://$packageName/${DeviceKeys.encode(certs.single())}"
    }

    fun websiteOrigin(value: String): String {
        val uri = URI(value)
        check(
            uri.scheme == "https" &&
                uri.host != null &&
                uri.rawUserInfo == null &&
                uri.rawQuery == null &&
                uri.rawFragment == null &&
                (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")
        ) {
            "A valid HTTPS origin is required"
        }
        return "https://${uri.host}" + if (uri.port != -1 && uri.port != 443) ":${uri.port}" else ""
    }

    fun addressBarOrigin(value: String, reportedOrigin: String): String {
        val uri = URI(if (value.startsWith("https://")) value else "https://$value")
        check(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null) {
            "Invalid browser address"
        }
        val origin = websiteOrigin("https://${uri.rawAuthority}")
        check(URI(origin).host == URI(reportedOrigin).host) {
            "Browser address does not match the form"
        }
        return origin
    }

    fun browserSite(reportedOrigin: String, nativeAddresses: List<String>): BrowserSite {
        val reported = websiteOrigin(reportedOrigin)
        if (nativeAddresses.isEmpty()) return BrowserSite(reported, true)
        // Conflicting native evidence must never fall back to hostname matching.
        val origins = nativeAddresses.map { addressBarOrigin(it, reported) }.toSet()
        check(origins.size == 1) { "Ambiguous native browser address" }
        return BrowserSite(origins.single(), false)
    }

    fun passwordOrigin(context: Context, info: CallingAppInfo): String =
        info.getOrigin(allowlist(context))?.let(::websiteOrigin)
            ?: appOrigin(context, info.packageName)

    // Must run off the main thread. Delegated origins are checked by CallingAppInfo;
    // native applications prove their RP association through HTTPS asset links.
    fun passkeyOrigin(context: Context, info: CallingAppInfo, rpId: String): String {
        info.getOrigin(allowlist(context))?.let {
            return websiteOrigin(it)
        }
        check(Regex("[a-z0-9.-]+").matches(rpId) && !rpId.startsWith('.') && !rpId.endsWith('.')) {
            "Invalid RP ID"
        }
        val certs = fingerprints(context, info.packageName)
        check(certs.size == 1) { "Multiple-signature apps require explicit support" }
        association(rpId, info.packageName, hex(certs.single()))?.let { error(it) }
        return "android:apk-key-hash:${DeviceKeys.encode(certs.single())}"
    }

    /**
     * Why [packageName] signed with [hash] may not use [rpId]'s passkeys, or null if it may. A
     * verdict is reused for an hour, a refusal for a few minutes; network failures are not cached.
     */
    private fun association(rpId: String, packageName: String, hash: String): String? {
        val key = "$rpId\n$packageName\n$hash"
        val now = SystemClock.elapsedRealtime()
        synchronized(associations) {
            associations[key]
                ?.takeIf { it.until > now }
                ?.let {
                    return it.error
                }
        }
        val error = fetchAssociation(rpId, packageName, hash)
        synchronized(associations) {
            associations[key] =
                Association(error, now + if (error == null) ASSOCIATED_MS else REFUSED_MS)
        }
        return error
    }

    private fun fetchAssociation(rpId: String, packageName: String, hash: String): String? {
        val connection =
            URL("https://$rpId/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            if (connection.responseCode != 200) return "Could not verify website/app association"
            val data = connection.inputStream.use { it.readBounded(256 * 1024) }
            check(data.size <= 256 * 1024) { "Website association file exceeds limit" }
            val links = JSONArray(data.toString(Charsets.UTF_8))
            val authorized =
                (0 until links.length()).any { i ->
                    val link = links.getJSONObject(i)
                    val target = link.optJSONObject("target")
                    val relations = link.optJSONArray("relation") ?: JSONArray()
                    val fingerprints =
                        target?.optJSONArray("sha256_cert_fingerprints") ?: JSONArray()
                    target?.optString("namespace") == "android_app" &&
                        target.optString("package_name") == packageName &&
                        (0 until relations.length()).any {
                            relations.getString(it) == "delegate_permission/common.get_login_creds"
                        } &&
                        (0 until fingerprints.length()).any {
                            fingerprints.getString(it).equals(hash, true)
                        }
                }
            return if (authorized) null else "This app is not authorized for the requested website"
        } finally {
            connection.disconnect()
        }
    }
}
