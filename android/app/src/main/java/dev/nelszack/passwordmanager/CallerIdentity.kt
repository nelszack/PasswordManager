package dev.nelszack.passwordmanager

import android.content.Context
import android.content.pm.PackageManager
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

object CallerIdentity {
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun fingerprints(context: Context, packageName: String): List<ByteArray> {
        val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        return requireNotNull(info.signingInfo).apkContentsSigners.map { digest(it.toByteArray()) }
    }
    fun allowlist(context: Context): String {
        val original = JSONObject(context.assets.open("trusted-browsers.json").bufferedReader().use { it.readText() })
        val apps = original.getJSONArray("apps")
        for (i in 0 until apps.length()) {
            val info = apps.getJSONObject(i).getJSONObject("info")
            val signatures = info.getJSONArray("signatures")
            val release = JSONArray()
            for (j in 0 until signatures.length()) if (signatures.getJSONObject(j).optString("build") == "release") release.put(signatures.getJSONObject(j))
            info.put("signatures", release)
        }
        return original.toString()
    }
    fun trustedBrowser(context: Context, packageName: String): Boolean {
        val certs = fingerprints(context, packageName).map { it.joinToString(":") { b -> "%02X".format(b) } }
        val apps = JSONObject(allowlist(context)).getJSONArray("apps")
        for (i in 0 until apps.length()) {
            val info = apps.getJSONObject(i).getJSONObject("info")
            if (info.getString("package_name") == packageName) {
                val signatures = info.getJSONArray("signatures")
                return signatures.length() > 0 && certs.all { hash ->
                    (0 until signatures.length()).any { signatures.getJSONObject(it).getString("cert_fingerprint_sha256") == hash }
                }
            }
        }
        return false
    }
    fun appOrigin(context: Context, packageName: String): String {
        val certs = fingerprints(context, packageName)
        check(certs.size == 1) { "Multiple-signature apps require explicit support" }
        return "androidapp://$packageName/${DeviceKeys.encode(certs.single())}"
    }
    fun websiteOrigin(value: String): String {
        val uri = URI(value)
        check(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null && (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")) { "A valid HTTPS origin is required" }
        return "https://${uri.host}" + if (uri.port != -1 && uri.port != 443) ":${uri.port}" else ""
    }
    fun addressBarOrigin(value: String, reportedOrigin: String): String {
        val uri = URI(if (value.startsWith("https://")) value else "https://$value")
        check(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null) { "Invalid browser address" }
        val origin = websiteOrigin("https://${uri.rawAuthority}")
        check(URI(origin).host == URI(reportedOrigin).host) { "Browser address does not match the form" }
        return origin
    }
    fun passwordOrigin(context: Context, info: CallingAppInfo): String =
        info.getOrigin(allowlist(context))?.let(::websiteOrigin) ?: appOrigin(context, info.packageName)

    // Must run on the worker. Delegated origins are checked by CallingAppInfo;
    // native applications prove their RP association through HTTPS asset links.
    fun passkeyOrigin(context: Context, info: CallingAppInfo, rpId: String): String {
        info.getOrigin(allowlist(context))?.let { return websiteOrigin(it) }
        check(Regex("[a-z0-9.-]+").matches(rpId) && !rpId.startsWith('.') && !rpId.endsWith('.')) { "Invalid RP ID" }
        val certs = fingerprints(context, info.packageName)
        check(certs.size == 1) { "Multiple-signature apps require explicit support" }
        val hash = certs.single().joinToString(":") { "%02X".format(it) }
        val connection = URL("https://$rpId/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false; connection.connectTimeout = 10000; connection.readTimeout = 10000
            check(connection.responseCode == 200) { "Could not verify website/app association" }
            val data = connection.inputStream.use { it.readBounded(256 * 1024) }
            check(data.size <= 256 * 1024) { "Website association file exceeds limit" }
            val links = JSONArray(data.toString(Charsets.UTF_8))
            check((0 until links.length()).any { i ->
                val link = links.getJSONObject(i); val target = link.optJSONObject("target")
                val relations = link.optJSONArray("relation") ?: JSONArray()
                val fingerprints = target?.optJSONArray("sha256_cert_fingerprints") ?: JSONArray()
                target?.optString("namespace") == "android_app" && target.optString("package_name") == info.packageName &&
                    (0 until relations.length()).any { relations.getString(it) == "delegate_permission/common.get_login_creds" } &&
                    (0 until fingerprints.length()).any { fingerprints.getString(it).equals(hash, true) }
            }) { "This app is not authorized for the requested website" }
            return "android:apk-key-hash:${DeviceKeys.encode(certs.single())}"
        } finally { connection.disconnect() }
    }
}
