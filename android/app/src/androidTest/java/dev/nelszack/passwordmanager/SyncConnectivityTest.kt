package dev.nelszack.passwordmanager

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in transport diagnostic: no personal vault or saved credential is opened. */
@RunWith(AndroidJUnit4::class)
class SyncConnectivityTest {
    @Test fun certificateStatusNetworkPolicyIsPackaged() {
        val policy = android.security.NetworkSecurityPolicy.getInstance()
        assertFalse(policy.isCleartextTrafficPermitted("example.com"))
        assertTrue(policy.isCleartextTrafficPermitted("ye2.c.lencr.org"))
    }

    @Test fun serverRejectsDummyCredentialOverHttps() {
        val server = InstrumentationRegistry.getArguments().getString("syncServer").orEmpty()
        assumeTrue("Supply -e syncServer with an HTTPS server origin", server.isNotBlank())
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = context.cacheDir.resolve("sync-transport-diagnostic")
        try {
            val request = JSONObject().put("op", "cloud_list").put("server", server)
                .put("token", "0".repeat(64))
            val reply = JSONObject(NativeBridge.call(context, directory.absolutePath, request.toString()))
            assertFalse("The diagnostic token must not authorize access", reply.getBoolean("ok"))
            assertEquals(reply.optString("error"), "Sync device is unauthorized or revoked", reply.optString("error"))
        } finally {
            directory.deleteRecursively()
        }
    }
}
