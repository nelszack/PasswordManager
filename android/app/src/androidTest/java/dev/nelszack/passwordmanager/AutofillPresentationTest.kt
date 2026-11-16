package dev.nelszack.passwordmanager

import android.content.Intent
import android.os.Bundle
import android.util.Size
import android.view.Gravity
import android.view.WindowManager
import android.widget.inline.InlinePresentationSpec
import android.view.inputmethod.InlineSuggestionsRequest
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Run alone. Only synthetic vault/cache data and suggestion metadata are used. */
@RunWith(AndroidJUnit4::class)
class AutofillPresentationTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("presentation")
    }
    @Test fun inlineNegotiationAndCompactSecureUnlockSheet() {
        vault.requireUnlocked()
        val instrumentation = vault.instrumentation
        val context = vault.context
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            val style = UiVersions.newStylesBuilder().addStyle(InlineSuggestionUi.newStyleBuilder().build()).build()
            fun request(bundle: Bundle) = InlineSuggestionsRequest.Builder(listOf(
                InlinePresentationSpec.Builder(Size(0,0), Size(600,120)).setStyle(bundle).build()
            )).setMaxSuggestionCount(1).build()
            val pending = Forms.pending(context, "fill")
            val presentation = AutofillSuggestions.inlinePresentation(context, request(style), 0, pending, "Synthetic account", "Port 8443")
            assertNotNull(presentation)
            val content = requireNotNull(InlineSuggestionUi.fromSlice(requireNotNull(presentation).slice))
            assertEquals("Synthetic account", content.title.toString())
            assertEquals("Port 8443", content.subtitle.toString())
            assertNull(AutofillSuggestions.inlinePresentation(context, request(style), 1, pending, "Account", "Saved"))
            assertNull(AutofillSuggestions.inlinePresentation(context, request(Bundle.EMPTY), 0, pending, "Account", "Saved"))
        }
        Vault.request("create", "password" to "Synthetic-Presentation-Vault-9274!")
        val intent = Intent(context, FillActivity::class.java).putExtra("mode", "save")
            .putExtra("origin", "https://example.com").putExtra("username", "synthetic")
            .putExtra("password", "synthetic")
        val scenario = vault.launch<FillActivity>(intent)
        repeat(3) { vault.drain() }
        instrumentation.waitForIdleSync()
        val deadline = android.os.SystemClock.elapsedRealtime() + 10000
        var measured = false
        while (!measured && android.os.SystemClock.elapsedRealtime() < deadline) {
            scenario.onActivity { measured = it.window.decorView.height > 100 }
            if (!measured) Thread.sleep(100)
        }
        scenario.onActivity { activity ->
            assertEquals(Gravity.BOTTOM, activity.window.attributes.gravity and Gravity.VERTICAL_GRAVITY_MASK)
            assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            assertTrue(activity.window.decorView.height > 100)
            assertTrue(activity.window.decorView.height < activity.resources.displayMetrics.heightPixels * 0.85)
        }
    }
}
