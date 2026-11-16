package dev.nelszack.passwordmanager

import android.app.AlertDialog
import android.app.Dialog
import android.view.*
import android.widget.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith

/** Actual MainActivity flows, cache-only vault, no sync, clipboard writes or personal files. Run alone. */
@RunWith(AndroidJUnit4::class)
class MobileRedesignTest {
    companion object {
        @org.junit.ClassRule @JvmField val vault = SyntheticVaultRule("redesign")
    }
    @After fun resetPreviewConfiguration() {
        MobileRedesignFixtureActivity.previewNight=null
        MobileRedesignFixtureActivity.previewFontScale=null
    }
    @Test fun searchFiltersSecretControlsSettingsAndDraftRecoveryWork() {
        vault.requireUnlocked()
        val instrumentation = vault.instrumentation
        val context = vault.context
        Vault.request("create","password" to "Synthetic-Redesign-Vault-9274!")
        for((name,kind) in listOf("Maple Mail" to "login","Code Garden" to "login","Recovery note" to "secure-note"))
            Vault.request("save_item","name" to name,"kind" to kind,"username" to "synthetic@example.test","password" to "synthetic-only-password",
                "urls" to JSONArray(listOf("https://example.test")),"notes" to "Synthetic notes")
        val args=InstrumentationRegistry.getArguments()
        MobileRedesignFixtureActivity.previewNight=when(args.getString("uiTheme")) { "dark"->true; "light"->false; else->null }
        MobileRedesignFixtureActivity.previewFontScale=args.getString("uiScale")?.toFloat() ?: context.resources.configuration.fontScale
        val capture=args.getString("captureUi")=="true"
        val scenario=vault.launch(MobileRedesignFixtureActivity::class.java)
        val screen = SyntheticScreen(scenario, vault)
        fun dialog(): AlertDialog {
            var result: AlertDialog?=null
            scenario.onActivity { activity ->
                @Suppress("UNCHECKED_CAST")
                val list=ManagementActivity::class.java.getDeclaredField("dialogs").apply { isAccessible=true }.get(activity) as List<Dialog>
                result=list.filterIsInstance<AlertDialog>().last()
            }
            return requireNotNull(result)
        }
        fun capture(name: String) {
            if(!capture) return
            assertTrue("Screenshots are limited to the isolated emulator",android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
            scenario.onActivity { it.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
            instrumentation.waitForIdleSync(); Thread.sleep(200)
            val bitmap=requireNotNull(instrumentation.uiAutomation.takeScreenshot())
            val file=context.cacheDir.resolve("redesign-${args.getString("uiTheme") ?: "system"}-$name.png")
            file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,it) }; bitmap.recycle()
        }
        screen.waitFor("3 items in your vault")
        scenario.onActivity { assertTrue(it.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0) }
        capture("vault")
        screen.input("Search your vault","maple"); screen.waitFor("1 item found")
        screen.input("Search your vault",""); screen.waitFor("3 items in your vault")
        screen.click("Notes"); screen.waitFor("1 item found"); screen.waitFor("Recovery note")
        screen.click("All"); screen.waitFor("3 items in your vault")
        screen.click("Maple Mail"); screen.waitFor("Item details")
        scenario.onActivity { a -> assertFalse(screen.views(a.window.decorView).filterIsInstance<TextView>().any { it.text.toString()=="synthetic-only-password" }) }
        capture("item")
        screen.click("Show password"); screen.waitFor("synthetic-only-password")
        screen.click("Hide password"); screen.waitFor("Show password")
        screen.back(); screen.waitFor("3 items in your vault")
        screen.click("Tools"); screen.waitFor("Everyday tools"); capture("tools")
        screen.click("Mobile settings"); screen.waitFor("5 minutes"); screen.waitFor("Age-based purging is off"); capture("preferences")
        screen.click("Lock after inactivity")
        val settingsDialog=dialog()
        instrumentation.runOnMainSync {
            val number=screen.views(settingsDialog.window!!.decorView).filterIsInstance<EditText>().single()
            number.setText("900")
            assertTrue(screen.views(settingsDialog.window!!.decorView).any { screen.matches(it,"15 minutes") })
            settingsDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
        }
        assertEquals(300,Vault.json("settings_get").getInt("unlock_seconds"))
        screen.back(); screen.waitFor("Tools & recovery")
        screen.click("Vault"); screen.waitFor("3 items in your vault")
        screen.click("Add item"); screen.input("Name","Draft only")
        screen.back(); val discard=dialog()
        instrumentation.runOnMainSync { discard.getButton(AlertDialog.BUTTON_NEGATIVE).performClick() }
        scenario.onActivity { a->assertEquals("Draft only",screen.views(a.window.decorView).filterIsInstance<EditText>().first { it.hint?.toString()=="Name" }.text.toString()) }
        screen.input("Name",""); screen.input("Password / primary secret","synthetic-draft-password")
        screen.click("Save item")
        val end=android.os.SystemClock.elapsedRealtime()+10000
        var rejected=false
        while(android.os.SystemClock.elapsedRealtime()<end) {
            vault.drain()
            val root=instrumentation.uiAutomation.rootInActiveWindow
            if(root?.findAccessibilityNodeInfosByText("Name is required")?.isNotEmpty()==true) { rejected=true; break }
            Thread.sleep(50)
        }
        assertTrue("Invalid save must explain the missing name",rejected)
        instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        scenario.onActivity { a -> assertEquals("synthetic-draft-password",screen.views(a.window.decorView).filterIsInstance<EditText>().first { it.hint?.toString()=="Password / primary secret" }.text.toString()) }
        capture("editor")
        screen.back(); val confirmDiscard=dialog()
        instrumentation.runOnMainSync { confirmDiscard.getButton(AlertDialog.BUTTON_POSITIVE).performClick() }
        screen.waitFor("3 items in your vault")
        assertEquals(3,Vault.json("list").getInt("total"))
    }
}
