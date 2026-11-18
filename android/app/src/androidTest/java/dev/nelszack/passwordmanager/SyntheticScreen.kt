package dev.nelszack.passwordmanager

import android.app.Activity
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.assertTrue

/** Native widget navigation only; behavior assertions stay in the individual tests. */
class SyntheticScreen<A : Activity>(
    private val scenario: ActivityScenario<A>,
    private val vault: SyntheticVaultRule,
) {
    fun views(root: View): List<View> =
        listOf(root) +
            if (root is ViewGroup) (0 until root.childCount).flatMap { views(root.getChildAt(it)) }
            else emptyList()

    fun matches(view: View, text: String) =
        view is TextView && view.text.toString().lineSequence().any { it == text }

    fun waitFor(text: String) {
        val end = SystemClock.elapsedRealtime() + 15000
        var found = false
        while (!found && SystemClock.elapsedRealtime() < end) {
            vault.drain()
            scenario.onActivity {
                found = views(it.window.decorView).any { view -> matches(view, text) }
            }
            if (!found) Thread.sleep(50)
        }
        assertTrue("Expected synthetic control: $text", found)
    }

    fun click(text: String) {
        waitFor(text)
        scenario.onActivity { activity ->
            views(activity.window.decorView)
                .filterIsInstance<Button>()
                .first { matches(it, text) }
                .performClick()
        }
    }

    fun input(hint: String, value: String) {
        scenario.onActivity { activity ->
            views(activity.window.decorView)
                .filterIsInstance<EditText>()
                .first { it.hint?.toString() == hint }
                .setText(value)
        }
    }

    fun back() {
        scenario.onActivity { activity ->
            views(activity.window.decorView)
                .filterIsInstance<Button>()
                .first { it.contentDescription == "Go back" }
                .performClick()
        }
    }
}
