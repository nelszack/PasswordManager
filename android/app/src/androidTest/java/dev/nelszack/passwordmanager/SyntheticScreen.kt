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
        var shown = emptyList<String>()
        while (!found && SystemClock.elapsedRealtime() < end) {
            vault.drain()
            scenario.onActivity {
                val all = views(it.window.decorView)
                found = all.any { view -> matches(view, text) }
                if (!found)
                    shown = all.filterIsInstance<TextView>().map { view -> view.text.toString() }
            }
            if (!found) Thread.sleep(50)
        }
        assertTrue("Expected synthetic control: $text (shown ${shown.filter { it.isNotBlank() }})", found)
    }

    fun click(text: String) {
        waitFor(text)
        scenario.onActivity { activity ->
            val all = views(activity.window.decorView)
            val target =
                all.filterIsInstance<Button>().firstOrNull { matches(it, text) }
                    // Navigation items are labelled views inside a clickable item.
                    ?: generateSequence(all.first { matches(it, text) } as View) { it.parent as? View }
                        .first { it.isClickable }
            target.performClick()
        }
    }

    /** A field's label: Material fields keep it on the wrapping TextInputLayout. */
    fun label(input: EditText): String? {
        var parent = input.parent
        while (parent != null) {
            if (parent is com.google.android.material.textfield.TextInputLayout)
                return parent.hint?.toString()
            parent = parent.parent
        }
        return input.hint?.toString()
    }

    fun field(activity: Activity, hint: String): EditText? =
        views(activity.window.decorView).filterIsInstance<EditText>().firstOrNull {
            label(it) == hint
        }

    fun input(hint: String, value: String) {
        val end = SystemClock.elapsedRealtime() + 15000
        var done = false
        var seen = emptyList<String?>()
        while (!done && SystemClock.elapsedRealtime() < end) {
            vault.drain()
            scenario.onActivity { activity ->
                val target = field(activity, hint)
                if (target != null) {
                    target.setText(value)
                    done = true
                } else
                    seen =
                        views(activity.window.decorView).filterIsInstance<EditText>().map {
                            label(it)
                        }
            }
            if (!done) Thread.sleep(50)
        }
        assertTrue("Expected synthetic field: $hint (found $seen)", done)
    }

    fun back() {
        scenario.onActivity { activity ->
            views(activity.window.decorView)
                .first { it.contentDescription == "Go back" && it.isClickable }
                .performClick()
        }
    }
}
