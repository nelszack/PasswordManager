package dev.nelszack.passwordmanager

/** Non-exported debug-only lifecycle fixture; never opens a vault itself. */
class AutofillSessionFixtureActivity : SecureActivity() {
    var completedHandoff = false

    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        setContentView(
            android.widget.TextView(this).apply { text = "Temporary autofill session test" }
        )
    }

    override fun retainVaultOnStop() = completedHandoff
}
