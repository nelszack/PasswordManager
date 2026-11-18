package dev.nelszack.passwordmanager

/** Non-exported debug UI, used only after instrumentation binds JNI to synthetic cache storage. */
class MobileManagementFixtureActivity : ManagementActivity() {
    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        tools()
    }

    override fun afterToolChange() = "Synthetic saved"

    override fun showItems(message: String) {
        page("Synthetic items")
        label(message)
        button("Tools & recovery") { tools() }
    }

    override fun showDetail(id: Long) {
        page("Synthetic item $id")
        button("Password history") { history(id) }
        button("Authenticator & Duo") { authenticator(id) }
    }

    override fun showHome() {
        tools()
    }

    internal fun openTools() {
        tools()
    }

    internal fun openItem(id: Long) {
        showDetail(id)
    }
}
