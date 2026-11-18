package dev.nelszack.passwordmanager

internal data class AutofillScope(val caller: String, val origin: String, val hostnameOnly: Boolean)

/** An in-memory grant, scoped to one caller/site; no vault keys or secrets. */
internal class AutofillSession(private val clock: () -> Long) {
    private var scope: AutofillScope? = null
    private var deadline = 0L

    @Synchronized
    fun grant(value: AutofillScope) {
        scope = value
        deadline = clock() + 5 * 60 * 1000L
    }

    @Synchronized
    fun allows(value: AutofillScope): Boolean {
        if (clock() >= deadline) clear()
        return scope == value
    }

    @Synchronized
    fun clear() {
        scope = null
        deadline = 0
    }

    @Synchronized fun hasGrant() = scope != null
}
