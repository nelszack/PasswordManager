package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class AutofillSessionTest {
    @Test
    fun grantIsCallerAndSiteScopedExpiresAndCanBeRevoked() {
        var now = 1000L
        val session = AutofillSession { now }
        val scope = AutofillScope("com.android.chrome", "https://accounts.example.com", true)
        assertFalse(session.allows(scope))
        session.grant(scope)
        assertTrue(session.allows(scope))
        assertFalse(session.allows(scope.copy(caller = "untrusted.app")))
        assertFalse(session.allows(scope.copy(origin = "https://other.example.com")))
        assertFalse(session.allows(scope.copy(hostnameOnly = false)))
        now += 299999
        assertTrue(session.allows(scope))
        now++
        assertFalse(session.allows(scope))
        assertFalse(session.hasGrant())
        session.grant(scope)
        session.clear()
        assertFalse(session.allows(scope))
    }
}
