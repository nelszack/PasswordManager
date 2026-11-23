package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class VaultNamesTest {
    @Test
    fun namesFollowTheDesktopRules() {
        assertNull(VaultNames.problem("Personal vault"))
        assertNull(VaultNames.problem("  Work  "))
        assertNotNull(VaultNames.problem(""))
        assertNotNull(VaultNames.problem("   "))
        assertNotNull(VaultNames.problem("a\nb"))
        assertNotNull(VaultNames.problem("x".repeat(81)))
    }
}
