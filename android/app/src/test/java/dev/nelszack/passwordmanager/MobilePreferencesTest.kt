package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class MobilePreferencesTest {
    @Test
    fun durationsAndOffValuesAreUnderstandableWithoutInterpretingRawNumbers() {
        assertEquals("5 minutes", MobilePreferences.summary("unlock_seconds", 300))
        assertEquals("30 seconds", MobilePreferences.summary("clipboard_seconds", 30))
        assertEquals("1 minute 30 seconds", MobilePreferences.duration(90))
        assertEquals("1 hour", MobilePreferences.duration(3600))
        assertEquals("Age-based purging is off", MobilePreferences.summary("trash_days", 0))
        assertTrue(MobilePreferences.summary("history_limit", 0).contains("off"))
        assertEquals("24 characters", MobilePreferences.summary("generator_length", 24))
        assertEquals("6 words", MobilePreferences.summary("passphrase_words", 6))
    }
}
