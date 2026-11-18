package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class AutofillSuggestionsTest {
    @Test
    fun selectedAccountTokenBindsEveryIdentityAndAddressComponent() {
        val original =
            AutofillSuggestions.token(1, "Google", "alice", "https://accounts.example.com")
        assertEquals(
            original,
            AutofillSuggestions.token(1, "Google", "alice", "https://accounts.example.com"),
        )
        for (changed in
            listOf(
                AutofillSuggestions.token(2, "Google", "alice", "https://accounts.example.com"),
                AutofillSuggestions.token(1, "Other", "alice", "https://accounts.example.com"),
                AutofillSuggestions.token(1, "Google", "bob", "https://accounts.example.com"),
                AutofillSuggestions.token(
                    1,
                    "Google",
                    "alice",
                    "https://accounts.example.com:8443",
                ),
            )) assertNotEquals(original, changed)
        assertNotEquals(
            AutofillSuggestions.token(1, "ab", "c", "https://example.com"),
            AutofillSuggestions.token(1, "a", "bc", "https://example.com"),
        )
    }
}
