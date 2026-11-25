package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class AddRequestTokenTest {
    @Test
    fun onlyTheIssuedTokenIsAcceptedAndOnlyOnce() {
        val token = AddRequestToken.issue()
        assertFalse(AddRequestToken.consume(null))
        assertFalse(AddRequestToken.consume(""))
        assertFalse(AddRequestToken.consume("0".repeat(32)))
        // Wrong guesses do not spend the genuine request.
        assertTrue(AddRequestToken.consume(token))
        assertFalse(AddRequestToken.consume(token))
    }

    @Test
    fun aNewerRequestReplacesAnOutstandingOne() {
        val first = AddRequestToken.issue()
        val second = AddRequestToken.issue()
        assertNotEquals(first, second)
        assertFalse(AddRequestToken.consume(first))
        assertTrue(AddRequestToken.consume(second))
    }
}
