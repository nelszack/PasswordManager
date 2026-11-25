package dev.nelszack.passwordmanager

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Proof that an "add an item" request comes from this app's own autofill sheet. MainActivity is
 * exported for the launcher, so any installed app can send it the same extras; only a request
 * carrying the token minted here, in this process, is honored. Each token works once, and a newer
 * one replaces any still outstanding.
 */
internal object AddRequestToken {
    private val random = SecureRandom()
    private var pending: String? = null

    @Synchronized
    fun issue(): String {
        val bytes = ByteArray(16).also(random::nextBytes)
        return bytes.joinToString("") { "%02x".format(it) }.also { pending = it }
    }

    /**
     * Whether [token] is the outstanding one, which it then spends. A wrong token leaves it in
     * place, so another app cannot cancel a genuine request by sending a guess first.
     */
    @Synchronized
    fun consume(token: String?): Boolean {
        val expected = pending ?: return false
        if (token == null || !MessageDigest.isEqual(expected.toByteArray(), token.toByteArray()))
            return false
        pending = null
        return true
    }
}
