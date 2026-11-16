package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class CallerIdentityTest {
    @Test fun hostnameFallbackRequiresMissingNativeEvidenceAndDoesNotGuessAPort() {
        val fallback = CallerIdentity.browserSite("https://accounts.example.com", emptyList())
        assertTrue(fallback.hostnameOnly)
        assertEquals("https://accounts.example.com", fallback.origin)
        val exact = CallerIdentity.browserSite("https://accounts.example.com", listOf("https://accounts.example.com:8443/login"))
        assertFalse(exact.hostnameOnly)
        assertEquals("https://accounts.example.com:8443", exact.origin)
        assertThrows(IllegalStateException::class.java) { CallerIdentity.browserSite("https://accounts.example.com", listOf("https://evil.example")) }
        assertThrows(IllegalStateException::class.java) { CallerIdentity.browserSite("https://accounts.example.com", listOf("https://accounts.example.com", "https://accounts.example.com:8443")) }
        assertThrows(IllegalStateException::class.java) { CallerIdentity.browserSite("http://accounts.example.com", emptyList()) }
    }
    @Test fun browserAddressPreservesPortAndMustMatchFormHost() {
        assertEquals("https://example.com:8443", CallerIdentity.addressBarOrigin("example.com:8443/login", "https://example.com"))
        assertEquals("https://example.com", CallerIdentity.addressBarOrigin("https://example.com/login", "https://example.com"))
        assertThrows(IllegalStateException::class.java) { CallerIdentity.addressBarOrigin("https://evil.com", "https://example.com") }
        assertThrows(IllegalStateException::class.java) { CallerIdentity.addressBarOrigin("https://user@example.com", "https://example.com") }
    }
    @Test fun originsAreHttpsAndContainNoPageOrCredentials() {
        assertEquals("https://example.com", CallerIdentity.websiteOrigin("https://example.com/"))
        assertEquals("https://example.com:8443", CallerIdentity.websiteOrigin("https://example.com:8443"))
        for (invalid in listOf("http://example.com", "https://user@example.com", "https://example.com/login", "https://example.com?x=1", "https://example.com#fragment")) {
            assertThrows(IllegalStateException::class.java) { CallerIdentity.websiteOrigin(invalid) }
        }
    }
}
