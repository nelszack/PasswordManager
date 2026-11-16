package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class CallerIdentityTest {
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
