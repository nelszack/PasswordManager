package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class BoundedInputTest {
    @Test fun preservesExactLimitAndRejectsOversize() {
        assertArrayEquals(byteArrayOf(0, 1, 2), byteArrayOf(0, 1, 2).inputStream().readBounded(3))
        assertArrayEquals(byteArrayOf(), byteArrayOf().inputStream().readBounded(0))
        assertThrows(IllegalStateException::class.java) { byteArrayOf(0, 1, 2, 3).inputStream().readBounded(3) }
    }
}
