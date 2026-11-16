package dev.nelszack.passwordmanager

import java.io.ByteArrayOutputStream
import java.io.InputStream

fun InputStream.readBounded(limit: Int): ByteArray {
    require(limit >= 0)
    val output = object : ByteArrayOutputStream() {
        override fun close() { buf.fill(0); reset(); super.close() }
    }
    val buffer = ByteArray(8192)
    try {
        while (true) {
            val count = read(buffer, 0, minOf(buffer.size, limit - output.size() + 1))
            if (count < 0) return output.toByteArray()
            check(count <= limit - output.size()) { "File exceeds size limit" }
            output.write(buffer, 0, count)
        }
    } finally { buffer.fill(0); output.close() }
}
