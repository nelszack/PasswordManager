package dev.nelszack.passwordmanager

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.widget.Toast
import java.util.UUID

object SecretClipboard {
    private const val COPY_ID = "dev.nelszack.passwordmanager.CLIP_ID"
    private val main = Handler(Looper.getMainLooper())
    fun copy(context: Context, value: String, lifetimeSeconds: Int = 300) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val copyId = UUID.randomUUID().toString()
        val clip = ClipData.newPlainText("Password Manager", value)
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
            putString(COPY_ID, copyId)
        }
        clipboard.setPrimaryClip(clip)
        main.postDelayed({
            // Check metadata only, and never erase something copied afterward.
            runCatching { if (clipboard.primaryClipDescription?.extras?.getString(COPY_ID) == copyId) clipboard.clearPrimaryClip() }
        }, minOf(lifetimeSeconds, Vault.clipboardSeconds).coerceIn(1, 300) * 1000L)
        Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
    }
}
