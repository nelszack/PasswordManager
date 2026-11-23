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
    @Volatile private var lastCopy: String? = null

    /**
     * Clears our copy. Android 10+ hides the clipboard from apps in the background, so when the
     * clip can't be read it is cleared anyway; a readable clip from someone else is kept.
     */
    private fun clearIfOurs(clipboard: ClipboardManager, copyId: String) {
        runCatching {
            val description = clipboard.primaryClipDescription
            if (description == null || description.extras?.getString(COPY_ID) == copyId)
                clipboard.clearPrimaryClip()
        }
        if (lastCopy == copyId) lastCopy = null
    }

    /** Called when the vault locks: nothing copied from it should outlive the session. */
    fun clearOnLock(context: Context) {
        val copyId = lastCopy ?: return
        clearIfOurs(context.getSystemService(ClipboardManager::class.java), copyId)
    }

    fun copy(context: Context, value: String, lifetimeSeconds: Int = 300, what: String = "Copied") {
        if (Vault.clipboardSeconds == 0) {
            Toast.makeText(
                    context,
                    "Copying is off. Turn it on in Settings → Mobile settings.",
                    Toast.LENGTH_LONG,
                )
                .show()
            return
        }
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val copyId = UUID.randomUUID().toString()
        val clip = ClipData.newPlainText("Password Manager", value)
        clip.description.extras =
            PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
                putString(COPY_ID, copyId)
            }
        clipboard.setPrimaryClip(clip)
        lastCopy = copyId
        val seconds = minOf(lifetimeSeconds, Vault.clipboardSeconds).coerceIn(1, 300)
        main.postDelayed({ clearIfOurs(clipboard, copyId) }, seconds * 1000L)
        Toast.makeText(context, "$what · clears in $seconds s", Toast.LENGTH_SHORT).show()
    }
}
