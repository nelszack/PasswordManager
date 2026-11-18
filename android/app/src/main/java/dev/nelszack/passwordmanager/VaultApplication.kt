package dev.nelszack.passwordmanager

import android.app.Application
import android.content.*
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors
import org.json.JSONObject

object NativeBridge {
    init {
        System.loadLibrary("pm_mobile")
    }

    @JvmStatic external fun invalidate()

    @JvmStatic external fun call(context: Context, directory: String, request: String): String
}

object Vault {
    const val LOCKED = "dev.nelszack.passwordmanager.LOCKED"
    lateinit var context: Context
    val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val expire = Runnable { lock() }
    private var lastNativeTouch = 0L
    @Volatile private var nativeUnlockSeconds: Long? = null
    @Volatile private var nativeClipboardSeconds: Int? = null
    internal val clipboardSeconds
        get() = nativeClipboardSeconds ?: settings.getInt("clipboard_seconds", 30)

    internal val autofillSession = AutofillSession { android.os.SystemClock.elapsedRealtime() }
    @Volatile
    var primaryUnlock = false
        private set

    /** Operations that end or replace the current session. */
    private val sessionChanges =
        setOf(
            "unlock",
            "biometric_unlock",
            "lock",
            "create",
            "create_key",
            "restore_backup",
            "rekey",
            "delete_vault",
        )
    private val primaryUnlocks = setOf("unlock", "create", "create_key")

    private val settings
        get() = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun request(op: String, vararg args: Pair<String, Any?>): Any {
        if (op in sessionChanges) {
            primaryUnlock = false
            autofillSession.clear()
        }
        val body = JSONObject().put("op", op)
        args.forEach { (key, value) -> if (value != null) body.put(key, value) }
        val reply =
            JSONObject(
                NativeBridge.call(
                    context,
                    context.filesDir.resolve("vaults").absolutePath,
                    body.toString(),
                )
            )
        check(reply.getBoolean("ok")) { reply.optString("error", "Vault operation failed") }
        if (op in primaryUnlocks) primaryUnlock = true
        if (op == "biometric_unlock" || op == "lock") primaryUnlock = false
        val data = reply.get("data")
        if (data is JSONObject && data.has("unlock_seconds") && data.has("clipboard_seconds")) {
            val seconds = data.getLong("unlock_seconds").coerceIn(15, 86400)
            if (nativeUnlockSeconds != seconds) {
                nativeUnlockSeconds = seconds
                main.removeCallbacks(expire)
                main.postDelayed(expire, seconds * 1000L)
            }
            nativeClipboardSeconds = data.getInt("clipboard_seconds").coerceIn(1, 300)
        }
        return data
    }

    fun json(op: String, vararg args: Pair<String, Any?>) = request(op, *args) as JSONObject

    /**
     * Runs a shared vault command built by [VaultCommands]. With [expectedRevision], the command is
     * refused if the item changed since it was read. Irreversible commands (purging trash,
     * advancing an HOTP counter) also need [confirmed], set only after the user confirms.
     */
    fun command(
        command: JSONObject,
        expectedRevision: Long? = null,
        confirmed: Boolean = false,
    ): Any =
        request(
            "vault",
            "command" to command,
            "expected_revision" to expectedRevision,
            "confirmed" to confirmed.takeIf { it },
        )

    fun commandJson(
        command: JSONObject,
        expectedRevision: Long? = null,
        confirmed: Boolean = false,
    ) = command(command, expectedRevision, confirmed) as JSONObject

    fun lock() {
        runCatching { NativeBridge.invalidate() }
        autofillSession.clear()
        primaryUnlock = false
        main.removeCallbacks(expire)
        worker.execute { runCatching { request("lock") } }
        context.sendBroadcast(Intent(LOCKED).setPackage(context.packageName))
    }

    fun touch() {
        val seconds =
            (nativeUnlockSeconds ?: settings.getLong("unlock_seconds", 300)).coerceIn(15, 86400)
        main.removeCallbacks(expire)
        main.postDelayed(expire, seconds * 1000L)
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastNativeTouch > minOf(30000L, seconds * 500L)) {
            lastNativeTouch = now
            worker.execute { runCatching { request("status") } }
        }
    }
}

class VaultApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Vault.context = applicationContext
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    Vault.lock()
                }
            }
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
    }
}

abstract class SecureActivity : FragmentActivity() {
    @Volatile private var generation = 0L
    @Volatile private var active = true
    private val lockReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                generation++
                clearSecrets()
                if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED))
                    onSessionLocked()
            }
        }
    protected val ui
        get() = Handler(Looper.getMainLooper())

    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        ContextCompat.registerReceiver(
            this,
            lockReceiver,
            IntentFilter(Vault.LOCKED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        Vault.touch()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        Vault.touch()
    }

    override fun onStart() {
        super.onStart()
        active = true
    }

    protected open fun retainVaultOnStop(): Boolean = false

    protected open fun uiRevision(): Long = 0L

    protected open fun onWorkStarted() {}

    protected open fun onWorkFinished() {}

    override fun onStop() {
        active = false
        generation++
        super.onStop()
        if (!retainVaultOnStop()) Vault.lock()
        clearSecrets()
    }

    override fun onDestroy() {
        unregisterReceiver(lockReceiver)
        super.onDestroy()
    }

    protected open fun onSessionLocked() {
        finish()
    }

    protected open fun clearSecrets() {}

    protected open fun showFailure(error: Throwable) {
        android.app.AlertDialog.Builder(this)
            .setTitle("Password Manager")
            .setMessage(error.message ?: "Operation failed")
            .setPositiveButton("OK", null)
            .show()
    }

    internal fun <T> sessionCallback(onDiscard: () -> Unit = {}, action: (T) -> Unit): (T) -> Unit {
        val ticket = generation
        val screen = uiRevision()
        return { value ->
            if (
                isFinishing ||
                    isDestroyed ||
                    !active ||
                    ticket != generation ||
                    screen != uiRevision() ||
                    !lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)
            ) {
                onDiscard()
            } else {
                runCatching { action(value) }
                    .onFailure { error ->
                        onDiscard()
                        showFailure(error)
                    }
            }
        }
    }

    protected fun <T> task(action: () -> T, done: (T) -> Unit) = taskDiscarding(action, {}, done)

    protected fun <T> taskDiscarding(action: () -> T, onDiscard: (T) -> Unit, done: (T) -> Unit) {
        val ticket = generation
        val screen = uiRevision()
        onWorkStarted()
        Vault.worker.execute {
            if (!active || ticket != generation || screen != uiRevision()) {
                ui.post { if (ticket == generation) onWorkFinished() }
                return@execute
            }
            val result = runCatching(action)
            if (!active || ticket != generation) {
                result.getOrNull()?.let(onDiscard)
                runCatching { Vault.request("lock") }
                return@execute
            }
            ui.post {
                if (ticket == generation) onWorkFinished()
                if (
                    !isFinishing &&
                        !isDestroyed &&
                        ticket == generation &&
                        screen == uiRevision() &&
                        lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)
                )
                    result.fold({ value ->
                        runCatching { done(value) }.onFailure(::showFailure)
                    }) { error ->
                        showFailure(error)
                    }
                else result.getOrNull()?.let(onDiscard)
            }
        }
    }
}
