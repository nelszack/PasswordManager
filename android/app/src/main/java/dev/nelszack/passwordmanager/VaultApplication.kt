package dev.nelszack.passwordmanager

import android.app.Application
import android.content.*
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
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
    /** Screen work. Native calls may run on several threads; Rust serializes vault access. */
    val worker = Executors.newSingleThreadExecutor()
    /**
     * Autofill and credential-provider service requests, including form parsing, so a long screen
     * task never delays Android's fill timeout.
     */
    val services = Executors.newSingleThreadExecutor()
    /** Caller verification that may wait on the network, such as asset-link fetches. */
    val lookups = Executors.newSingleThreadExecutor()
    /** Follow-up syncs, after the caller already has its result. */
    private val syncer = Executors.newSingleThreadExecutor()
    private val syncQueued = AtomicBoolean(false)
    private val main = Handler(Looper.getMainLooper())
    private val expire = Runnable { lock() }
    private var lastNativeTouch = 0L
    @Volatile private var nativeUnlockSeconds: Long? = null
    @Volatile private var nativeClipboardSeconds: Int? = null
    internal val clipboardSeconds
        get() = nativeClipboardSeconds ?: settings.getInt("clipboard_seconds", 30)
    @Volatile private var nativeLeaveSeconds: Long? = null
    /** Seconds the vault stays unlocked after leaving the app; 0 locks at once. */
    internal val leaveLockSeconds
        get() = (nativeLeaveSeconds ?: settings.getLong("leave_lock_seconds", 30)).coerceIn(0, 300)
    // Leaving the app locks without touching the clipboard: a password copied to paste
    // into another app must survive the switch; the clipboard timer clears it.
    private val leaveLock = Runnable { lock(clearClipboard = false) }

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
            nativeClipboardSeconds = data.getInt("clipboard_seconds").coerceIn(0, 300)
            if (data.has("leave_lock_seconds"))
                nativeLeaveSeconds = data.getLong("leave_lock_seconds").coerceIn(0, 300)
        }
        return data
    }

    fun json(op: String, vararg args: Pair<String, Any?>) = request(op, *args) as JSONObject

    @Volatile private var profiles: Map<String, JSONObject>? = null

    /**
     * Per-type editor labels and suggested custom fields, keyed by item kind. They come from the
     * same Rust table as the desktop editor and never change while the app runs.
     */
    fun itemProfiles(): Map<String, JSONObject> =
        profiles
            ?: (request("item_profiles") as org.json.JSONArray).let { list ->
                (0 until list.length())
                    .map(list::getJSONObject)
                    .associateBy { it.getString("kind") }
                    .also { profiles = it }
            }

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

    /**
     * Queues one sync after a change, coalescing changes made while it waits. Rust snapshots the
     * encrypted vault as soon as the sync starts and may finish uploading it after the app locks;
     * anything it would apply still needs the session that saved the change.
     */
    fun queueSync() {
        val server = settings.getString("server", "").orEmpty()
        if (server.isBlank() || !syncQueued.compareAndSet(false, true)) return
        syncer.execute {
            syncQueued.set(false)
            runCatching {
                request(
                    "sync",
                    "server" to server,
                    "token" to DeviceKeys.token(context),
                    "if_enabled" to true,
                    "background" to true,
                )
            }
        }
    }

    /**
     * The app went to the background. Locks now, or after the configured delay so a quick switch
     * to another app (to read a code, or paste a password) keeps the screen and any draft. Returns
     * whether the vault stays unlocked for now.
     */
    fun leftApp(): Boolean {
        main.removeCallbacks(leaveLock)
        val seconds = leaveLockSeconds
        if (seconds == 0L) {
            lock(clearClipboard = false)
            return false
        }
        main.postDelayed(leaveLock, seconds * 1000L)
        return true
    }

    /** The app is visible again before the delayed lock ran. */
    fun returnedToApp() {
        main.removeCallbacks(leaveLock)
    }

    /**
     * Locks now. Explicit locks and screen-off also clear our clipboard copy; leaving
     * the app ([clearClipboard] false) keeps it so it can be pasted elsewhere.
     */
    fun lock(clearClipboard: Boolean = true) {
        main.removeCallbacks(leaveLock)
        if (clearClipboard) SecretClipboard.clearOnLock(context)
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
    /** Bumped each time the screen leaves view, so callbacks from an earlier visit are stale. */
    @Volatile private var visit = 0L
    private val lockReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                generation++
                clearSecrets()
                if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED))
                    onSessionLocked()
            }
        }
    /** One handler, so callbacks posted through it can also be removed through it. */
    internal val ui = Handler(Looper.getMainLooper())

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
        Vault.returnedToApp()
    }

    protected open fun retainVaultOnStop(): Boolean = false

    /**
     * Leaving waits for the configured leave-lock delay. Handoff surfaces shown over another
     * app (the autofill sheet) lock at once instead when left without completing.
     */
    protected open fun delayLockOnLeave(): Boolean = true

    protected open fun uiRevision(): Long = 0L

    protected open fun onWorkStarted() {}

    protected open fun onWorkFinished() {}

    override fun onStop() {
        super.onStop()
        // Rotation and other configuration changes recreate the screen; they are not leaving.
        if (isChangingConfigurations) return
        visit++
        // While the delayed lock waits, the screen stays live: reveal timers still hide
        // secrets, codes keep refreshing, and saves finish (all hidden from screenshots and
        // recents by FLAG_SECURE). The lock broadcast clears everything when it runs.
        if (!retainVaultOnStop()) {
            if (delayLockOnLeave()) {
                if (Vault.leftApp()) return
            } else Vault.lock(clearClipboard = false)
        }
        active = false
        generation++
        clearSecrets()
    }

    override fun onDestroy() {
        // A screen kept live through the leave-lock delay still ends here: late work is dropped.
        if (!isChangingConfigurations) {
            active = false
            generation++
        }
        ui.removeCallbacksAndMessages(null)
        unregisterReceiver(lockReceiver)
        super.onDestroy()
    }

    protected open fun onSessionLocked() {
        finish()
    }

    protected open fun clearSecrets() {}

    /** Failures appear as a snackbar with the reason; they never block the screen. */
    protected open fun showFailure(error: Throwable) {
        val message = friendlyError(error.message)
        val root = findViewById<android.view.View>(android.R.id.content)
        if (root == null) {
            android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG).show()
            return
        }
        com.google.android.material.snackbar.Snackbar.make(
                root,
                message,
                com.google.android.material.snackbar.Snackbar.LENGTH_INDEFINITE,
            )
            .setAction("OK") {}
            .apply { (view.findViewById<android.widget.TextView>(com.google.android.material.R.id.snackbar_text))?.maxLines = 6 }
            .show()
    }

    /** Plain-language wording for common vault errors, with the original text kept otherwise. */
    internal fun friendlyError(message: String?): String {
        val text = message?.trim().orEmpty()
        return when {
            text.isEmpty() -> "Something went wrong. Try again."
            text.contains("incorrect password", ignoreCase = true) ->
                "That password or key file doesn't open this vault. Check it and try again."
            text.contains("locked", ignoreCase = true) ->
                "Your vault locked. Unlock it, then try again."
            text.contains("Unable to resolve host", ignoreCase = true) ||
                text.contains("timeout", ignoreCase = true) ->
                "The sync server couldn't be reached. Check your connection; your local vault still works."
            else -> text.replaceFirstChar { it.uppercase() }
        }
    }

    /**
     * Wraps a late callback so it runs only while this screen and session are current. By default
     * it must also arrive in the same visit: an authentication result started before leaving the
     * app is dropped. Timers that only hide secrets or refresh codes pass [acrossVisits] so they keep
     * working during the leave-lock delay.
     */
    internal fun <T> sessionCallback(
        onDiscard: () -> Unit = {},
        acrossVisits: Boolean = false,
        action: (T) -> Unit,
    ): (T) -> Unit {
        val ticket = generation
        val screen = uiRevision()
        val started = visit
        return { value ->
            if (
                isFinishing ||
                    (!acrossVisits && started != visit) ||
                    isDestroyed ||
                    !active ||
                    ticket != generation ||
                    screen != uiRevision() ||
                    !lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.CREATED)
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

    internal fun <T> task(action: () -> T, done: (T) -> Unit) = taskDiscarding(action, {}, done)

    protected fun <T> taskDiscarding(action: () -> T, onDiscard: (T) -> Unit, done: (T) -> Unit) =
        runTask(Vault.worker, action, onDiscard, done)

    /** Like [task], on [Vault.lookups], for caller checks that may wait on the network. */
    protected fun <T> lookupTask(action: () -> T, done: (T) -> Unit) =
        runTask(Vault.lookups, action, {}, done)

    private fun <T> runTask(
        executor: java.util.concurrent.Executor,
        action: () -> T,
        onDiscard: (T) -> Unit,
        done: (T) -> Unit,
    ) {
        val ticket = generation
        val screen = uiRevision()
        onWorkStarted()
        executor.execute {
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
                        // Still created: a screen kept during the leave-lock delay finishes its work.
                        lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.CREATED)
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
