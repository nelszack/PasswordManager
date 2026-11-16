package dev.nelszack.passwordmanager

import android.app.Application
import android.content.*
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.util.concurrent.Executors

object NativeBridge {
    init { System.loadLibrary("pm_mobile") }
    @JvmStatic external fun call(context: Context, directory: String, request: String): String
}

object Vault {
    const val LOCKED = "dev.nelszack.passwordmanager.LOCKED"
    lateinit var context: Context
    val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val expire = Runnable { lock() }
    private var lastNativeTouch = 0L
    @Volatile var primaryUnlock = false
        private set
    fun request(op: String, vararg args: Pair<String, Any?>): Any {
        if (op == "unlock" || op == "biometric_unlock" || op == "lock") primaryUnlock = false
        val body = JSONObject().put("op", op)
        args.forEach { (key, value) -> if (value != null) body.put(key, value) }
        val reply = JSONObject(NativeBridge.call(context, context.filesDir.resolve("vaults").absolutePath, body.toString()))
        check(reply.getBoolean("ok")) { reply.optString("error", "Vault operation failed") }
        if (op == "unlock" || op == "create") primaryUnlock = true
        if (op == "biometric_unlock" || op == "lock") primaryUnlock = false
        return reply.get("data")
    }
    fun json(op: String, vararg args: Pair<String, Any?>) = request(op, *args) as JSONObject
    fun lock() {
        primaryUnlock = false
        main.removeCallbacks(expire)
        worker.execute { runCatching { request("lock") } }
        context.sendBroadcast(Intent(LOCKED).setPackage(context.packageName))
    }
    fun touch() {
        main.removeCallbacks(expire); main.postDelayed(expire, 5 * 60 * 1000L)
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastNativeTouch > 30000L) {
            lastNativeTouch = now
            worker.execute { runCatching { request("status") } }
        }
    }
}

class VaultApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Vault.context = applicationContext
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) { Vault.lock() }
        }
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
    }
}

abstract class SecureActivity : FragmentActivity() {
    @Volatile private var generation = 0L
    @Volatile private var active = true
    private val lockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            generation++
            clearSecrets()
            if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) onSessionLocked()
        }
    }
    protected val ui get() = Handler(Looper.getMainLooper())
    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        ContextCompat.registerReceiver(this, lockReceiver, IntentFilter(Vault.LOCKED), ContextCompat.RECEIVER_NOT_EXPORTED)
        Vault.touch()
    }
    override fun onUserInteraction() { super.onUserInteraction(); Vault.touch() }
    override fun onStart() { super.onStart(); active = true }
    override fun onStop() { active = false; generation++; super.onStop(); Vault.lock(); clearSecrets() }
    override fun onDestroy() { unregisterReceiver(lockReceiver); super.onDestroy() }
    protected open fun onSessionLocked() { finish() }
    protected open fun clearSecrets() {}
    protected open fun showFailure(error: Throwable) {
        android.app.AlertDialog.Builder(this).setTitle("Password Manager")
            .setMessage(error.message ?: "Operation failed").setPositiveButton("OK", null).show()
    }
    protected fun <T> task(action: () -> T, done: (T) -> Unit) {
        val ticket = generation
        Vault.worker.execute {
            if (!active || ticket != generation) return@execute
            val result = runCatching(action)
            if (!active || ticket != generation) runCatching { Vault.request("lock") }
            ui.post {
                if (!isFinishing && !isDestroyed && ticket == generation && lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) result.fold(done) { error ->
                    showFailure(error)
                }
            }
        }
    }
}
