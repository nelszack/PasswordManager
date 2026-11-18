package dev.nelszack.passwordmanager

import android.app.Activity
import android.app.KeyguardManager
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.rules.ExternalResource

/** Class-scoped cache storage. JNI keeps its first path, so run each class in a fresh process. */
class SyntheticVaultRule(private val prefix: String) : ExternalResource() {
    val instrumentation
        get() = InstrumentationRegistry.getInstrumentation()

    val context
        get() = instrumentation.targetContext

    private lateinit var directory: File
    private val scenarios = mutableListOf<ActivityScenario<*>>()

    companion object {
        private var bound = false
    }

    override fun before() {
        check(!bound) { "Run each synthetic vault test class in a fresh instrumentation process" }
        bound = true
        directory = context.cacheDir.resolve("$prefix-${UUID.randomUUID()}")
        try {
            assertTrue("Synthetic JNI storage must initialize", reply("status").getBoolean("ok"))
        } catch (error: Throwable) {
            runCatching { after() }.exceptionOrNull()?.let(error::addSuppressed)
            throw error
        }
    }

    fun reply(op: String, vararg args: Pair<String, Any?>): JSONObject {
        val request = JSONObject().put("op", op)
        args.forEach { (key, value) -> request.put(key, value) }
        return JSONObject(NativeBridge.call(context, directory.absolutePath, request.toString()))
    }

    fun requireUnlocked() {
        assertFalse(
            "Unlock the device for synthetic UI checks",
            context.getSystemService(KeyguardManager::class.java).isKeyguardLocked,
        )
    }

    fun drain() {
        instrumentation.waitForIdleSync()
        Vault.worker.submit {}.get(10, TimeUnit.SECONDS)
        instrumentation.waitForIdleSync()
    }

    fun <A : Activity> launch(type: Class<A>): ActivityScenario<A> =
        ActivityScenario.launch(type).also(scenarios::add)

    fun <A : Activity> launch(intent: Intent): ActivityScenario<A> =
        ActivityScenario.launch<A>(intent).also(scenarios::add)

    override fun after() {
        val errors = mutableListOf<Throwable>()
        fun clean(action: () -> Unit) {
            try {
                action()
            } catch (error: Throwable) {
                errors.add(error)
            }
        }
        scenarios.asReversed().forEach { scenario -> clean { scenario.close() } }
        scenarios.clear()
        clean { drain() }
        clean { Vault.request("lock") }
        clean {
            check(directory.deleteRecursively()) { "Could not remove synthetic cache storage" }
        }
        errors.firstOrNull()?.let { first ->
            errors.drop(1).forEach(first::addSuppressed)
            throw first
        }
    }
}
