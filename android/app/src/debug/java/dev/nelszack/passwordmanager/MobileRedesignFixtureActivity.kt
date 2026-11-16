package dev.nelszack.passwordmanager

/** Preview the actual vault screens only after the test has bound JNI to cache storage. */
class MobileRedesignFixtureActivity : MainActivity() {
    companion object {
        var previewNight: Boolean? = null
        var previewFontScale: Float? = null
    }
    override fun attachBaseContext(base: android.content.Context) {
        val config=android.content.res.Configuration(base.resources.configuration)
        previewNight?.let { config.uiMode=(config.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK.inv()) or
            if(it) android.content.res.Configuration.UI_MODE_NIGHT_YES else android.content.res.Configuration.UI_MODE_NIGHT_NO }
        previewFontScale?.let { config.fontScale=it }
        super.attachBaseContext(base.createConfigurationContext(config))
    }
    override fun afterToolChange() = "Saved in synthetic vault"
    override fun onCreate(state: android.os.Bundle?) {
        super.onCreate(state)
        MainActivity::class.java.getDeclaredMethod("items",String::class.java,String::class.java).apply { isAccessible=true }.invoke(this,"","")
    }
}
