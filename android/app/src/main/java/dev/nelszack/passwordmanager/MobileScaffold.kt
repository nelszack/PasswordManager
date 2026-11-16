package dev.nelszack.passwordmanager

import android.content.res.Configuration
import android.view.*
import android.widget.*
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

/** Fixed app bar and navigation keep actions reachable while only the body scrolls. */
internal class MobileScaffold(private val activity: ManagementActivity, content: LinearLayout,
    private val navigate: (String) -> Unit, private val lock: () -> Unit) {
    private fun dp(value: Int) = MobileUi.dp(activity,value)
    val scroll = ScrollView(activity).apply { isFillViewport = false; clipToPadding = false }
    private val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(MobileUi.color(activity,R.color.pm_background)) }
    private val back = MobileUi.button(activity,"‹") { backAction?.invoke() }.apply { contentDescription = "Go back"; background = null; textSize = 30f; setPadding(0,0,0,0) }
    private val heading = MobileUi.text(activity,"Password Manager",20f,bold=true).apply { maxLines=1; ellipsize=android.text.TextUtils.TruncateAt.END }
    private val lockButton = MobileUi.button(activity,"Lock") { lock() }.apply { background = null; setTextColor(MobileUi.color(activity,R.color.pm_accent)); setPadding(dp(8),0,dp(8),0) }
    private val progress = ProgressBar(activity,null,android.R.attr.progressBarStyleHorizontal).apply { isIndeterminate = true; visibility = View.GONE; importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO }
    private val actions = LinearLayout(activity).apply { setPadding(dp(16),dp(10),dp(16),dp(10)); setBackgroundColor(MobileUi.color(activity,R.color.pm_surface)); visibility=View.GONE }
    private val navigation = LinearLayout(activity).apply { setPadding(dp(12),dp(8),dp(12),dp(8)); background = MobileUi.shape(activity) }
    private var navRequested = false
    private var unlocked = false
    private var imeVisible = false
    var backAction: (() -> Unit)? = null
    init {
        (content.parent as? ViewGroup)?.removeView(content)
        val bar = LinearLayout(activity).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(dp(12),dp(6),dp(12),dp(6)); minimumHeight = dp(64) }
        bar.addView(back,LinearLayout.LayoutParams(dp(48),dp(52)))
        bar.addView(heading,LinearLayout.LayoutParams(0,-2,1f))
        ViewCompat.setAccessibilityHeading(heading,true)
        bar.addView(lockButton,LinearLayout.LayoutParams(-2,dp(48)))
        root.addView(bar); root.addView(progress,LinearLayout.LayoutParams(-1,dp(3)))
        content.setPadding(dp(20),dp(12),dp(20),dp(28))
        content.isFocusableInTouchMode = true
        scroll.addView(content,ViewGroup.LayoutParams(-1,-2))
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f)); root.addView(actions); root.addView(navigation)
        activity.setContentView(root)
        WindowCompat.setDecorFitsSystemWindows(activity.window,false)
        val dark = activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(activity.window,root).apply { isAppearanceLightStatusBars = !dark; isAppearanceLightNavigationBars = !dark }
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
            imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
            root.setPadding(bars.left,bars.top,bars.right,maxOf(bars.bottom,keyboard.bottom))
            navigation.visibility = if (navRequested && !imeVisible) View.VISIBLE else View.GONE
            insets
        }
        ViewCompat.requestApplyInsets(root)
    }
    fun page(title: String) {
        actions.removeAllViews(); actions.visibility=View.GONE
        heading.text = title; back.visibility = View.VISIBLE; lockButton.visibility = if(unlocked) View.VISIBLE else View.GONE
        navigation.visibility = View.GONE; navRequested = false
        scroll.post { scroll.scrollTo(0,0) }
        WindowInsetsControllerCompat(activity.window,root).hide(WindowInsetsCompat.Type.ime())
    }
    fun root(tab: String, unlocked: Boolean) {
        this.unlocked=unlocked
        back.visibility = View.GONE; backAction = null; lockButton.visibility = if (unlocked) View.VISIBLE else View.GONE
        navRequested = true; navigation.visibility = if (imeVisible) View.GONE else View.VISIBLE
        navigation.removeAllViews()
        for (name in listOf("Vault","Tools","Settings")) {
            val button = MobileUi.button(activity,name) { navigate(name) }.apply {
                minHeight = dp(48); minimumHeight = dp(48); isSelected = name == tab
                background = if (isSelected) MobileUi.shape(activity,R.color.pm_accent_soft,radius=14) else null
                setTextColor(MobileUi.color(activity,if (isSelected) R.color.pm_accent else R.color.pm_muted))
                setPadding(dp(8),dp(8),dp(8),dp(8)); contentDescription = if (isSelected) "$name, selected" else name
            }
            navigation.addView(button,LinearLayout.LayoutParams(0,-2,1f).apply { marginStart = dp(3); marginEnd = dp(3) })
        }
    }
    fun pin(first: View, second: View) {
        actions.removeAllViews()
        for(view in listOf(first,second)) {
            (view.parent as? ViewGroup)?.removeView(view)
            actions.addView(view,LinearLayout.LayoutParams(0,-2,1f).apply {marginStart=dp(4); marginEnd=dp(4)})
        }
        actions.visibility=View.VISIBLE
    }
    fun working(visible: Boolean) { progress.visibility = if (visible) View.VISIBLE else View.GONE }
    fun clear() { actions.removeAllViews(); actions.visibility=View.GONE; unlocked=false; heading.text = "Password Manager"; working(false); lockButton.visibility = View.GONE; backAction = null; navigation.visibility = View.GONE; navRequested = false }
}
