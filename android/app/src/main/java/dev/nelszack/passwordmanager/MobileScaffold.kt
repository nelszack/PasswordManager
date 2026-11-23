package dev.nelszack.passwordmanager

import android.content.res.Configuration
import android.view.*
import android.widget.*
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

/** Fixed app bar and navigation keep actions reachable while only the body scrolls. */
internal class MobileScaffold(
    private val activity: ManagementActivity,
    private val content: LinearLayout,
    private val navigate: (String) -> Unit,
    private val lock: () -> Unit,
) {
    private fun dp(value: Int) = MobileUi.dp(activity, value)

    val scroll =
        ScrollView(activity).apply {
            isFillViewport = false
            clipToPadding = false
        }
    private val root =
        LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(MobileUi.color(activity, R.color.pm_background))
        }
    private val back =
        ImageButton(activity).apply {
            setImageResource(R.drawable.pm_icon_back)
            contentDescription = "Go back"
            background =
                android.graphics.drawable.RippleDrawable(
                    android.content.res.ColorStateList.valueOf(
                        MobileUi.color(activity, R.color.pm_accent_soft)
                    ),
                    null,
                    MobileUi.shape(activity, radius = 24),
                )
            setOnClickListener { backAction?.invoke() }
        }
    private val heading =
        MobileUi.text(activity, "Password Manager", 20f, bold = true).apply {
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
    private val lockButton = MobileUi.textButton(activity, "Lock") { lock() }
    /** Pinned above the scrolling page (the vault search), so it never scrolls away. */
    private val header =
        LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), 0, dp(20), 0)
            visibility = View.GONE
        }
    /** The page's main creation action, floating over the list (Material extended FAB). */
    private val fab =
        com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton(activity).apply {
            setIconResource(R.drawable.pm_icon_add)
            iconTint =
                android.content.res.ColorStateList.valueOf(MobileUi.color(activity, R.color.pm_on_accent))
            setTextColor(MobileUi.color(activity, R.color.pm_on_accent))
            backgroundTintList =
                android.content.res.ColorStateList.valueOf(MobileUi.color(activity, R.color.pm_accent))
            isAllCaps = false
            visibility = View.GONE
        }
    /** Icon actions for the current page, such as the item's favorite star. */
    private val barActions = LinearLayout(activity).apply { gravity = Gravity.CENTER_VERTICAL }
    private val progress =
        ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = true
            visibility = View.GONE
            contentDescription = "Working"
        }
    private val actions =
        LinearLayout(activity).apply {
            setPadding(dp(16), dp(10), dp(16), dp(10))
            setBackgroundColor(MobileUi.color(activity, R.color.pm_surface))
            visibility = View.GONE
        }
    /** Material bottom navigation: real tab semantics for TalkBack and the standard look. */
    private val tabs = listOf("Vault", "Tools", "Settings")
    private var syncingTab = false
    private val navigation =
        com.google.android.material.bottomnavigation.BottomNavigationView(activity).apply {
            val icons = listOf(R.drawable.pm_icon_vault, R.drawable.pm_icon_tools, R.drawable.pm_icon_settings)
            tabs.forEachIndexed { index, name -> menu.add(0, index + 1, index, name).setIcon(icons[index]) }
            labelVisibilityMode =
                com.google.android.material.navigation.NavigationBarView.LABEL_VISIBILITY_LABELED
            setBackgroundColor(MobileUi.color(activity, R.color.pm_surface))
            setOnItemSelectedListener { item ->
                if (!syncingTab) navigate(item.title.toString())
                true
            }
            // Tapping the current tab again returns to its start page. Showing the
            // current tab from code (syncingTab) must not navigate, or it would loop.
            setOnItemReselectedListener { item -> if (!syncingTab) navigate(item.title.toString()) }
        }
    private var navRequested = false
    private var unlocked = false
    private var imeVisible = false
    var backAction: (() -> Unit)? = null

    init {
        (content.parent as? ViewGroup)?.removeView(content)
        val bar =
            LinearLayout(activity).apply {
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(12), dp(6), dp(12), dp(6))
                minimumHeight = dp(64)
            }
        bar.addView(back, LinearLayout.LayoutParams(dp(48), dp(52)))
        bar.addView(heading, LinearLayout.LayoutParams(0, -2, 1f))
        ViewCompat.setAccessibilityHeading(heading, true)
        bar.addView(barActions, LinearLayout.LayoutParams(-2, -2))
        bar.addView(lockButton, LinearLayout.LayoutParams(-2, dp(48)))
        root.addView(bar)
        root.addView(progress, LinearLayout.LayoutParams(-1, dp(3)))
        root.addView(header, LinearLayout.LayoutParams(-1, -2))
        content.setPadding(dp(20), dp(12), dp(20), dp(28))
        content.isFocusableInTouchMode = true
        scroll.addView(content, ViewGroup.LayoutParams(-1, -2))
        val body = android.widget.FrameLayout(activity)
        body.addView(scroll, android.widget.FrameLayout.LayoutParams(-1, -1))
        body.addView(
            fab,
            android.widget.FrameLayout.LayoutParams(-2, -2, Gravity.BOTTOM or Gravity.END).apply {
                setMargins(dp(16), dp(16), dp(16), dp(16))
            },
        )
        root.addView(body, LinearLayout.LayoutParams(-1, 0, 1f))
        root.addView(actions)
        root.addView(navigation)
        activity.setContentView(root)
        WindowCompat.setDecorFitsSystemWindows(activity.window, false)
        val dark =
            activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
                Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(activity.window, root).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
        }
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars =
                insets.getInsets(
                    WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
                )
            val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
            imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
            root.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
            navigation.visibility = if (navRequested && !imeVisible) View.VISIBLE else View.GONE
            insets
        }
        ViewCompat.requestApplyInsets(root)
    }

    /** Pins [view] above the scrolling content until the next page. */
    fun pinHeader(view: View) {
        (view.parent as? ViewGroup)?.removeView(view)
        header.addView(view)
        header.visibility = View.VISIBLE
    }

    /** Shows the floating creation button for this page; the next page hides it. */
    fun floatingAction(label: String, action: () -> Unit) {
        fab.text = label
        fab.contentDescription = label
        fab.setOnClickListener { action() }
        fab.visibility = View.VISIBLE
        // Leave room so the button never covers the last row.
        content.setPadding(dp(20), dp(12), dp(20), dp(96))
    }

    private fun resetPageChrome() {
        barActions.removeAllViews()
        header.removeAllViews()
        header.visibility = View.GONE
        fab.visibility = View.GONE
        content.setPadding(dp(20), dp(12), dp(20), dp(28))
    }

    /** Adds an icon button to the app bar for this page; the next page removes it. */
    fun barAction(icon: Int, description: String, action: () -> Unit) {
        barActions.addView(
            ImageButton(activity).apply {
                setImageResource(icon)
                contentDescription = description
                background =
                    android.graphics.drawable.RippleDrawable(
                        android.content.res.ColorStateList.valueOf(
                            MobileUi.color(activity, R.color.pm_accent_soft)
                        ),
                        null,
                        MobileUi.shape(activity, radius = 24),
                    )
                setOnClickListener { action() }
            },
            LinearLayout.LayoutParams(dp(48), dp(48)),
        )
    }

    fun page(title: String) {
        resetPageChrome()
        actions.removeAllViews()
        actions.visibility = View.GONE
        heading.text = title
        back.visibility = View.VISIBLE
        lockButton.visibility = if (unlocked) View.VISIBLE else View.GONE
        navigation.visibility = View.GONE
        navRequested = false
        scroll.post { scroll.scrollTo(0, 0) }
        WindowInsetsControllerCompat(activity.window, root).hide(WindowInsetsCompat.Type.ime())
    }

    fun root(tab: String, unlocked: Boolean) {
        resetPageChrome()
        this.unlocked = unlocked
        back.visibility = View.GONE
        backAction = null
        lockButton.visibility = if (unlocked) View.VISIBLE else View.GONE
        navRequested = true
        navigation.visibility = if (imeVisible) View.GONE else View.VISIBLE
        // Show which tab is current without navigating again.
        val id = tabs.indexOf(tab).coerceAtLeast(0) + 1
        if (navigation.selectedItemId != id) {
            syncingTab = true
            try {
                navigation.selectedItemId = id
            } finally {
                syncingTab = false
            }
        }
    }

    fun pin(first: View, second: View) {
        actions.removeAllViews()
        for (view in listOf(first, second)) {
            (view.parent as? ViewGroup)?.removeView(view)
            actions.addView(
                view,
                LinearLayout.LayoutParams(0, -2, 1f).apply {
                    marginStart = dp(4)
                    marginEnd = dp(4)
                },
            )
        }
        actions.visibility = View.VISIBLE
    }

    fun working(visible: Boolean) {
        val wasVisible = progress.visibility == View.VISIBLE
        progress.visibility = if (visible) View.VISIBLE else View.GONE
        // Screen readers hear when longer work starts; results announce themselves.
        if (visible && !wasVisible)
            progress.postDelayed(
                { if (progress.visibility == View.VISIBLE) progress.announceForAccessibility("Working") },
                700,
            )
    }

    fun clear() {
        resetPageChrome()
        actions.removeAllViews()
        actions.visibility = View.GONE
        unlocked = false
        heading.text = "Password Manager"
        working(false)
        lockButton.visibility = View.GONE
        backAction = null
        navigation.visibility = View.GONE
        navRequested = false
    }
}
