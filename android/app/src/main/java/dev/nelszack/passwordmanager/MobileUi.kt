package dev.nelszack.passwordmanager

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.*
import android.graphics.drawable.*
import android.text.SpannableString
import android.text.Spanned
import android.text.style.*
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.core.content.ContextCompat

/** Native components shared by management screens; autofill keeps its compact presentation. */
internal object MobileUi {
    fun dp(context: Context, value: Int) =
        (context.resources.displayMetrics.density * value).toInt()

    fun color(context: Context, id: Int) = ContextCompat.getColor(context, id)

    fun shape(
        context: Context,
        fill: Int = R.color.pm_surface,
        outline: Boolean = false,
        radius: Int = 16,
    ): GradientDrawable =
        GradientDrawable().apply {
            setColor(color(context, fill))
            cornerRadius = dp(context, radius).toFloat()
            if (outline) setStroke(dp(context, 1), color(context, R.color.pm_outline))
        }

    fun ripple(
        context: Context,
        fill: Int = R.color.pm_surface,
        outline: Boolean = true,
    ): RippleDrawable =
        RippleDrawable(
            ColorStateList.valueOf(color(context, R.color.pm_accent_soft)),
            shape(context, fill, outline),
            shape(context),
        )

    fun text(
        context: Context,
        value: String,
        size: Float = 15f,
        muted: Boolean = false,
        bold: Boolean = false,
    ) =
        TextView(context).apply {
            text = value
            textSize = size
            setTextColor(color(context, if (muted) R.color.pm_muted else R.color.pm_text))
            typeface =
                Typeface.create(if (bold) "sans-serif-medium" else "sans-serif", Typeface.NORMAL)
            setLineSpacing(dp(context, 3).toFloat(), 1f)
        }

    fun margins(context: Context, bottom: Int = 10) =
        LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(context, bottom) }

    fun button(
        context: Context,
        title: String,
        primary: Boolean = false,
        danger: Boolean = false,
        action: () -> Unit,
    ) =
        Button(context).apply {
            text = title
            isAllCaps = false
            textSize = 15f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            minHeight = dp(context, 52)
            minimumHeight = dp(context, 52)
            minWidth = 0
            stateListAnimator = null
            setPadding(dp(context, 18), dp(context, 12), dp(context, 18), dp(context, 12))
            gravity = Gravity.CENTER
            background =
                ripple(context, if (primary) R.color.pm_accent else R.color.pm_surface, !primary)
            setTextColor(
                color(
                    context,
                    if (primary) R.color.pm_on_accent
                    else if (danger) R.color.pm_danger else R.color.pm_text,
                )
            )
            layoutParams = margins(context)
            setOnClickListener { action() }
        }

    fun row(
        context: Context,
        title: String,
        subtitle: String,
        badge: String = "",
        action: () -> Unit,
    ): Button =
        button(context, title, action = action).apply {
            val value = if (subtitle.isBlank()) title else "$title\n$subtitle"
            text =
                SpannableString(value).apply {
                    setSpan(
                        StyleSpan(Typeface.BOLD),
                        0,
                        title.length,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                    )
                    if (subtitle.isNotBlank()) {
                        setSpan(
                            RelativeSizeSpan(13f / 15f),
                            title.length + 1,
                            length,
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                        )
                        setSpan(
                            ForegroundColorSpan(color(context, R.color.pm_muted)),
                            title.length + 1,
                            length,
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                        )
                    }
                }
            tag = title
            gravity = Gravity.START or Gravity.CENTER_VERTICAL
            minHeight = dp(context, 76)
            minimumHeight = dp(context, 76)
            setLineSpacing(dp(context, 4).toFloat(), 1f)
            val chevron =
                ContextCompat.getDrawable(context, R.drawable.pm_chevron)?.apply {
                    setBounds(0, 0, dp(context, 20), dp(context, 20))
                }
            val icon =
                if (badge.isBlank()) null
                else
                    Badge(context, badge, ICONS[badge]?.let { ContextCompat.getDrawable(context, it) })
                        .apply { setBounds(0, 0, dp(context, 40), dp(context, 40)) }
            setCompoundDrawablesRelative(icon, null, chevron, null)
            compoundDrawablePadding = dp(context, 12)
        }

    fun field(
        context: Context,
        parent: LinearLayout,
        hint: String,
        value: String,
        secret: Boolean,
    ): EditText {
        val caption =
            text(context, hint, 13f, muted = true, bold = true).apply {
                layoutParams = margins(context, 6)
            }
        parent.addView(caption)
        val container =
            LinearLayout(context).apply {
                gravity = Gravity.CENTER_VERTICAL
                background = shape(context, outline = true, radius = 12)
                layoutParams = margins(context, 16)
            }
        val input =
            EditText(context).apply {
                id = View.generateViewId()
                this.hint = hint
                setText(value)
                isSaveEnabled = false
                inputType =
                    if (secret)
                        android.text.InputType.TYPE_CLASS_TEXT or
                            android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                    else
                        android.text.InputType.TYPE_CLASS_TEXT or
                            android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                background = null
                textSize = 16f
                setTextColor(color(context, R.color.pm_text))
                setHintTextColor(color(context, R.color.pm_muted))
                setPadding(dp(context, 14), dp(context, 14), dp(context, 12), dp(context, 14))
                minHeight = dp(context, 52)
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            }
        caption.labelFor = input.id
        container.addView(input)
        if (secret)
            container.addView(
                button(context, "Show") {
                        val visible = input.transformationMethod == null
                        input.transformationMethod =
                            if (visible)
                                android.text.method.PasswordTransformationMethod.getInstance()
                            else null
                        input.setSelection(input.text.length)
                        val toggle = container.getChildAt(1) as Button
                        toggle.text = if (visible) "Show" else "Hide"
                        toggle.contentDescription = "${toggle.text} $hint"
                    }
                    .apply {
                        contentDescription = "Show $hint"
                        textSize = 12f
                        minWidth = 0
                        background = null
                        setTextColor(color(context, R.color.pm_accent))
                        layoutParams = LinearLayout.LayoutParams(dp(context, 64), -2)
                        setPadding(0, 0, 0, 0)
                    }
            )
        parent.addView(container)
        return input
    }

    fun date(value: String): String = runCatching {
        java.time.OffsetDateTime.parse(value)
            .atZoneSameInstant(java.time.ZoneId.systemDefault())
            .format(
                java.time.format.DateTimeFormatter.ofLocalizedDateTime(
                    java.time.format.FormatStyle.MEDIUM
                )
            )
    }
        .getOrDefault(value)

    fun kindLabel(kind: String) =
        when (kind) {
            "login" -> "Login"
            "secure-note" -> "Secure note"
            "payment-card" -> "Payment card"
            "identity" -> "Identity"
            "wifi" -> "Wi-Fi"
            "software-license" -> "Software license"
            "ssh-key" -> "SSH key"
            "api-secret" -> "API secret"
            else -> kind
        }

    /** Named badges drawn as icons; any other badge text is drawn as a letter. */
    private val ICONS =
        mapOf(
            "search" to R.drawable.pm_icon_search,
            "health" to R.drawable.pm_icon_health,
            "restore" to R.drawable.pm_icon_restore,
            "sync" to R.drawable.pm_icon_sync,
            "settings" to R.drawable.pm_icon_settings,
            "key" to R.drawable.pm_icon_key,
            "add" to R.drawable.pm_icon_add,
            "open" to R.drawable.pm_icon_open,
        )

    /** Logins show their first letter; other types show their type badge. */
    fun initial(name: String, kind: String): String =
        if (kind == "login")
            name.firstOrNull(Char::isLetterOrDigit)?.uppercaseChar()?.toString() ?: "L"
        else kindBadge(kind)

    fun kindBadge(kind: String) =
        when (kind) {
            "secure-note" -> "N"
            "payment-card" -> "C"
            "identity" -> "ID"
            "wifi" -> "W"
            "software-license" -> "K"
            "ssh-key" -> "S"
            "api-secret" -> "A"
            else -> "L"
        }

    private class Badge(
        private val context: Context,
        private val value: String,
        private val icon: Drawable? = null,
    ) : Drawable() {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)

        override fun draw(canvas: Canvas) {
            paint.color = color(context, R.color.pm_accent_soft)
            canvas.drawRoundRect(
                RectF(bounds),
                dp(context, 12).toFloat(),
                dp(context, 12).toFloat(),
                paint,
            )
            if (icon != null) {
                val inset = bounds.width() / 4
                icon.setBounds(
                    bounds.left + inset,
                    bounds.top + inset,
                    bounds.right - inset,
                    bounds.bottom - inset,
                )
                icon.setTint(color(context, R.color.pm_accent))
                icon.draw(canvas)
                return
            }
            paint.color = color(context, R.color.pm_accent)
            paint.textAlign = Paint.Align.CENTER
            paint.typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            paint.textSize = dp(context, 16).toFloat()
            canvas.drawText(
                value,
                bounds.exactCenterX(),
                bounds.exactCenterY() - (paint.ascent() + paint.descent()) / 2,
                paint,
            )
        }

        override fun setAlpha(alpha: Int) {
            paint.alpha = alpha
        }

        override fun setColorFilter(filter: ColorFilter?) {
            paint.colorFilter = filter
        }

        @Deprecated("Android drawable opacity") override fun getOpacity() = PixelFormat.TRANSLUCENT
    }
}
