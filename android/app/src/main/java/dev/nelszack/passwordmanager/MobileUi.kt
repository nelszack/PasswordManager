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
    /** A short human-readable file size. */
    fun byteSize(bytes: Long): String =
        when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format(java.util.Locale.ROOT, "%.1f KiB", bytes / 1024.0)
            else -> String.format(java.util.Locale.ROOT, "%.1f MiB", bytes / 1048576.0)
        }

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
            if (outline) setStroke(dp(context, 1), color(context, R.color.pm_edge))
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

    /**
     * A Material 3 button: filled for the main action, outlined otherwise, and outlined in the
     * error color for destructive actions.
     */
    fun button(
        context: Context,
        title: String,
        primary: Boolean = false,
        danger: Boolean = false,
        action: () -> Unit,
    ): Button {
        val style =
            if (primary) com.google.android.material.R.attr.materialButtonStyle
            else com.google.android.material.R.attr.materialButtonOutlinedStyle
        return com.google.android.material.button.MaterialButton(context, null, style).apply {
            text = title
            isAllCaps = false
            textSize = 15f
            minHeight = dp(context, 52)
            minimumHeight = dp(context, 52)
            insetTop = 0
            insetBottom = 0
            cornerRadius = dp(context, 14)
            if (danger) {
                val red = ColorStateList.valueOf(color(context, R.color.pm_danger))
                setTextColor(red)
                strokeColor = red
            } else if (!primary) {
                strokeColor = ColorStateList.valueOf(color(context, R.color.pm_edge))
                setTextColor(color(context, R.color.pm_text))
            }
            layoutParams = margins(context)
            setOnClickListener { action() }
        }
    }

    /** A Material text button, for low-emphasis actions such as the app bar's Lock. */
    fun textButton(context: Context, title: String, action: () -> Unit): Button =
        com.google.android.material.button.MaterialButton(
                context,
                null,
                com.google.android.material.R.attr.borderlessButtonStyle,
            )
            .apply {
                text = title
                isAllCaps = false
                textSize = 15f
                minHeight = dp(context, 48)
                minimumHeight = dp(context, 48)
                insetTop = 0
                insetBottom = 0
                setOnClickListener { action() }
            }

    /** A Material filter chip for list filters. */
    fun chip(context: Context, title: String, checked: Boolean, action: () -> Unit) =
        com.google.android.material.chip.Chip(context).apply {
            text = title
            isCheckable = true
            isChecked = checked
            isCheckedIconVisible = true
            setEnsureMinTouchTargetSize(true)
            setOnClickListener { action() }
        }

    fun row(
        context: Context,
        title: String,
        subtitle: String,
        badge: String = "",
        action: () -> Unit,
    ): Button =
        Button(context).apply {
            isAllCaps = false
            textSize = 15f
            stateListAnimator = null
            setPadding(dp(context, 18), dp(context, 12), dp(context, 18), dp(context, 12))
            background = ripple(context)
            setTextColor(color(context, R.color.pm_text))
            layoutParams = margins(context)
            setOnClickListener { action() }
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

    /** A Material outlined text field; secret fields get a show/hide toggle. */
    fun field(
        context: Context,
        parent: LinearLayout,
        hint: String,
        value: String,
        secret: Boolean,
    ): EditText {
        val box =
            com.google.android.material.textfield.TextInputLayout(
                    context,
                    null,
                    com.google.android.material.R.attr.textInputOutlinedStyle,
                )
                .apply {
                    this.hint = hint
                    boxStrokeColor = color(context, R.color.pm_accent)
                    setBoxCornerRadii(
                        dp(context, 12).toFloat(),
                        dp(context, 12).toFloat(),
                        dp(context, 12).toFloat(),
                        dp(context, 12).toFloat(),
                    )
                    if (secret)
                        endIconMode =
                            com.google.android.material.textfield.TextInputLayout.END_ICON_PASSWORD_TOGGLE
                    layoutParams = margins(context, 16)
                }
        val input =
            com.google.android.material.textfield.TextInputEditText(box.context).apply {
                id = View.generateViewId()
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
                textSize = 16f
                minHeight = dp(context, 56)
            }
        box.addView(input)
        parent.addView(box)
        return input
    }

    /** Changes the label of an input made by [field] (the show/hide toggle follows it). */
    fun relabel(input: EditText, label: String) {
        layoutOf(input)?.hint = label
    }

    /** The Material field wrapping [input], if it has one. */
    fun layoutOf(input: View): com.google.android.material.textfield.TextInputLayout? {
        var parent = input.parent
        while (parent != null) {
            if (parent is com.google.android.material.textfield.TextInputLayout) return parent
            parent = parent.parent
        }
        return null
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
            "vault" to R.drawable.pm_icon_vault,
            "biometric" to R.drawable.pm_icon_lock,
            "generate" to R.drawable.pm_icon_generate,
            "autofill" to R.drawable.pm_icon_autofill,
            "files" to R.drawable.pm_icon_folder,
            "file" to R.drawable.pm_icon_file,
            // Item types. Names, never letters, so a login's initial is never an icon.
            "type-note" to R.drawable.pm_icon_note,
            "type-card" to R.drawable.pm_icon_card,
            "type-identity" to R.drawable.pm_icon_identity,
            "type-wifi" to R.drawable.pm_icon_wifi,
            "type-license" to R.drawable.pm_icon_license,
            "type-ssh" to R.drawable.pm_icon_terminal,
            "type-api" to R.drawable.pm_icon_code,
        )

    /** Logins show their first letter; other types show their type badge. */
    fun initial(name: String, kind: String): String =
        if (kind == "login")
            name.firstOrNull(Char::isLetterOrDigit)?.uppercaseChar()?.toString() ?: "L"
        else kindBadge(kind)

    fun kindBadge(kind: String) =
        when (kind) {
            "secure-note" -> "type-note"
            "payment-card" -> "type-card"
            "identity" -> "type-identity"
            "wifi" -> "type-wifi"
            "software-license" -> "type-license"
            "ssh-key" -> "type-ssh"
            "api-secret" -> "type-api"
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
