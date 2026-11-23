package dev.nelszack.passwordmanager

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Field descriptions as the autofill service sees them in real apps and in Chrome pages (view ID,
 * hint, HTML attributes and autofill hints, joined and lowercased like [Forms.read] does), with
 * the sign-in role each should get. Add a row for every misclassified field found in the wild.
 */
class AutofillFieldCorpusTest {
    private data class Case(
        val source: String,
        val inputType: Int,
        val expected: LoginRole?,
        val descriptions: List<String>,
    )

    private val text = InputType.TYPE_CLASS_TEXT
    private val email = text or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
    private val password = text or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val webPassword = text or InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
    private val numberPassword = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
    private val number = InputType.TYPE_CLASS_NUMBER

    private fun case(source: String, inputType: Int, expected: LoginRole?, vararg descriptions: String) =
        Case(source, inputType, expected, descriptions.toList())

    private val corpus =
        listOf(
            // Chrome pages: autocomplete, type, name, id, label.
            case("web login username", text, LoginRole.USERNAME, "username", "text", "login", "login_field"),
            case("web login password", webPassword, LoginRole.PASSWORD, "current-password", "password", "password"),
            case("web email-first sign-in", text, LoginRole.USERNAME, "username webauthn", "email", "identifier"),
            case("web signup new password", webPassword, LoginRole.PASSWORD, "new-password", "password", "new_password"),
            case("web confirm password", webPassword, LoginRole.PASSWORD, "new-password", "password", "confirm_password"),
            case("web one-time code", number, LoginRole.CODE, "one-time-code", "text", "otp", "Verification code"),
            case("web authenticator code", text, LoginRole.CODE, "totpPin", "Authenticator code"),
            case("web search box", text, null, "search", "q", "site-search"),
            case("web coupon code", text, null, "coupon_code", "Promo code"),
            case("web masked card CVV", webPassword, null, "cc-csc", "password", "cvv"),
            case("web masked card security code", webPassword, null, "password", "card-security-code"),
            case("web zip code", text, null, "postal-code", "zip"),
            // A lone newsletter email looks the same as identifier-first sign-in; it is
            // offered login fill on purpose.
            case("web newsletter email", text, LoginRole.USERNAME, "email", "newsletter_email"),
            // Native apps: resource ID entry, hint and android:autofillHints.
            case("app email field", email, LoginRole.USERNAME, "et_email", "Email address"),
            case("app username hint only", text, LoginRole.USERNAME, "username"),
            case("app password field", password, LoginRole.PASSWORD, "et_password", "Password"),
            case("app numeric PIN", numberPassword, LoginRole.PASSWORD, "pin_entry", "PIN"),
            case("app SMS one-time password", number, LoginRole.CODE, "sms_otp", "Code we texted you"),
            case("app plain number", number, null, "quantity", "How many"),
            case("app display name", text, null, "display_name", "Your name"),
        )

    @Test
    fun corpusFieldsGetTheirSignInRoles() {
        val mismatches =
            corpus.mapNotNull { case ->
                val hints = case.descriptions.joinToString(" ").lowercase()
                val actual = Forms.loginRole(hints, case.inputType)
                if (actual == case.expected) null
                else "${case.source}: expected ${case.expected}, got $actual"
            }
        assertEquals(emptyList<String>(), mismatches)
    }
}
