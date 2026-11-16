package dev.nelszack.passwordmanager

import org.junit.Assert.*
import org.junit.Test

class VerificationFieldsTest {
    @Test fun recognizesExplicitCodeHintsWithoutGuessingFromANumericInput() {
        for (hint in listOf("one-time-code", "totpPin", "verificationCode", "smsOTP", "otp", "authenticator code")) {
            assertTrue(hint, VerificationFields.isCode(hint))
        }
        for (hint in listOf("password", "username", "email", "coupon code", "zip code", "pin", "cvv", "account number")) {
            assertFalse(hint, VerificationFields.isCode(hint))
        }
    }
}
