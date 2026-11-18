package dev.nelszack.passwordmanager

object VerificationFields {
    fun isCode(hints: String): Boolean {
        val normalized = hints.lowercase().replace(Regex("[^a-z0-9]"), "")
        return listOf(
                "onetimecode",
                "onetimepassword",
                "verificationcode",
                "authenticatorcode",
                "totppin",
                "totpcode",
                "smsotp",
            )
            .any(normalized::contains) ||
            hints.lowercase().split(Regex("[^a-z0-9]+")).any { it == "otp" || it == "totp" }
    }
}
