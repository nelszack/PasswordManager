package dev.nelszack.passwordmanager

internal data class MobilePreference(val key: String, val title: String, val unit: String, val help: String, val range: LongRange)
internal object MobilePreferences {
    val fields = listOf(
        MobilePreference("unlock_seconds","Lock after inactivity","seconds","Time without activity before the vault locks. 300 seconds is 5 minutes. Leaving the app or turning off the screen also locks it, except for a temporary completed autofill session.",15L..86400L),
        MobilePreference("clipboard_seconds","Clear copied secrets after","seconds","How long a copied secret stays on the clipboard before the app tries to clear it. Verification codes can expire sooner.",1L..300L),
        MobilePreference("history_limit","Previous passwords to keep","passwords per item","Keep this many older passwords for each item. Zero stops keeping old passwords on future changes.",0L..1000L),
        MobilePreference("trash_days","Deleted-item retention","days","Used only when you choose Apply configured trash retention in Deleted items. Zero disables age-based purging. Changing this value never deletes items automatically.",0L..36500L),
        MobilePreference("generator_length","Generated password length","characters","Number of characters in new passwords. Existing passwords are unchanged.",1L..255L),
        MobilePreference("passphrase_words","Generated passphrase length","words","Number of words in new passphrases, separated by your chosen separator, such as a hyphen.",1L..64L)
    )
    fun duration(seconds: Long): String {
        val hours=seconds/3600; val minutes=(seconds%3600)/60; val rest=seconds%60
        return listOf(hours to "hour",minutes to "minute",rest to "second").filter { it.first>0 }.joinToString(" ") { (n,unit)->"$n $unit${if(n==1L) "" else "s"}" }.ifEmpty { "0 seconds" }
    }
    fun summary(key: String, value: Long) = when(key) {
        "unlock_seconds","clipboard_seconds" -> duration(value)
        "history_limit" -> if(value==0L) "History off for future password changes" else "$value previous ${if(value==1L) "password" else "passwords"} per item"
        "trash_days" -> if(value==0L) "Age-based purging is off" else "$value days · applied manually"
        "generator_length" -> "$value characters"
        "passphrase_words" -> "$value words"
        else -> value.toString()
    }
}
