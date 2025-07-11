package com.encryption

class EncryptionUtil {
    companion object {
        fun getNormalizedText(text: String): String {
            return text.uppercase().filter { it in 'A'..'Z' }
        }

        fun collapseRepeatedString(s: String): String {
            val n = s.length
            for (i in 1..n / 2) {
                val part = s.substring(0, i)
                val repeated = part.repeat(n / i)
                if (repeated == s) {
                    return part
                }
            }

            return s
        }
    }
}