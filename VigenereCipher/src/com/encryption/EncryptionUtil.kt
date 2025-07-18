package com.encryption

import kotlin.math.abs
import kotlin.math.sqrt

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

        fun getIntegerFactors(n: Int, includeTrivial: Boolean = true): List<Int> {
            var result = mutableSetOf<Int>()

            if (n != 0) {
                val absValue = abs(n)
                val start = if (includeTrivial) 1 else 2
                val end = sqrt(absValue.toDouble()).toInt()

                for (i in start..end) {
                    if (absValue % i == 0) {
                        result.add(i)
                        result.add(absValue / i)
                    }
                }
            }

            return result.sorted()
        }
    }
}