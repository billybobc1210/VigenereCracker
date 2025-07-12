package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.vigenere.encipher.VigenereCipher
import kotlin.math.pow
import kotlin.math.sqrt

class VigenereSolution(val key: String, val plainText: String)

class VigenereCracker {
    fun crack(cipherText: String): VigenereSolution {
        val mostLikelyKeyLength = getMostLikelyKeyLength(cipherText, 2..15)
        val mostLikelyKey = getMostLikelyKey(cipherText, mostLikelyKeyLength)
        val vigenereCipher = VigenereCipher()
        val mostLikelyPlainText = vigenereCipher.decipher(cipherText, mostLikelyKey)

        return VigenereSolution(mostLikelyKey, mostLikelyPlainText)
    }

    fun getCharFrequencyMap(text: String): List<Map.Entry<Char, Double>> {
        val result = text
            .groupingBy { it }
            .eachCount()
            .toMutableMap()

        for (c in 'A'..'Z') {
            result.putIfAbsent(c, 0)
        }

        return result.mapValues { it.value.toDouble() / text.length }.entries
            .sortedByDescending { it.value }
    }

    fun getStandardDeviation(frequencyMap: List<Map.Entry<Char, Double>>): Double {
        val values = frequencyMap.map { it.value }
        val mean = values.average()
        val variance = values.sumOf { (it - mean).pow(2) } / values.size

        return sqrt(variance)
    }

    fun buildStringFromEveryNthChar(text: String, n: Int, offset: Int = 0): String {
        return text.substring(offset).filterIndexed { index, _ -> index % n == 0 }
    }

    fun getKeyLengthScore(cipherText: String, keyLength: Int): Double {
        var stdDevSum = 0.0

        for (keyCharPosition in 0 until keyLength) {
            val cipherSlice = buildStringFromEveryNthChar(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getCharFrequencyMap(cipherSlice)
            stdDevSum += getStandardDeviation(cipherFrequencyMap)
        }

        return stdDevSum / keyLength.toDouble()
    }

    fun getMostLikelyKeyLength(cipherText: String, keyLengthRange: IntRange): Int {
        var result = 0
        var bestScore = 0.0
        var scores = mutableMapOf<Int, Double>()

        for (keyLengthCandidate in keyLengthRange) {
            val score = getKeyLengthScore(cipherText, keyLengthCandidate)
            scores[keyLengthCandidate] = score

            if (score > bestScore) {
                bestScore = score
                result = keyLengthCandidate
            }
        }

        var factors = EncryptionUtil.getIntegerFactors(result, false)

        for (factor in factors) {
            var isLikeyTrueKeyLength = true

            for (i in factor until result step factor) {
                scores[i]?.let {
                    if (bestScore / it > 1.1) {
                        isLikeyTrueKeyLength = false
                    }
                }

                if (!isLikeyTrueKeyLength) {
                    break;
                }
            }

            if (isLikeyTrueKeyLength) {
                return factor
            }
        }

        return result
    }

    fun getMostLikelyKey(cipherText: String, keyLength: Int): String {
        val keyCharCandidatesByKeyCharPosition = mutableListOf<List<Char>>()

        for (keyCharPosition in 0 until keyLength) {
            val cipherSlice = buildStringFromEveryNthChar(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getCharFrequencyMap(cipherSlice)
            var mostFrequentCipherChar = cipherFrequencyMap[0].key

            val keyCharCandidates = mutableListOf<Char>()

            for (c in TOP_10_ENGLISH_LETTERS) {
                getKeyCharForSpeculatedPlainChar(mostFrequentCipherChar, c)?.let { keyCharCandidates.add(it) }
            }

            keyCharCandidatesByKeyCharPosition.add(keyCharCandidates)
        }

        val vigenereCipher = VigenereCipher()

        // Initialize 'bestKeyCharCandidates' to be the first key char candidate for each key char position.
        // Basically, we are assuming to start out with, that the most common cipher character in each
        // cipher slice represented a plain text 'E' (the first character in TOP_10_ENGLISH_LETTERS).
        val bestKeyCharCandidates = keyCharCandidatesByKeyCharPosition.map { it[0] }.toMutableList()
        var currentBestKey = bestKeyCharCandidates.map { it }.joinToString("")
        var prevBestKey = ""

        // Iteratively try to improve the best key until there was no improvement from the last iteration.
        while (prevBestKey != currentBestKey) {
            prevBestKey = currentBestKey

            // Loop through all key char positions, testing all key char candidates at 'keyCharPosition' and
            // updating 'bestKeyCharCandidates[keyCharPosition]' when we find a new key char candidate at
            // that position that yields better plain text results than the previous best.
            for (keyCharPosition in 0 until keyLength) {
                // Use 'bestKeyCharCandidates[key char position]' to build the key for all key char
                // positions other than 'keyCharPosition'.
                val startOfKeyBuilder = StringBuilder()

                for (startOfKeyCharPosition in 0 until keyCharPosition) {
                    startOfKeyBuilder.append(bestKeyCharCandidates[startOfKeyCharPosition])
                }

                val endOfKeyBuilder = StringBuilder()

                for (endOfKeyCharPosition in keyCharPosition + 1 until keyLength) {
                    endOfKeyBuilder.append(bestKeyCharCandidates[endOfKeyCharPosition])
                }

                var bestEnglishScore = 0.0

                // Loop thru all key char candidates at 'keyCharPosition', using each of them to build a new key
                // and testing to find the best key char candidate at this position.
                for (keyCharCandidate in keyCharCandidatesByKeyCharPosition[keyCharPosition]) {
                    val completeKeyBuilder = StringBuilder(startOfKeyBuilder)
                        .append(keyCharCandidate)
                        .append(endOfKeyBuilder)

                    val plainText = vigenereCipher.decipher(cipherText, completeKeyBuilder)
                    val englishScore = getEnglishPlainTextScore(plainText)

                    if (englishScore > bestEnglishScore) {
                        // Found better character from key char candidates at this key character position,
                        // so we update 'bestKeyCharCandidates[keyCharPosition]' with the new best key char
                        // candidate.
                        bestEnglishScore = englishScore
                        bestKeyCharCandidates[keyCharPosition] = keyCharCandidate
                    }
                }
            }

            currentBestKey = bestKeyCharCandidates.map { it }.joinToString("")
        }

        return EncryptionUtil.collapseRepeatedString(currentBestKey)
    }

    fun getEnglishPlainTextScore(plainText: String): Double {
        return ((1.0 * getEnglishNgramCount(plainText, 2).toDouble()) +
                (2.0 * getEnglishNgramCount(plainText, 3).toDouble()) +
                (4.0 * getEnglishNgramCount(plainText, 4).toDouble())) /
                plainText.length.toDouble()
    }

    fun getEnglishNgramCount(plainText: String, n: Int): Int {
        var result = 0

        TOP_10_ENGLISH_NGRAMS[n]?.let { nGramSet ->
            for (i in 0 until plainText.length - n + 1) {
                val nGram = plainText.substring(i, i + n)
                if (nGram in nGramSet) {
                    result++
                }
            }
        }

        return result
    }

    fun getKeyCharForSpeculatedPlainChar(cipherChar: Char, speculatedPlainChar: Char): Char? {
        var result: Char? = null

        for (keyChar in 'A' .. 'Z') {
            VigenereCipher.TABULA_RECTA[keyChar]
                ?.getOrNull(speculatedPlainChar - 'A')
                ?.let {
                    if (it == cipherChar) {
                        return keyChar
                    }
                }
        }

        return result
    }

    companion object {
        val TOP_10_ENGLISH_LETTERS = listOf(
            'E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D'
        )

        val TOP_10_ENGLISH_BIGRAMS = setOf(
            "TH", "HE", "IN", "ER", "AN", "RE", "ND", "AT", "ON", "NT",
        )

        val TOP_10_ENGLISH_TRIGRAMS = setOf(
            "THE", "AND", "ING", "HER", "ENG", "ION", "THA", "NTH", "INT", "ERE",
        )

        val TOP_10_ENGLISH_QUADRIGRAMS = setOf(
            "TION", "THER", "WITH", "MENT", "IONS", "HERE", "THAT", "OULD", "IGHT", "HAVE",
        )

        val TOP_10_ENGLISH_NGRAMS = mapOf(
            2 to TOP_10_ENGLISH_BIGRAMS,
            3 to TOP_10_ENGLISH_TRIGRAMS,
            4 to TOP_10_ENGLISH_QUADRIGRAMS
        )
    }
}