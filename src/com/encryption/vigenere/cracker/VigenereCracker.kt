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

        for (keyLength in keyLengthRange) {
            var score = getKeyLengthScore(cipherText, keyLength)

            if (score > bestScore) {
                bestScore = score
                result = keyLength
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
        val bestKeyCharCandidates = keyCharCandidatesByKeyCharPosition.map { it[0] }.toMutableList()
        var currentBestKey = bestKeyCharCandidates.map { it }.joinToString("")
        var prevBestKey = ""

        while (prevBestKey != currentBestKey) {
            prevBestKey = currentBestKey

            for (keyCharPosition in 0 until keyLength) {
                val startOfKeyBuilder = StringBuilder()

                for (startKeyCharPosition in 0 until keyCharPosition) {
                    startOfKeyBuilder.append(bestKeyCharCandidates[startKeyCharPosition])
                }

                var bestEnglishScore = 0.0

                for (newBestKeyCharCandidate in keyCharCandidatesByKeyCharPosition[keyCharPosition]) {
                    val completeKeyBuilder = StringBuilder(startOfKeyBuilder)
                    completeKeyBuilder.append(newBestKeyCharCandidate)

                    for (tailKeyCharPosition in keyCharPosition + 1 until keyLength) {
                        completeKeyBuilder.append(bestKeyCharCandidates[tailKeyCharPosition])
                    }

                    val plainText = vigenereCipher.decipher(cipherText, completeKeyBuilder.toString())
                    val englishScore = getEnglishPlainTextScore(plainText)

                    if (englishScore > bestEnglishScore) {
                        bestEnglishScore = englishScore
                        bestKeyCharCandidates[keyCharPosition] = newBestKeyCharCandidate
                    }
                }
            }

            currentBestKey = bestKeyCharCandidates.map { it }.joinToString("")
        }

        return EncryptionUtil.collapseRepeatedString(currentBestKey)
    }

    fun getEnglishPlainTextScore(plainText: String): Double {
        return ((1.0 * getEnglishNgramCount(plainText, 2).toDouble()) +
                (1.1 * getEnglishNgramCount(plainText, 3).toDouble()) +
                (1.2 * getEnglishNgramCount(plainText, 4).toDouble())) /
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
            var found = false
            TABULA_RECTA[keyChar]
                ?.getOrNull(speculatedPlainChar - 'A')
                ?.let {
                    if (it == cipherChar) {
                        result = keyChar
                        found = true
                    }
                }

            if (found) {
                break
            }
        }

        return result
    }

    companion object {
        val TABULA_RECTA = mapOf(
            'A' to "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            'B' to "BCDEFGHIJKLMNOPQRSTUVWXYZA",
            'C' to "CDEFGHIJKLMNOPQRSTUVWXYZAB",
            'D' to "DEFGHIJKLMNOPQRSTUVWXYZABC",
            'E' to "EFGHIJKLMNOPQRSTUVWXYZABCD",
            'F' to "FGHIJKLMNOPQRSTUVWXYZABCDE",
            'G' to "GHIJKLMNOPQRSTUVWXYZABCDEF",
            'H' to "HIJKLMNOPQRSTUVWXYZABCDEFG",
            'I' to "IJKLMNOPQRSTUVWXYZABCDEFGH",
            'J' to "JKLMNOPQRSTUVWXYZABCDEFGHI",
            'K' to "KLMNOPQRSTUVWXYZABCDEFGHIJ",
            'L' to "LMNOPQRSTUVWXYZABCDEFGHIJK",
            'M' to "MNOPQRSTUVWXYZABCDEFGHIJKL",
            'N' to "NOPQRSTUVWXYZABCDEFGHIJKLM",
            'O' to "OPQRSTUVWXYZABCDEFGHIJKLMN",
            'P' to "PQRSTUVWXYZABCDEFGHIJKLMNO",
            'Q' to "QRSTUVWXYZABCDEFGHIJKLMNOP",
            'R' to "RSTUVWXYZABCDEFGHIJKLMNOPQ",
            'S' to "STUVWXYZABCDEFGHIJKLMNOPQR",
            'T' to "TUVWXYZABCDEFGHIJKLMNOPQRS",
            'U' to "UVWXYZABCDEFGHIJKLMNOPQRST",
            'V' to "VWXYZABCDEFGHIJKLMNOPQRSTU",
            'W' to "WXYZABCDEFGHIJKLMNOPQRSTUV",
            'X' to "XYZABCDEFGHIJKLMNOPQRSTUVW",
            'Y' to "YZABCDEFGHIJKLMNOPQRSTUVWX",
            'Z' to "ZABCDEFGHIJKLMNOPQRSTUVWXY",
        )

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