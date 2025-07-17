package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.vigenere.encipher.VigenereCipher
import java.io.File
import kotlin.math.log10
import kotlin.math.pow
import kotlin.math.sqrt

class VigenereSolution(val key: String, val plainText: String)

class VigenereCracker {
    fun crack(cipherTextFile: File): VigenereSolution {
        return crack(EncryptionUtil.getNormalizedText(cipherTextFile.readText()))
    }

    fun crack(cipherText: StringBuilder): VigenereSolution {
        return crack(cipherText.toString())
    }

    fun crack(cipherText: StringBuffer): VigenereSolution {
        return crack(cipherText.toString())
    }

    fun crack(cipherText: String): VigenereSolution {
        val mostLikelyKeyLength = getMostLikelyKeyLength(cipherText, 2..MAX_KEY_LENGTH_CANDIDATE)
        val mostLikelyKey = getMostLikelyKey(cipherText, mostLikelyKeyLength)
        val vigenereCipher = VigenereCipher()
        val mostLikelyPlainText = vigenereCipher.decipher(cipherText, mostLikelyKey)

        return VigenereSolution(mostLikelyKey, mostLikelyPlainText)
    }

    private fun getCharFrequencyMap(text: String): List<Map.Entry<Char, Double>> {
        val result = text
            .groupingBy { it }
            .eachCount()
            .toMutableMap()

        for (c in 'A'..'Z') {
            result.putIfAbsent(c, 0)
        }

        return result.mapValues { it.value.toDouble() / text.length.toDouble() }.entries
            .sortedByDescending { it.value }
    }

    private fun getStandardDeviation(frequencyMap: List<Map.Entry<Char, Double>>): Double {
        val values = frequencyMap.map { it.value }
        val mean = values.average()
        val variance = values.sumOf { (it - mean).pow(2) } / values.size

        return sqrt(variance)
    }

    private fun buildStringFromEveryNthChar(text: String, n: Int, offset: Int = 0): String {
        return text.substring(offset).filterIndexed { index, _ -> index % n == 0 }
    }

    private fun getKeyLengthScore(cipherText: String, keyLength: Int): Double {
        var stdDevSum = 0.0

        for (keyCharPosition in 0 until keyLength) {
            val cipherSlice = buildStringFromEveryNthChar(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getCharFrequencyMap(cipherSlice)
            stdDevSum += getStandardDeviation(cipherFrequencyMap)
        }

        return stdDevSum / keyLength.toDouble()
    }

    private fun getMostLikelyKeyLength(cipherText: String, keyLengthRange: IntRange): Int {
        var bestKeyLengthCandidate = 0
        var bestScore = 0.0
        var worstScore = Double.MAX_VALUE
        var scores = mutableMapOf<Int, Double>()

        for (keyLengthCandidate in keyLengthRange) {
            val score = getKeyLengthScore(cipherText, keyLengthCandidate)
            scores[keyLengthCandidate] = score

            if (score > bestScore) {
                bestScore = score
                bestKeyLengthCandidate = keyLengthCandidate
            }

            if (score < worstScore) {
                worstScore = score
            }
        }

        // Key length scores tend to favor high key lengths over low ones since the scores are based off of the std
        // deviation of the frequency maps on the slices we take from the cipher text.  When we have high key lengths,
        // the slices we take from the cipher text are shorter so they tend to have more anomalous frequency
        // distributions (e.g. more 0-occurrence characters) which makes their std devs higher.  So even if the actual
        // key is length 3, for example, we might have a best key length candidate at this point that is some multiple
        // of 3, for example, 15. When this happens we tend to have similar scores to the high score for the real key
        // length and all its multiples (e.g. 6, 9 and 12). To counter this, we find all the key lengths that have
        // a similar score to the high score.  If the number of similar scores, s, is a factor of the current best key
        // length candidate, then most likely the real key length is the current best key length candidate divided by s.
        val bestToWorstScoreRatio = bestScore / worstScore
        val keyLengthScoreSimilarityLimit = 1.0 + ((bestToWorstScoreRatio - 1.0) / scores.size)
        val similarToBestScore = mutableSetOf<Int>()

        for (keyLengthCandidate in keyLengthRange.first .. bestKeyLengthCandidate) {
            scores[keyLengthCandidate]?.let { score ->
                if (bestScore / score <= keyLengthScoreSimilarityLimit) {
                    similarToBestScore.add(keyLengthCandidate)
                }
            }
        }

        var result = bestKeyLengthCandidate
        val similarityCount = similarToBestScore.size

        if (similarityCount > 1) {
            if (bestKeyLengthCandidate % similarityCount == 0) {
                bestKeyLengthCandidate = bestKeyLengthCandidate / similarityCount

                // One last check to make sure that all the key lengths that gave similar scores are also
                // multiples of the new best key length candidate.
                if (similarToBestScore.all { it % bestKeyLengthCandidate == 0 }) {
                    result = bestKeyLengthCandidate
                }
            }
        }

        return result
    }

    private fun getMostLikelyKey(cipherText: String, keyLength: Int): String {
        val keyCharCandidatesByKeyCharPosition = mutableListOf<List<Char>>()

        for (keyCharPosition in 0 until keyLength) {
            val cipherSlice = buildStringFromEveryNthChar(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getCharFrequencyMap(cipherSlice)
            var mostFrequentCipherChar = cipherFrequencyMap[0].key

            val keyCharCandidates = mutableListOf<Char>()

            for (c in TOP_10_ENGLISH_LETTERS.map { it.key[0] } ) {
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

            // Loop through all key char positions, testing all key char candidates at 'varyingKeyCharPosition' and
            // updating 'bestKeyCharCandidates[varyingKeyCharPosition]' when we find a new key char candidate at
            // that position that yields better plain text results than the previous best.
            for (varyingKeyCharPosition in 0 until keyLength) {
                // Use 'bestKeyCharCandidates[key char position]' to build the key for all key char
                // positions other than 'varyingKeyCharPosition'.
                val startOfKeyBuilder = StringBuilder()

                for (startOfKeyCharPosition in 0 until varyingKeyCharPosition) {
                    startOfKeyBuilder.append(bestKeyCharCandidates[startOfKeyCharPosition])
                }

                val endOfKeyBuilder = StringBuilder()

                for (endOfKeyCharPosition in varyingKeyCharPosition + 1 until keyLength) {
                    endOfKeyBuilder.append(bestKeyCharCandidates[endOfKeyCharPosition])
                }

                var bestEnglishScore = Double.NEGATIVE_INFINITY

                // Loop thru all key char candidates at 'varyingKeyCharPosition', using each of them to build a new key
                // and testing to find the best key char candidate at this position.
                for (keyCharCandidate in keyCharCandidatesByKeyCharPosition[varyingKeyCharPosition]) {
                    val completeKeyBuilder = StringBuilder(startOfKeyBuilder)
                        .append(keyCharCandidate)
                        .append(endOfKeyBuilder)

                    val plainText = vigenereCipher.decipher(cipherText, completeKeyBuilder)
                    val englishScore = getEnglishPlainTextScore(plainText)

                    if (englishScore > bestEnglishScore) {
                        // Found better character from key char candidates at this key character position,
                        // so we update 'bestKeyCharCandidates[varyingKeyCharPosition]' with the new best key char
                        // candidate.
                        bestEnglishScore = englishScore
                        bestKeyCharCandidates[varyingKeyCharPosition] = keyCharCandidate
                    }
                }
            }

            currentBestKey = bestKeyCharCandidates.map { it }.joinToString("")
        }

        return EncryptionUtil.collapseRepeatedString(currentBestKey)
    }

    internal fun getEnglishPlainTextScore(plainText: String): Double {
        return ((CHAR_WEIGTH * getEnglishNgramScore(plainText, 1)) +
                (BIGRAM_WEIGTH * getEnglishNgramScore(plainText, 2)) +
                (TRIGRAM_WEIGTH * getEnglishNgramScore(plainText, 3)) +
                (QUADRIGRAM_WEIGTH * getEnglishNgramScore(plainText, 4))) /
                plainText.length.toDouble()
    }

    private fun getEnglishNgramScore(plainText: String, n: Int): Double {
        var result = 0.0

        TOP_10_ENGLISH_NGRAMS[n]?.let {
            val ngrams = (0..plainText.length - n).map { plainText.substring(it, it + n).uppercase() }
            val logProbabilities = ngrams.map { trigram ->
                log10(it.getOrDefault(trigram, 1e-7))
            }

            result = logProbabilities.sum() / ngrams.size.toDouble()
        }

        return result
    }

    private fun getKeyCharForSpeculatedPlainChar(cipherChar: Char, speculatedPlainChar: Char): Char? {
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
        const val MAX_KEY_LENGTH_CANDIDATE = 15

        const val CHAR_WEIGTH = 0.5
        val TOP_10_ENGLISH_LETTERS: Map<String, Double> = mapOf(
            "E" to 0.127,
            "T" to 0.091,
            "A" to 0.082,
            "O" to 0.075,
            "I" to 0.070,
            "N" to 0.067,
            "S" to 0.063,
            "H" to 0.061,
            "R" to 0.060,
            "D" to 0.043
        )

        const val BIGRAM_WEIGTH = 0.3
        val TOP_10_ENGLISH_BIGRAMS: Map<String, Double> = mapOf(
            "TH" to 0.0356,
            "HE" to 0.0307,
            "IN" to 0.0243,
            "ER" to 0.0205,
            "AN" to 0.0199,
            "RE" to 0.0185,
            "ND" to 0.0172,
            "ON" to 0.0165,
            "EN" to 0.0162,
            "AT" to 0.0149
        )

        const val TRIGRAM_WEIGTH = 0.15
        val TOP_10_ENGLISH_TRIGRAMS: Map<String, Double> = mapOf(
            "THE" to 0.0181,
            "AND" to 0.0073,
            "ING" to 0.0072,
            "HER" to 0.0042,
            "ERE" to 0.0031,
            "ENT" to 0.0028,
            "THA" to 0.0027,
            "NTH" to 0.0023,
            "WAS" to 0.0022,
            "ETH" to 0.0021
        )

        const val QUADRIGRAM_WEIGTH = 0.05
        val TOP_10_ENGLISH_QUADRIGRAMS: Map<String, Double> = mapOf(
            "THER" to 0.0031,
            "THAT" to 0.0026,
            "WITH" to 0.0024,
            "HERE" to 0.0021,
            "HATI" to 0.0018,
            "TION" to 0.0017,
            "EVER" to 0.0016,
            "FROM" to 0.0015,
            "THIS" to 0.0014,
            "THEY" to 0.0013
        )

        val TOP_10_ENGLISH_NGRAMS: Map<Int, Map<String, Double>> = mapOf(
            1 to TOP_10_ENGLISH_LETTERS,
            2 to TOP_10_ENGLISH_BIGRAMS,
            3 to TOP_10_ENGLISH_TRIGRAMS,
            4 to TOP_10_ENGLISH_QUADRIGRAMS
        )
    }
}