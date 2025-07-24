package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.vigenere.VigenereCipher
import java.io.File
import java.lang.Math.log
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

    private fun getNormalizedCharFrequencyMap(text: String): List<Map.Entry<Char, Double>> {
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

    private fun getStandardDeviation(frequencyMap: List<Map.Entry<Char, Double>>): Double {
        val values = frequencyMap.map { it.value }
        val mean = values.average()
        val variance = values.sumOf { (it - mean).pow(2) } / values.size

        return sqrt(variance)
    }

    private fun getSlice(text: String, n: Int, offset: Int = 0): String {
        return text.slice(offset until text.length step n)
    }

    private fun getKeyLengthScore(cipherText: String, keyLength: Int): Double {
        var stdDevSum = 0.0

        for (keyCharPosition in 0 until keyLength) {
            val cipherSlice = getSlice(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getNormalizedCharFrequencyMap(cipherSlice)
            stdDevSum += getStandardDeviation(cipherFrequencyMap)
        }

        return stdDevSum / keyLength
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
        val maxScoreSimilarityRatio = 1.0 + ((bestToWorstScoreRatio - 1.0) / scores.size)
        val similarToBestScore = scores.entries
            .filter {  bestScore / it.value <= maxScoreSimilarityRatio  }
            .map { it.key }

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
            val cipherSlice = getSlice(cipherText, keyLength, keyCharPosition)
            val cipherFrequencyMap = getNormalizedCharFrequencyMap(cipherSlice)
            var mostFrequentCipherChar = cipherFrequencyMap[0].key

            val keyCharCandidates = mutableListOf<Char>()

            for (c in unigramProbs.entries.take(10).map { it.key[0] } ) {
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
        var bestEnglishScore = Double.NEGATIVE_INFINITY

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

    internal fun getEnglishPlainTextScore(text: String): Double {
        val totalScore = (1..4).sumOf { n ->
            val weight = NGRAM_WEIGHTS[n] ?: 0.0
            val nGramLogProbabilities = TOP_ENGLISH_NGRAMS[n] ?: return@sumOf 0.0
            val ngrams = text.windowed(n, 1)
            weight * ngrams.sumOf { ngram -> nGramLogProbabilities[ngram] ?: log(1e-6) }
        }

        return totalScore / text.length
    }

    private fun getKeyCharForSpeculatedPlainChar(cipherChar: Char, speculatedPlainChar: Char): Char? {
        var result: Char? = null

        for (keyChar in 'A' .. 'Z') {
            TABULA_RECTA[keyChar]
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
        private val TABULA_RECTA = mapOf(
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

        private const val MAX_KEY_LENGTH_CANDIDATE = 15

        private val NGRAM_WEIGHTS = mapOf(
            1 to 0.70,
            2 to 0.20,
            3 to 0.06,
            4 to 0.04,
        )

        val unigramProbs = mapOf(
            "E" to 0.1270, "T" to 0.0906, "A" to 0.0817, "O" to 0.0751, "I" to 0.0697,
            "N" to 0.0675, "S" to 0.0633, "H" to 0.0609, "R" to 0.0599, "D" to 0.0425,
            "L" to 0.0403, "C" to 0.0278, "U" to 0.0276, "M" to 0.0241, "W" to 0.0236,
            "F" to 0.0223, "G" to 0.0202, "Y" to 0.0197, "P" to 0.0193, "B" to 0.0149,
            "V" to 0.0098, "K" to 0.0077, "J" to 0.0015, "X" to 0.0015, "Q" to 0.0010,
            "Z" to 0.0007
        )

        val bigramProbs = mapOf(
            "TH" to 0.0356, "HE" to 0.0307, "IN" to 0.0243, "ER" to 0.0205, "AN" to 0.0199,
            "RE" to 0.0185, "ND" to 0.0171, "ON" to 0.0165, "EN" to 0.0161, "AT" to 0.0149,
            "OU" to 0.0128, "ED" to 0.0127, "HA" to 0.0124, "TO" to 0.0116, "OR" to 0.0113,
            "IT" to 0.0112, "IS" to 0.0107, "HI" to 0.0107, "ES" to 0.0103, "NG" to 0.0095,
            "ST" to 0.0091, "AR" to 0.0088, "SE" to 0.0083, "VE" to 0.0082, "AL" to 0.0079
        )

        val trigramProbs = mapOf(
            "THE" to 0.0181, "AND" to 0.0073, "ING" to 0.0072, "HER" to 0.0051, "ERE" to 0.0046,
            "ENT" to 0.0043, "THA" to 0.0042, "NTH" to 0.0041, "WAS" to 0.0038, "ETH" to 0.0037,
            "FOR" to 0.0036, "DTH" to 0.0035, "HAT" to 0.0034, "SHE" to 0.0032, "ION" to 0.0031,
            "TIO" to 0.0030, "VER" to 0.0029, "HIS" to 0.0028, "YOU" to 0.0027, "ITH" to 0.0026,
            "HAD" to 0.0025, "ALL" to 0.0024, "ONE" to 0.0023, "NOT" to 0.0022, "BUT" to 0.0021
        )

        val quadrigramProbs = mapOf(
            "TION" to 0.0032, "THER" to 0.0029, "WITH" to 0.0024, "HERE" to 0.0023, "OULD" to 0.0022,
            "IGHT" to 0.0021, "HAVE" to 0.0020, "HICH" to 0.0019, "WHIC" to 0.0018, "THAT" to 0.0017,
            "THES" to 0.0017, "ATIO" to 0.0016, "EVER" to 0.0016, "FROM" to 0.0015, "THIS" to 0.0015,
            "TING" to 0.0014, "MENT" to 0.0014, "IONS" to 0.0013, "OUGH" to 0.0013, "THEM" to 0.0012,
            "NING" to 0.0012, "ANCE" to 0.0012, "THEY" to 0.0012, "EDTH" to 0.0011, "STHE" to 0.0011
        )

        fun convertToLogProbabilities(nGramProbabilities: Map<String, Double>): Map<String, Double> {
            val sum = nGramProbabilities.values.sum()
            return nGramProbabilities.mapValues { log(it.value / sum) }
        }

        private val TOP_ENGLISH_NGRAMS: Map<Int, Map<String, Double>> = mapOf(
            1 to convertToLogProbabilities(unigramProbs),
            2 to convertToLogProbabilities(bigramProbs),
            3 to convertToLogProbabilities(trigramProbs),
            4 to convertToLogProbabilities(quadrigramProbs)
        )
    }
}