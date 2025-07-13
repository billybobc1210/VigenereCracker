package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.vigenere.encipher.VigenereCipher
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class VigenereCrackerTest {
    companion object {
        val TEST_KEYS = listOf(
            "SAM", "TOM", "BILL", "FRODO", "BILBO", "GIMLI", "ELROND", "LEGOLAS", "GANDALF", "ARAGORN", "BOROMIR",
            "DENETHOR", "GALADRIEL", "GLORFINDEL", "TOMTOMTOMSAM", "GANDALFTHEGREY","AAA", "TTTT", "XXXXX", "ABBA",
            "XY", "OFJHZLKGHOOGHIM",
        )

        val WORST_CASE_KEY ="OFJHZLKGHOOGHIM"

        val TEST_FILE_NAMES =  listOf(
            "tcoe.txt",
            "atotc.txt",
            "hobbit.txt",
        )

        val FALLOVER_BY_TEST_FILE = mapOf(
            "tcoe.txt" to 1328,
            "atotc.txt" to 731,
            "hobbit.txt" to 962,
        )
    }

    @Test
    fun currentBestCaseTest() {
        for (fileName in TEST_FILE_NAMES) {
            val plainText = File(fileName).readText()
            val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText)
            val vigenereCipher = VigenereCipher()

            for (key in TEST_KEYS) {
                val cipherText = vigenereCipher.encipher(normalizedPlainText, key)
                val vigenereCracker = VigenereCracker()
                val solution = vigenereCracker.crack(cipherText)
                assertEquals(EncryptionUtil.collapseRepeatedString(key), solution.key)
                assertEquals(normalizedPlainText, solution.plainText)
            }
        }
    }

    @Test
    fun falloverTest() {
        val vigenereCipher = VigenereCipher()
        val vigenereCracker = VigenereCracker()

        var minPlainTextSize = Int.MAX_VALUE

        for (fileName in TEST_FILE_NAMES) {
            val plainText = File(fileName).readText()
            val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText)
            if (normalizedPlainText.length < minPlainTextSize) {
                 minPlainTextSize = normalizedPlainText.length
            }
        }

        for (fileName in TEST_FILE_NAMES) {
            var plainTextLen = minPlainTextSize
            val plainText = File(fileName).readText()

            while (plainTextLen > 0) {
                val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText).substring(0, plainTextLen)
                plainTextLen -= 10

                println("Filename: $fileName, key: $WORST_CASE_KEY, plane text len: $plainTextLen")
                val cipherText = vigenereCipher.encipher(normalizedPlainText, WORST_CASE_KEY)
                val solution = vigenereCracker.crack(cipherText)
                val expected = EncryptionUtil.collapseRepeatedString(WORST_CASE_KEY)
                val actual = solution.key
                if (actual != expected) {
                    FALLOVER_BY_TEST_FILE[fileName]?.let {
                        assert(plainTextLen <= it)
                    }
                    break
                }
        }
        }
    }
}