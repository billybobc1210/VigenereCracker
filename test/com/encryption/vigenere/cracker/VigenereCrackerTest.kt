package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.EncryptionUtil.Companion.collapseRepeatedString
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
                assertEquals(collapseRepeatedString(key), solution.key)
                assertEquals(normalizedPlainText, solution.plainText)
            }
        }
    }

    @Test
    fun tcoeFalloverTest() {
        falloverTest(File("tcoe.txt"), 1328)
    }

    @Test
    fun atotcFalloverTest() {
        falloverTest(File("atotc.txt"), 434)
    }

    @Test
    fun hobbitFalloverTest() {
        falloverTest(File("hobbit.txt"), 962)
    }

    fun falloverTest(file: File, expectedFallover: Int) {
        val vigenereCipher = VigenereCipher()
        val vigenereCracker = VigenereCracker()

        val plainText = EncryptionUtil.getNormalizedText(file.readText())
        var plainTextLen = expectedFallover + 100

        while (plainTextLen > 0) {
            val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText).substring(0, plainTextLen)
            plainTextLen--

//            println("Filename: ${file.name}, key: $WORST_CASE_KEY, plane text len: $plainTextLen")
            val cipherText = vigenereCipher.encipher(normalizedPlainText, WORST_CASE_KEY)
            val solution = vigenereCracker.crack(cipherText)
            val expected = collapseRepeatedString(WORST_CASE_KEY)
            val actual = solution.key
            if (actual != expected) {
                assert(plainTextLen <= expectedFallover)
                if (plainTextLen < expectedFallover) {
                    println("Improved fallover point: File name: ${file.name}, key: $WORST_CASE_KEY, plane text len: $plainTextLen")
                }
                break
            }
        }
    }
}