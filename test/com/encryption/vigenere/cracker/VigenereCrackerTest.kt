package com.encryption.vigenere.cracker

import com.encryption.EncryptionUtil
import com.encryption.vigenere.encipher.VigenereCipher
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class VigenereCrackerTest {
    @Test
    fun test1() {
        val keys = listOf("SAM", "TOM", "BILL", "FRODO", "BILBO", "GIMLI", "ELROND", "LEGOLAS", "GANDALF", "ARAGORN", "BOROMIR", "DENETHOR", "GALADRIEL", "GLORFINDEL", "TOMTOMTOMSAM", "GANDALFTHEGREY","AAA", "TTTT", "XXXXX", "ABBA", "XY" )
        val testFileNames = listOf("tcoe.txt", "atotc.txt", "hobbit.txt")

        for (fileName in testFileNames) {
            val plainText = File(fileName).readText()
            val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText)
            val vigenereCipher = VigenereCipher()

            for (key in keys) {
                val cipherText = vigenereCipher.encipher(normalizedPlainText, key)
                val vigenereCracker = VigenereCracker()
                val solution = vigenereCracker.crack(cipherText)
                assertEquals(EncryptionUtil.collapseRepeatedString(key), solution.key)
                assertEquals(normalizedPlainText, solution.plainText)
            }
        }
    }
}