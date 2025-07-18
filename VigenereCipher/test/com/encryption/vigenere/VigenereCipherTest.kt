package com.encryption.vigenere

import com.encryption.EncryptionUtil
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File

class VigenereCipherTest {
    @Test
    fun test1() {
        val key = "AAA"
        val plainText = "All we have to fear is fear itself."
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipher(EncryptionUtil.getNormalizedText(plainText), key)
        assertEquals("ALLWEHAVETOFEARISFEARITSELF", actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals("ALLWEHAVETOFEARISFEARITSELF", actualDeciphered)
    }

    @Test
    fun test2() {
        val key = "CAT"
        val plainText = "All we have to fear is fear itself."
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipher(EncryptionUtil.getNormalizedText(plainText), key)
        assertEquals("CLEYEACVXVOYGAKKSYGAKKTLGLY", actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals("ALLWEHAVETOFEARISFEARITSELF", actualDeciphered)
    }

    @Test
    fun test3() {
        val key = "DOG"
        val plainText = "All we have to fear is fear itself."
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipher(EncryptionUtil.getNormalizedText(plainText), key)
        assertEquals("DZRZSNDJKWCLHOXLGLHOXLHYHZL", actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals("ALLWEHAVETOFEARISFEARITSELF", actualDeciphered)
    }

    @Test
    fun test4() {
        val key = "GANDALF"
        val plainText = File("hobbit.txt").readText()
        val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText)
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipher(normalizedPlainText, key)
        assertEquals(File("hobbit_key_gandalf.txt").readText(), actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals(normalizedPlainText, actualDeciphered)
    }

    @Test
    fun test5() {
        val key = "GANDALF"
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipherFromUnnormalizedFile(File("hobbit.txt"), key)
        assertEquals(File("hobbit_key_gandalf.txt").readText(), actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals(EncryptionUtil.getNormalizedText(File("hobbit.txt").readText()), actualDeciphered)
    }

    @Test
    fun test6() {
        val key = "GANDALF"
        val vigenereCipher = VigenereCipher()
        val actualEnciphered = vigenereCipher.encipherFromFile(File("hobbit_normalized.txt"), key)
        assertEquals(File("hobbit_key_gandalf.txt").readText(), actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals(EncryptionUtil.getNormalizedText(File("hobbit.txt").readText()), actualDeciphered)
    }

    @Test
    fun test7() {
        val key = "GANDALF"
        val vigenereCipher = VigenereCipher()
        val unnormalizedPlainText = File("hobbit_normalized.txt").readText()
        val actualEnciphered = vigenereCipher.encipherFromUnnormalizedText(unnormalizedPlainText, key)
        assertEquals(File("hobbit_key_gandalf.txt").readText(), actualEnciphered)

        val actualDeciphered = vigenereCipher.decipher(actualEnciphered, key)
        assertEquals(EncryptionUtil.getNormalizedText(File("hobbit.txt").readText()), actualDeciphered)
    }
}