package com.encryption.vigenere

import com.encryption.EncryptionUtil
import java.io.File

class VigenereCipher() {
    fun encipherFromUnnormalizedFile(plainTextFile: File, key: String): String {
        return encipher(EncryptionUtil.getNormalizedText(plainTextFile.readText()), key)
    }

    fun encipherFromFile(normalizedPlainTextFile: File, key: String): String {
        return encipher(normalizedPlainTextFile.readText(), key)
    }

    fun encipherFromUnnormalizedText(plainText: String, key: String): String {
        return encipher(EncryptionUtil.getNormalizedText(plainText), key)
    }

    fun encipher(normalizedPlainText: String, key: String): String {
        if (!normalizedPlainText.all { it in 'A'..'Z' }) {
            throw Exception("Invalid cipher text")
        }

        if (!key.all { it in 'A'..'Z' }) {
            throw Exception("Invalid key: $key")
        }

        val result = StringBuilder()

        for (i in normalizedPlainText.indices) {
            val plainChar = normalizedPlainText[i]
            val keyChar = key[i % key.length]
            result.append(TABULA_RECTA[keyChar]?.let { it[plainChar - 'A'] })
        }

        return result.toString()
    }

    fun decipher(normalizedCipherText: String, key: StringBuilder): String {
        return decipher(normalizedCipherText, key.toString())
    }

    fun decipher(normalizedCipherText: String, key: StringBuffer): String {
        return decipher(normalizedCipherText, key.toString())
    }

    fun decipher(normalizedCipherText: String, key: String): String {
        if (!normalizedCipherText.all { it in 'A'..'Z' }) {
            throw Exception("Invalid cipher text")
        }

        if (!key.all { it in 'A'..'Z' }) {
            throw Exception("Invalid key: $key")
        }

        val result = StringBuilder()

        for (i in normalizedCipherText.indices) {
            val cipherChar = normalizedCipherText[i]
            val keyChar = key[i % key.length]
            result.append(
                TABULA_RECTA[keyChar]
                    ?.indexOf(cipherChar)
                    ?.let { 'A' + it })
        }

        return result.toString()
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
    }
}