package com.encryption.vigenere.encipher

import com.encryption.EncryptionUtil

class VigenereCipher() {
    fun encipher(plainText: String, key: String): String {
        val result = StringBuilder()

        val normalizedPlainText = EncryptionUtil.getNormalizedText(plainText)
        val normalizedKey = EncryptionUtil.getNormalizedText(key)

        for (i in normalizedPlainText.indices) {
            val plainChar = normalizedPlainText[i]
            val keyChar = normalizedKey[i % normalizedKey.length]
            TABULA_RECTA[keyChar]?.let { result.append(it[plainChar - 'A']) }
        }

        return result.toString()
    }

    fun decipher(cipherText: String, key: StringBuilder): String {
        return decipher(cipherText, key.toString())
    }

    fun decipher(cipherText: String, key: StringBuffer): String {
        return decipher(cipherText, key.toString())
    }

    fun decipher(cipherText: String, key: String): String {
        val result = StringBuilder()

        val normalizedKey = EncryptionUtil.getNormalizedText(key)

        for (i in cipherText.indices) {
            val cipherChar = cipherText[i]
            val keyChar = normalizedKey[i % normalizedKey.length]
            TABULA_RECTA[keyChar]
                ?.indexOf(cipherChar)
                ?.takeIf { it in 0..25 }
                ?.let { result.append('A' + it) }
        }

        return result.toString()
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
    }
}