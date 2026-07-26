package com.ghosterdex.wallet.crypto

/**
 * Base58 (Bitcoin alphabet). The encoding NEAR uses for public keys.
 *
 * The alphabet deliberately omits 0, O, I and l so a key read aloud or copied
 * by hand cannot land on a different valid key.
 */
object Base58 {

    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val INDEX = IntArray(128) { -1 }.apply {
        ALPHABET.forEachIndexed { i, c -> this[c.code] = i }
    }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""

        // Leading zero bytes are not representable by division, and each maps
        // to a literal '1'. NEAR keys routinely start with a zero byte, so
        // dropping these would silently produce a wrong, but valid-looking, key.
        var zeros = 0
        while (zeros < input.size && input[zeros].toInt() == 0) zeros++

        val buffer = input.copyOf()
        val encoded = CharArray(input.size * 2)
        var outputStart = encoded.size

        var inputStart = zeros
        while (inputStart < buffer.size) {
            encoded[--outputStart] = ALPHABET[divmod(buffer, inputStart, 256, 58).toInt()]
            if (buffer[inputStart].toInt() == 0) inputStart++
        }

        // Skip zeros the division itself introduced, then re-add the real ones.
        while (outputStart < encoded.size && encoded[outputStart] == ALPHABET[0]) outputStart++
        repeat(zeros) { encoded[--outputStart] = ALPHABET[0] }

        buffer.fill(0)
        return String(encoded, outputStart, encoded.size - outputStart)
    }

    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)

        val input58 = ByteArray(input.length)
        for (i in input.indices) {
            val c = input[i]
            val digit = if (c.code < 128) INDEX[c.code] else -1
            require(digit >= 0) { "Invalid base58 character '$c' at $i" }
            input58[i] = digit.toByte()
        }

        var zeros = 0
        while (zeros < input58.size && input58[zeros].toInt() == 0) zeros++

        val decoded = ByteArray(input.length)
        var outputStart = decoded.size
        var inputStart = zeros
        while (inputStart < input58.size) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256)
            if (input58[inputStart].toInt() == 0) inputStart++
        }

        while (outputStart < decoded.size && decoded[outputStart].toInt() == 0) outputStart++
        input58.fill(0)
        return decoded.copyOfRange(outputStart - zeros, decoded.size)
    }

    /** Divides `number` (base `base`) by `divisor` in place, returning the remainder. */
    private fun divmod(number: ByteArray, firstDigit: Int, base: Int, divisor: Int): Byte {
        var remainder = 0
        for (i in firstDigit until number.size) {
            val digit = number[i].toInt() and 0xFF
            val temp = remainder * base + digit
            number[i] = (temp / divisor).toByte()
            remainder = temp % divisor
        }
        return remainder.toByte()
    }
}
