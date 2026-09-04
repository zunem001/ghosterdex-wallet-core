package com.ghosterdex.wallet.crypto

/**
 * Base64, both alphabets, with no platform in it.
 *
 * `android.util.Base64` is what the rest of this package uses, and it is
 * fine on a phone. It is a stub on the JVM the unit tests run on, and
 * `java.util.Base64` only arrived in Android 8, above this app's floor. The
 * transaction parser has to run in both places, because the refusals it
 * makes are the ones worth testing without a device, so it carries its own
 * few lines of base64 rather than choosing a platform.
 */
object TonBase64 {
    private const val STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val VALUE = IntArray(128) { -1 }.also { t ->
        STD.forEachIndexed { i, c -> t[c.code] = i }
        t['-'.code] = 62
        t['_'.code] = 63
    }

    /** Decodes either alphabet, padded or not. Throws on anything else. */
    fun decode(text: String): ByteArray {
        val s = text.trim().trimEnd('=')
        require(s.isNotEmpty()) { "empty base64" }
        val out = java.io.ByteArrayOutputStream((s.length * 3) / 4)
        var acc = 0
        var bits = 0
        for (ch in s) {
            val v = if (ch.code < 128) VALUE[ch.code] else -1
            require(v >= 0) { "not base64: '$ch'" }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc ushr bits) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    /** URL-safe alphabet, no padding, the way TON writes addresses. */
    fun encodeUrl(bytes: ByteArray): String {
        val sb = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else -1
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else -1
            sb.append(url(b0 ushr 2))
            sb.append(url(((b0 and 3) shl 4) or (if (b1 >= 0) b1 ushr 4 else 0)))
            if (b1 >= 0) sb.append(url(((b1 and 15) shl 2) or (if (b2 >= 0) b2 ushr 6 else 0)))
            if (b2 >= 0) sb.append(url(b2 and 63))
            i += 3
        }
        return sb.toString()
    }

    private fun url(v: Int): Char = when {
        v < 62 -> STD[v]
        v == 62 -> '-'
        else -> '_'
    }
}
