package com.ghosterdex.wallet.crypto

/**
 * String-free handling of secret text.
 *
 * ## The problem this exists to solve
 *
 * A recovery phrase held as a [String] cannot be erased. Strings are immutable,
 * so `phrase.toCharArray()` and `String(bytes)` each leave an original the
 * program can never overwrite; it survives until the collector happens to reach
 * it, and until then it is visible in a heap dump, a debugger, or swap.
 *
 * Worse, the idiomatic normalisation chain -
 * `String(chars).trim().lowercase().split(...).joinToString(" ")`. Creates
 * *five* such copies, each of the full phrase, on a path that runs on **every
 * signature**.
 *
 * These helpers do the same work over [CharArray] and [ByteArray], which can be
 * zeroed deterministically.
 *
 * ## What this does not claim
 *
 * It is a reduction, not elimination. The JVM may relocate arrays during GC and
 * leave copies behind, and Android's own UI widgets ([android.widget.EditText],
 * [android.widget.TextView]) deal in Strings, so the entry and display screens
 * still create them. The real protection remains that this material never
 * leaves Kotlin. See SECURITY.md.
 */
object Secrets {

    /**
     * UTF-8 encodes without materialising a String.
     *
     * Handles the full BMP; BIP39 words are ASCII, but an optional passphrase
     * may not be, and mangling one silently derives the wrong wallet.
     */
    fun charsToUtf8(chars: CharArray): ByteArray {
        val out = ByteArray(chars.size * 3)
        var n = 0
        for (c in chars) {
            val code = c.code
            when {
                code < 0x80 -> out[n++] = code.toByte()
                code < 0x800 -> {
                    out[n++] = (0xC0 or (code shr 6)).toByte()
                    out[n++] = (0x80 or (code and 0x3F)).toByte()
                }
                else -> {
                    out[n++] = (0xE0 or (code shr 12)).toByte()
                    out[n++] = (0x80 or ((code shr 6) and 0x3F)).toByte()
                    out[n++] = (0x80 or (code and 0x3F)).toByte()
                }
            }
        }
        val exact = out.copyOf(n)
        out.fill(0)
        return exact
    }

    /** UTF-8 decodes without materialising a String. Inverse of [charsToUtf8]. */
    fun utf8ToChars(bytes: ByteArray): CharArray {
        val out = CharArray(bytes.size)
        var n = 0
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i].toInt() and 0xFF
            when {
                b < 0x80 -> {
                    out[n++] = b.toChar()
                    i += 1
                }
                b and 0xE0 == 0xC0 && i + 1 < bytes.size -> {
                    out[n++] = (((b and 0x1F) shl 6) or (bytes[i + 1].toInt() and 0x3F)).toChar()
                    i += 2
                }
                b and 0xF0 == 0xE0 && i + 2 < bytes.size -> {
                    out[n++] = (
                        ((b and 0x0F) shl 12) or
                            ((bytes[i + 1].toInt() and 0x3F) shl 6) or
                            (bytes[i + 2].toInt() and 0x3F)
                        ).toChar()
                    i += 3
                }
                else -> {
                    // Malformed input: a sealed blob that decrypted to garbage.
                    // Fail loudly rather than deriving a key from nonsense.
                    out.fill(' ')
                    throw IllegalArgumentException("Malformed UTF-8 in secret material")
                }
            }
        }
        val exact = out.copyOf(n)
        out.fill(' ')
        return exact
    }

    /**
     * Trims, lowercases and collapses internal whitespace runs to one space -
     * the normalisation TON's derivation expects. Entirely in place.
     *
     * ASCII-only lowercasing is deliberate: the wordlist is ASCII, and a
     * locale-sensitive `lowercase()` is a real hazard here. In Turkish locales
     * 'I' lowercases to 'ı' (dotless), which would silently change the derived
     * key for any user whose device locale is tr-TR.
     */
    fun normalizeWords(chars: CharArray): CharArray {
        val out = CharArray(chars.size)
        var n = 0
        var pendingSpace = false

        for (c in chars) {
            if (isSeparator(c)) {
                if (n > 0) pendingSpace = true
                continue
            }
            if (pendingSpace) {
                out[n++] = ' '
                pendingSpace = false
            }
            out[n++] = if (c in 'A'..'Z') (c + 32) else c
        }

        val exact = out.copyOf(n)
        out.fill(' ')
        return exact
    }

    /**
     * True for anything that separates words in a pasted phrase.
     *
     * [Character.isWhitespace] is not enough on its own: it returns **false**
     * for U+00A0 (non-breaking space), which is exactly what arrives when a
     * phrase is copied out of a PDF, a chat message, or a notes app. Left
     * unhandled it fuses two words into one non-member token and the import is
     * rejected with "that isn't a recovery word" for a phrase that is perfectly
     * correct. [Character.isSpaceChar] covers NBSP, U+202F and U+3000.
     */
    fun isSeparator(c: Char): Boolean = Character.isWhitespace(c) || Character.isSpaceChar(c)

    /** Splits into word boundaries without allocating Strings. */
    fun wordRanges(chars: CharArray): List<IntRange> {
        val ranges = ArrayList<IntRange>(24)
        var start = -1
        for (i in chars.indices) {
            val ws = isSeparator(chars[i])
            if (!ws && start == -1) start = i
            if (ws && start != -1) {
                ranges.add(start until i)
                start = -1
            }
        }
        if (start != -1) ranges.add(start until chars.size)
        return ranges
    }

    fun wipe(data: ByteArray?) = data?.fill(0)

    fun wipe(data: CharArray?) = data?.fill(' ')
}
