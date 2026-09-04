package com.ghosterdex.wallet.crypto

import android.util.Base64
import java.util.Locale

/**
 * A TON account address: a workchain and a 32-byte hash.
 *
 * TON writes the same address two ways, and both reach this app. The raw form
 * `0:<64 hex>` is what the Worker stores and compares. The friendly form
 * (`EQ…`, `UQ…`) is what a person copies out of Tonkeeper and pastes into a
 * send box, and it carries a checksum plus two flag bits that the raw form
 * cannot express.
 *
 * Parsing is strict on purpose. The friendly form exists precisely so a typo
 * fails loudly instead of sending money into a hash nobody holds the key to, so
 * accepting one whose checksum does not verify would throw away the single
 * protection the encoding offers.
 */
class TonAddress private constructor(
    val workchain: Int,
    val hash: ByteArray,
) {

    /** `0:<64 hex>`, the form the Worker and the mini app exchange. */
    val raw: String
        get() = "$workchain:" + hash.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    /**
     * The user-facing form.
     *
     * [bounceable] is not cosmetic. Sent to a bounceable address, a message that
     * the receiving contract cannot handle comes back with the money; sent to a
     * non-bounceable one, it does not. Wallets are published as `UQ`
     * (non-bounceable) so a transfer to an uninitialised wallet sticks instead
     * of rebounding, while contracts are published as `EQ`.
     */
    fun toFriendly(bounceable: Boolean = false, urlSafe: Boolean = true): String {
        val body = ByteArray(34)
        body[0] = (if (bounceable) 0x11 else 0x51).toByte()
        body[1] = workchain.toByte()
        System.arraycopy(hash, 0, body, 2, 32)
        val sum = crc16(body)
        val full = body + byteArrayOf(((sum ushr 8) and 0xFF).toByte(), (sum and 0xFF).toByte())
        val flags = Base64.NO_WRAP or (if (urlSafe) Base64.URL_SAFE else 0)
        return Base64.encodeToString(full, flags)
    }

    /** Short form for display: first four and last four characters of the friendly form. */
    fun short(): String {
        val f = toFriendly()
        return f.take(4) + "…" + f.takeLast(4)
    }

    override fun equals(other: Any?): Boolean =
        other is TonAddress && workchain == other.workchain && hash.contentEquals(other.hash)

    override fun hashCode(): Int = hash.contentHashCode() * 31 + workchain

    override fun toString(): String = raw

    companion object {

        /** Basechain, where wallets and jettons live. */
        const val BASECHAIN = 0

        /** Masterchain. Valid, but no ordinary user asset is here. */
        const val MASTERCHAIN = -1

        /**
         * Parses either form, or throws with a reason a person could act on.
         *
         * Testnet-flagged addresses are refused rather than silently accepted.
         * This app is mainnet-only, and the flag exists so the two networks
         * cannot be confused, honouring it costs one branch and prevents a
         * transfer aimed at an address that means nothing on the live chain.
         */
        fun parse(input: String): TonAddress {
            val s = input.trim()
            require(s.isNotEmpty()) { "No address given." }

            if (s.contains(':')) {
                val parts = s.split(':')
                require(parts.size == 2) { "That does not look like a TON address." }
                val wc = parts[0].toIntOrNull()
                    ?: throw IllegalArgumentException("That address has an unreadable workchain.")
                val hex = parts[1]
                require(hex.length == 64 && hex.all { isHex(it) }) {
                    "That address should have 64 hexadecimal characters after the colon."
                }
                return of(wc, hexToBytes(hex))
            }

            require(s.length == 48) { "That address is ${s.length} characters; a TON address is 48." }
            val bytes = try {
                // The two base64 alphabets both circulate; accept either rather
                // than rejecting a perfectly good address over one character.
                Base64.decode(s.replace('+', '-').replace('/', '_'), Base64.URL_SAFE or Base64.NO_WRAP)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("That address is not valid base64.")
            }
            require(bytes.size == 36) { "That address decodes to ${bytes.size} bytes, not 36." }

            val want = crc16(bytes.copyOfRange(0, 34))
            val got = ((bytes[34].toInt() and 0xFF) shl 8) or (bytes[35].toInt() and 0xFF)
            require(want == got) { "That address fails its own checksum, so it has a typo in it." }

            val tag = bytes[0].toInt() and 0xFF
            require(tag and 0x80 == 0) { "That is a testnet address, and this wallet is on mainnet." }
            require(tag and 0x7F == 0x11 || tag and 0x7F == 0x51) {
                "That address has an unrecognised type marker."
            }

            return of(bytes[1].toInt(), bytes.copyOfRange(2, 34))
        }

        /** Parses, or returns null. For input that is being typed and not yet finished. */
        fun parseOrNull(input: String?): TonAddress? = try {
            if (input.isNullOrBlank()) null else parse(input)
        } catch (e: IllegalArgumentException) {
            null
        }

        fun of(workchain: Int, hash: ByteArray): TonAddress {
            require(hash.size == 32) { "An address hash is 32 bytes, not ${hash.size}." }
            require(workchain == BASECHAIN || workchain == MASTERCHAIN) {
                "Workchain $workchain does not exist on TON."
            }
            return TonAddress(workchain, hash.copyOf())
        }

        /**
         * CRC-16/XMODEM, the check the friendly form carries.
         *
         * Bitwise for the same reason as the bag-of-cells checksum: 34 bytes is
         * far too little to earn a lookup table.
         */
        private fun crc16(data: ByteArray): Int {
            var crc = 0
            for (b in data) {
                crc = crc xor ((b.toInt() and 0xFF) shl 8)
                repeat(8) {
                    crc = if (crc and 0x8000 != 0) {
                        ((crc shl 1) xor 0x1021) and 0xFFFF
                    } else {
                        (crc shl 1) and 0xFFFF
                    }
                }
            }
            return crc and 0xFFFF
        }

        private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

        private fun hexToBytes(s: String) = ByteArray(s.length / 2) {
            ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
        }
    }
}
