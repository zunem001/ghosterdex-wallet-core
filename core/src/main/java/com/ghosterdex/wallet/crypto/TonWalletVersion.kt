package com.ghosterdex.wallet.crypto

/**
 * TON wallet contract versions.
 *
 * The same private key produces a **completely different address** under each
 * version, because a TON address is the hash of the deployed state-init. Code
 * cell included. So the version is not cosmetic: choose the wrong one on import
 * and the user's funds are perfectly safe at an address the app never looks at,
 * which is indistinguishable from "my money is gone".
 *
 * Verified for the same public key:
 * ```
 * v5R1  0:dcced75998cdf8dcb53977aa51b9e91b6cfdc7d5dfb41d7d22424a675fbb6dce
 * v4R2  0:40a42ae8d0aea047bb718e1d04a5b7c2af161b3c5225f56f874a46170e17a21c
 * v3R2  0:1f20f387f972de5891f9b385e88c979a69154bf2b89afb92a8702ed4035f48ab
 * ```
 *
 * [V5R1] is the ecosystem default: the W5 standard was finalised in July 2024
 * and Tonkeeper and the other major wallets create new accounts with it. A
 * wallet imported from Tonkeeper in the last two years is almost certainly V5R1,
 * which is why the app must derive more than one candidate and let the user
 * recognise their balance.
 *
 * Code-cell hashes and depths were precomputed from the BOCs shipped by
 * `@ton/ton` 16.3.0, so no BOC parser is needed at runtime. `TonVectorsTest`
 * re-derives each address and compares against that library, which would fail
 * immediately if any constant here were wrong.
 */
enum class TonWalletVersion(
    val id: String,
    internal val codeHash: String,
    internal val codeDepth: Int,
) {
    /** W5. The current default across the TON ecosystem. */
    V5R1(
        id = "v5r1",
        codeHash = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f",
        codeDepth = 6,
    ),

    /** The previous default; still holds a great deal of value. */
    V4R2(
        id = "v4r2",
        codeHash = "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0",
        codeDepth = 7,
    ),

    /** Older, but common in long-dormant wallets. No plugins dictionary. */
    V3R2(
        id = "v3r2",
        codeHash = "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599",
        codeDepth = 0,
    );

    companion object {
        /**
         * What a newly created wallet uses.
         *
         * Matching the ecosystem default matters beyond convention: W5 has
         * meaningfully lower fees and supports gasless transfers, and a user who
         * later imports this phrase into Tonkeeper will find the same address
         * waiting rather than an empty one.
         */
        val DEFAULT = V5R1

        /** Order to probe on import: most likely to hold funds first. */
        val PROBE_ORDER = listOf(V5R1, V4R2, V3R2)

        fun from(id: String?): TonWalletVersion =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: DEFAULT

        /** `698983191 + workchain`, shared by v3 and v4. */
        private const val SUBWALLET_ID = 698983191

        /**
         * v5R1 stores `networkGlobalId XOR context`, not a plain subwallet id.
         *
         * For mainnet defaults. NetworkGlobalId -239, workchain 0, version
         * v5r1, subwallet 0. The context is `1` followed by 31 zero bits
         * (-2147483648), giving `-239 xor -2147483648` = 2147483409 (0x7FFFFF11).
         */
        private const val V5R1_WALLET_ID = 2147483409

        private fun writeInt32(target: ByteArray, offset: Int, value: Int) {
            target[offset] = ((value ushr 24) and 0xFF).toByte()
            target[offset + 1] = ((value ushr 16) and 0xFF).toByte()
            target[offset + 2] = ((value ushr 8) and 0xFF).toByte()
            target[offset + 3] = (value and 0xFF).toByte()
        }
    }

    /**
     * Builds this version's data cell for [publicKey].
     *
     * The layouts genuinely differ. This is not one format with optional
     * fields:
     * ```
     * v3R2  seqno(32) walletId(32) pubkey(256)                        = 320 bits
     * v4R2  seqno(32) walletId(32) pubkey(256) plugins(1)             = 321 bits
     * v5R1  auth(1) seqno(32) walletId(32) pubkey(256) plugins(1)     = 322 bits
     * ```
     */
    internal fun dataCell(publicKey: ByteArray): TonCell.Ref {
        require(publicKey.size == 32) { "Ed25519 public key must be 32 bytes" }

        return when (this) {
            V3R2 -> {
                val data = ByteArray(40)
                writeInt32(data, 4, SUBWALLET_ID)
                System.arraycopy(publicKey, 0, data, 8, 32)
                TonCell.hash(data, 320)
            }

            V4R2 -> {
                val data = ByteArray(41)
                writeInt32(data, 4, SUBWALLET_ID)
                System.arraycopy(publicKey, 0, data, 8, 32)
                // byte 40 carries the single 0 bit for an empty plugins dict.
                TonCell.hash(data, 321)
            }

            V5R1 -> {
                // Everything after the leading auth bit is offset by one, so
                // the whole payload is bit-shifted rather than byte-aligned.
                val bits = BitWriter(322)
                bits.writeBit(1)                 // is_signature_auth_allowed
                bits.writeInt(0, 32)             // seqno
                bits.writeInt(V5R1_WALLET_ID, 32)
                bits.writeBytes(publicKey)
                bits.writeBit(0)                 // empty extensions dict
                TonCell.hash(bits.bytes(), 322)
            }
        }
    }

    /** Minimal MSB-first bit writer, for layouts that are not byte-aligned. */
    private class BitWriter(bitCapacity: Int) {
        private val buffer = ByteArray((bitCapacity + 7) / 8)
        private var pos = 0

        fun writeBit(bit: Int) {
            if (bit != 0) {
                buffer[pos ushr 3] = (buffer[pos ushr 3].toInt() or (0x80 ushr (pos and 7))).toByte()
            }
            pos++
        }

        fun writeInt(value: Int, bits: Int) {
            for (i in bits - 1 downTo 0) writeBit((value ushr i) and 1)
        }

        fun writeBytes(bytes: ByteArray) {
            for (b in bytes) writeInt(b.toInt() and 0xFF, 8)
        }

        fun bytes(): ByteArray = buffer
    }
}
