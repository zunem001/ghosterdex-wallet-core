package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.digests.SHA256Digest

/**
 * Just enough TON cell representation hashing to derive a wallet address.
 *
 * A TON address *is* `sha256(representation(stateInit cell))`, so computing one
 * means hashing cells exactly the way the network does. This is not a general
 * BOC library, it handles ordinary cells at level 0, which is all the wallet
 * v4R2 state init requires, and deliberately refuses anything else rather than
 * guessing.
 *
 * The representation of a cell is:
 * ```
 * d1 || d2 || augmented data || ref depths (2 bytes BE each) || ref hashes (32 each)
 * ```
 * where `d1 = refCount` for an ordinary level-0 cell, and
 * `d2 = floor(bits/8) + ceil(bits/8)`, an encoding that lets a reader recover
 * whether the final byte is partially filled.
 */
object TonCell {

    /** A hashed cell: what a parent needs in order to reference it. */
    data class Ref(val hash: ByteArray, val depth: Int) {
        init {
            require(hash.size == 32) { "Cell hash must be 32 bytes, got ${hash.size}" }
            require(depth in 0..1023) { "Cell depth out of range: $depth" }
        }

        // Data class equality on a ByteArray field compares references, which is
        // never what a caller means for a hash.
        override fun equals(other: Any?): Boolean =
            other is Ref && depth == other.depth && hash.contentEquals(other.hash)

        override fun hashCode(): Int = hash.contentHashCode() * 31 + depth
    }

    /**
     * Hashes one ordinary cell.
     *
     * @param data the cell's bits, MSB-first, in [bitLength] significant bits
     * @param bitLength 0..1023
     * @param refs child cells, already hashed, in order
     */
    fun hash(data: ByteArray, bitLength: Int, refs: List<Ref> = emptyList()): Ref {
        require(bitLength in 0..1023) { "A cell holds at most 1023 bits, got $bitLength" }
        require(refs.size <= 4) { "A cell holds at most 4 refs, got ${refs.size}" }
        require(data.size >= (bitLength + 7) / 8) { "data is shorter than bitLength" }

        val fullBytes = bitLength / 8
        val totalBytes = (bitLength + 7) / 8

        val d1 = refs.size                      // ordinary cell, level 0, not exotic
        val d2 = fullBytes + totalBytes

        val repr = ArrayList<Byte>(2 + totalBytes + refs.size * 34)
        repr.add(d1.toByte())
        repr.add(d2.toByte())

        for (i in 0 until totalBytes) repr.add(data[i])

        // Augmentation: when the last byte is partial, a single 1 bit marks the
        // end of real data and the remainder is zero. Without this, "5 bits" and
        // "5 bits then three zeros" would hash identically.
        if (bitLength % 8 != 0) {
            val used = bitLength % 8
            val last = repr[repr.size - 1].toInt() and 0xFF
            val keepMask = (0xFF shl (8 - used)) and 0xFF
            val augmented = (last and keepMask) or (1 shl (7 - used))
            repr[repr.size - 1] = augmented.toByte()
        }

        // Depths first, then hashes, the order is part of the spec.
        for (r in refs) {
            repr.add(((r.depth shr 8) and 0xFF).toByte())
            repr.add((r.depth and 0xFF).toByte())
        }
        for (r in refs) r.hash.forEach { repr.add(it) }

        val bytes = ByteArray(repr.size) { repr[it] }
        val digest = SHA256Digest()
        digest.update(bytes, 0, bytes.size)
        val out = ByteArray(32)
        digest.doFinal(out, 0)

        val depth = if (refs.isEmpty()) 0 else refs.maxOf { it.depth } + 1
        return Ref(out, depth)
    }
}
