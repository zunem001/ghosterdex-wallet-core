package com.ghosterdex.wallet.crypto

import java.math.BigInteger

/**
 * Reading a cell back: the mirror of [TonBoc.Builder].
 *
 * Exists for one reason. When the web layer asks the phone to sign a message
 * it did not build itself, a swap the aggregator prepared, say, the phone has
 * to describe that message to its owner from the bytes it is about to sign,
 * not from whatever the web layer says they mean. That takes reading a few
 * fields out of a payload: an opcode, an amount, an address. Nothing here
 * decides anything; it only makes the bytes sayable.
 *
 * Bounded like the builder. Reading past the end throws rather than
 * returning zeroes, because a description built on zeroes would be a lie.
 */
class TonSlice(private val cell: TonBoc.Cell) {
    private var bit = 0
    private var ref = 0

    val bitsLeft: Int get() = cell.bits - bit
    val refsLeft: Int get() = cell.refs.size - ref

    fun loadBit(): Int {
        require(bit < cell.bits) { "slice underflow" }
        val b = (cell.data[bit ushr 3].toInt() ushr (7 - (bit and 7))) and 1
        bit += 1
        return b
    }

    fun loadUint(width: Int): BigInteger {
        require(width in 0..256) { "width out of range: $width" }
        require(bitsLeft >= width) { "slice underflow" }
        var v = BigInteger.ZERO
        repeat(width) { v = v.shiftLeft(1).or(BigInteger.valueOf(loadBit().toLong())) }
        return v
    }

    fun loadLong(width: Int): Long {
        require(width in 0..63) { "width out of range: $width" }
        return loadUint(width).toLong()
    }

    /** VarUInteger 16. */
    fun loadCoins(): BigInteger {
        val len = loadLong(4).toInt()
        return loadUint(len * 8)
    }

    /** addr_none as null, addr_std as an address; anything else is refused. */
    fun loadAddress(): TonAddress? {
        return when (val tag = loadLong(2).toInt()) {
            0 -> null
            2 -> {
                require(loadBit() == 0) { "anycast addresses are not supported" }
                val wcByte = loadLong(8).toInt()
                val wc = if (wcByte > 127) wcByte - 256 else wcByte
                val hash = ByteArray(32) { loadLong(8).toByte() }
                TonAddress.of(wc, hash)
            }
            else -> throw IllegalArgumentException("unsupported address type $tag")
        }
    }

    fun loadBytes(count: Int): ByteArray = ByteArray(count) { loadLong(8).toByte() }

    fun loadRef(): TonBoc.Cell {
        require(ref < cell.refs.size) { "no more references" }
        return cell.refs[ref++]
    }

    fun skip(bits: Int) {
        require(bits >= 0 && bit + bits <= cell.bits) { "slice underflow" }
        bit += bits
    }
}
