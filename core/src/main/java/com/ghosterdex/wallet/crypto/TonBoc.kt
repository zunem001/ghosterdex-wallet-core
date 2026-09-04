package com.ghosterdex.wallet.crypto

import java.math.BigInteger
import java.util.Locale

/**
 * Building, serialising and reading TON cells.
 *
 * [TonCell] answers "what is this cell's hash", which is all an *address*
 * needs. Sending needs the opposite: the actual bytes, in the exact shape a
 * validator will parse. So this module keeps the data rather than discarding it
 * after hashing, and adds the bag-of-cells envelope the network transports.
 *
 * Every layout decision here was taken from `@ton/core` 0.63.1, the same
 * library whose addresses [TonWalletVersion] is pinned against, and the tests
 * compare output byte for byte. That is deliberate. Several choices below are
 * *not* forced by the TL-B schema:
 *
 *  - the ordering of cells within the envelope (any topological order parses),
 *  - whether a child rides inline or as a reference,
 *  - whether the checksum is present at all.
 *
 * A different-but-legal choice would still be accepted by the chain, and then
 * the only thing vouching for this code would be my own reading of the spec.
 * Matching a library that moves real money every day puts a published
 * implementation in charge of refereeing each of those decisions instead.
 */
object TonBoc {

    private const val MAGIC = 0xB5EE9C72L
    private const val MAX_BITS = 1023
    private const val MAX_REFS = 4

    /**
     * One ordinary, level-0 cell: up to 1023 bits and 4 children.
     *
     * Immutable, and hashed on construction. Cells are small and built once,
     * and both serialisation and equality need the hash anyway, so deferring it
     * would buy nothing except a thread-safety question.
     */
    class Cell internal constructor(
        internal val data: ByteArray,
        internal val bits: Int,
        internal val refs: List<Cell>,
    ) {
        private val self: TonCell.Ref = TonCell.hash(data, bits, refs.map { it.self })

        val hash: ByteArray get() = self.hash
        val depth: Int get() = self.depth
        val refCount: Int get() = refs.size
        val hashHex: String get() = self.hash.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

        /** The descriptor byte: floor(bits/8) + ceil(bits/8), whose parity flags a partial byte. */
        internal val d2: Int get() = bits / 8 + (bits + 7) / 8

        /**
         * The data as stored: a partial final byte gets a 1 bit marking the end
         * of real data, then zeroes. Without it, "five bits" and "five bits
         * followed by three zeroes" would be indistinguishable on the wire.
         */
        internal fun padded(): ByteArray {
            val out = data.copyOf((bits + 7) / 8)
            val used = bits % 8
            if (used != 0) {
                val keep = (0xFF shl (8 - used)) and 0xFF
                val last = out[out.size - 1].toInt() and 0xFF
                out[out.size - 1] = ((last and keep) or (1 shl (7 - used))).toByte()
            }
            return out
        }

        fun toBoc(crc32: Boolean = true): ByteArray = serialize(this, crc32)

        /** Cells are identified by hash everywhere in TON; so is equality here. */
        override fun equals(other: Any?): Boolean = other is Cell && hash.contentEquals(other.hash)
        override fun hashCode(): Int = hash.contentHashCode()
        override fun toString(): String = "Cell(${bits}b, ${refs.size} refs, ${hashHex.take(8)})"
    }

    /** The unique empty cell. It appears in real messages: an empty action list is one. */
    val EMPTY: Cell = Cell(ByteArray(0), 0, emptyList())

    /**
     * Accumulates bits most-significant-first, and references in order.
     *
     * [endCell] does not consume the builder, which is what lets a signature be
     * appended after the payload it signs: build, hash, sign, keep storing.
     * Wallet v5 packs its signature exactly that way.
     */
    class Builder {
        private val buf = ByteArray((MAX_BITS + 7) / 8)
        private var bits = 0
        private val refs = ArrayList<Cell>(MAX_REFS)

        val bitsUsed: Int get() = bits
        val refsUsed: Int get() = refs.size
        val bitsFree: Int get() = MAX_BITS - bits

        fun storeBit(bit: Int): Builder {
            require(bits < MAX_BITS) { "cell overflow: a cell holds $MAX_BITS bits" }
            if (bit != 0) {
                buf[bits ushr 3] = (buf[bits ushr 3].toInt() or (0x80 ushr (bits and 7))).toByte()
            }
            bits++
            return this
        }

        fun storeBit(bit: Boolean): Builder = storeBit(if (bit) 1 else 0)

        fun storeUint(value: Long, width: Int): Builder {
            require(width in 0..64) { "width out of range: $width" }
            // A silently truncated field is the worst outcome available here: it
            // produces a well-formed message that means something else.
            if (width < 64) {
                require(value >= 0) { "storeUint is unsigned, got $value" }
                require(value ushr width == 0L) { "$value does not fit in $width bits" }
            }
            for (i in width - 1 downTo 0) storeBit(((value ushr i) and 1L).toInt())
            return this
        }

        fun storeUint(value: BigInteger, width: Int): Builder {
            require(value.signum() >= 0) { "storeUint is unsigned" }
            require(value.bitLength() <= width) { "value does not fit in $width bits" }
            for (i in width - 1 downTo 0) storeBit(if (value.testBit(i)) 1 else 0)
            return this
        }

        fun storeBytes(bytes: ByteArray): Builder {
            for (b in bytes) storeUint((b.toInt() and 0xFF).toLong(), 8)
            return this
        }

        /**
         * VarUInteger 16: a four-bit byte count, then that many big-endian
         * bytes. Zero is four zero bits and nothing else.
         */
        fun storeCoins(value: BigInteger): Builder {
            require(value.signum() >= 0) { "an amount cannot be negative" }
            val mag = if (value.signum() == 0) ByteArray(0) else {
                val raw = value.toByteArray()
                // BigInteger prepends a zero byte when the top bit is set, to
                // keep the sign; TON wants the magnitude alone.
                if (raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
            }
            require(mag.size <= 15) { "amount exceeds VarUInteger 16" }
            storeUint(mag.size.toLong(), 4)
            return storeBytes(mag)
        }

        fun storeCoins(value: Long): Builder = storeCoins(BigInteger.valueOf(value))

        /** addr_std, no anycast. */
        fun storeAddress(workchain: Int, hash: ByteArray): Builder {
            require(hash.size == 32) { "an address hash is 32 bytes, got ${hash.size}" }
            require(workchain in -128..127) { "workchain out of range: $workchain" }
            storeUint(2, 2)
            storeBit(0)
            storeUint((workchain and 0xFF).toLong(), 8)
            return storeBytes(hash)
        }

        fun storeAddress(address: TonAddress): Builder = storeAddress(address.workchain, address.hash)

        /** addr_none, a sender that is nobody, or an unset response address. */
        fun storeAddressNone(): Builder = storeUint(0, 2)

        fun storeRef(cell: Cell): Builder {
            require(refs.size < MAX_REFS) { "a cell holds at most $MAX_REFS refs" }
            refs.add(cell)
            return this
        }

        fun storeMaybeRef(cell: Cell?): Builder {
            if (cell == null) return storeBit(0)
            return storeBit(1).storeRef(cell)
        }

        /**
         * Inlines a finished cell's contents into this one: its bits, then its
         * references. This is how a child rides in its parent instead of being
         * pointed at, which the message layouts do whenever there is room.
         */
        fun storeInline(cell: Cell): Builder {
            require(refs.size + cell.refs.size <= MAX_REFS) { "too many references to inline" }
            for (i in 0 until cell.bits) {
                storeBit((cell.data[i ushr 3].toInt() ushr (7 - (i and 7))) and 1)
            }
            refs.addAll(cell.refs)
            return this
        }

        /** Appends another builder's bits and refs, as storeBuilder does upstream. */
        fun storeBuilder(other: Builder): Builder {
            require(refs.size + other.refs.size <= MAX_REFS) { "too many refs to merge" }
            for (i in 0 until other.bits) {
                storeBit((other.buf[i ushr 3].toInt() ushr (7 - (i and 7))) and 1)
            }
            refs.addAll(other.refs)
            return this
        }

        /** Snapshots the builder. Safe to call repeatedly; the builder stays usable. */
        fun endCell(): Cell = Cell(buf.copyOf((bits + 7) / 8), bits, refs.toList())
    }

    fun builder(): Builder = Builder()

    // ── envelope ────────────────────────────────────────────────────────────

    /**
     * Orders the tree the way `@ton/core` does: depth-first from the root,
     * visiting each cell's references **last to first**, recording in
     * post-order, then reversing the result.
     *
     * Any order where a parent precedes its children is a legal envelope, so
     * this is a compatibility choice rather than a correctness one. Visiting
     * references forward instead, the obvious way, yields a different but
     * equally valid ordering, and every byte-for-byte test would fail.
     */
    private fun topological(root: Cell): List<Cell> {
        val byHash = LinkedHashMap<String, Cell>()
        var pending = listOf(root)
        while (pending.isNotEmpty()) {
            val next = ArrayList<Cell>()
            for (cell in pending) {
                if (byHash.put(cell.hashHex, cell) != null) continue
                next.addAll(cell.refs)
            }
            pending = next
        }

        val sorted = ArrayList<Cell>(byHash.size)
        val done = HashSet<String>()
        val active = HashSet<String>()
        fun visit(cell: Cell) {
            if (cell.hashHex in done) return
            check(active.add(cell.hashHex)) { "cell graph is not a DAG" }
            for (i in cell.refs.indices.reversed()) visit(cell.refs[i])
            active.remove(cell.hashHex)
            done.add(cell.hashHex)
            sorted.add(cell)
        }
        visit(root)
        for (cell in byHash.values) visit(cell)
        return sorted.reversed()
    }

    /** Bytes needed to hold [value], never fewer than one. */
    private fun widthFor(value: Int): Int {
        var bits = 0
        var v = value
        while (v > 0) {
            bits++
            v = v ushr 1
        }
        return maxOf((bits + 7) / 8, 1)
    }

    /** Serialises a cell tree into a bag of cells. */
    fun serialize(root: Cell, crc32: Boolean = true): ByteArray {
        val cells = topological(root)
        val indexOf = HashMap<String, Int>(cells.size * 2)
        cells.forEachIndexed { i, c -> indexOf[c.hashHex] = i }

        val sizeBytes = widthFor(cells.size)
        var totalCellSize = 0
        for (c in cells) totalCellSize += 2 + (c.bits + 7) / 8 + c.refs.size * sizeBytes
        val offsetBytes = widthFor(totalCellSize)

        val out = java.io.ByteArrayOutputStream(64 + totalCellSize)
        fun put(value: Long, width: Int) {
            for (i in width - 1 downTo 0) out.write(((value ushr (i * 8)) and 0xFF).toInt())
        }

        put(MAGIC, 4)
        // has_idx 0, has_crc32c, has_cache_bits 0, flags 00, then the ref width.
        out.write((if (crc32) 0x40 else 0x00) or sizeBytes)
        out.write(offsetBytes)
        put(cells.size.toLong(), sizeBytes)
        put(1, sizeBytes) // one root
        put(0, sizeBytes) // none absent
        put(totalCellSize.toLong(), offsetBytes)
        put(0, sizeBytes) // the root is cell zero

        for (c in cells) {
            out.write(c.refs.size) // ordinary, level 0
            out.write(c.d2)
            out.write(c.padded())
            for (r in c.refs) {
                val idx = indexOf[r.hashHex] ?: error("unreachable: reference missing from index")
                put(idx.toLong(), sizeBytes)
            }
        }

        val body = out.toByteArray()
        if (!crc32) return body
        val sum = crc32c(body)
        // Little-endian, unlike every other field in the format.
        return body + byteArrayOf(
            (sum and 0xFF).toByte(),
            ((sum ushr 8) and 0xFF).toByte(),
            ((sum ushr 16) and 0xFF).toByte(),
            ((sum ushr 24) and 0xFF).toByte(),
        )
    }

    /**
     * Reads a bag of cells back into a tree.
     *
     * Needed because a wallet's code cell is distributed as a BOC and cannot be
     * reconstructed from its hash. Exotic cells and non-zero levels are refused
     * rather than mis-parsed: nothing this app sends uses either, so meeting one
     * means the input is not what the caller believes it is.
     */
    fun parse(boc: ByteArray): Cell {
        require(boc.size >= 10) { "not a bag of cells: ${boc.size} bytes" }
        var p = 0
        fun u8(): Int {
            require(p < boc.size) { "bag of cells truncated" }
            return boc[p++].toInt() and 0xFF
        }
        fun un(width: Int): Int {
            var v = 0
            repeat(width) { v = (v shl 8) or u8() }
            return v
        }

        require(un(4).toLong() and 0xFFFFFFFFL == MAGIC) { "not a bag of cells" }
        val flags = u8()
        val hasIdx = (flags ushr 7) and 1 == 1
        val hasCrc = (flags ushr 6) and 1 == 1
        val sizeBytes = flags and 7
        require(sizeBytes in 1..4) { "unsupported reference width $sizeBytes" }
        val offsetBytes = u8()
        require(offsetBytes in 1..8) { "unsupported offset width $offsetBytes" }
        val count = un(sizeBytes)
        val roots = un(sizeBytes)
        un(sizeBytes) // absent
        un(offsetBytes) // total size, recomputed below by reading
        require(count in 1..8192) { "implausible cell count $count" }
        require(roots == 1) { "expected exactly one root, got $roots" }
        val rootIndex = un(sizeBytes)
        require(rootIndex < count) { "root index out of range" }
        if (hasIdx) repeat(count) { un(offsetBytes) }

        val descriptors = ArrayList<Triple<ByteArray, Int, IntArray>>(count)
        for (i in 0 until count) {
            val d1 = u8()
            val d2 = u8()
            require((d1 ushr 3) and 1 == 0) { "exotic cell at index $i" }
            require(d1 ushr 5 == 0) { "cell at index $i has a non-zero level" }
            val refCount = d1 and 7
            require(refCount <= MAX_REFS) { "cell at index $i claims $refCount references" }
            val byteLen = (d2 + 1) / 2
            require(p + byteLen <= boc.size) { "bag of cells truncated inside cell $i" }
            val raw = boc.copyOfRange(p, p + byteLen)
            p += byteLen
            // An odd descriptor means the final byte is padded: find the marker
            // bit and drop it, along with the zeroes after it.
            val bits = if (d2 % 2 == 0) {
                byteLen * 8
            } else {
                val last = raw[byteLen - 1].toInt() and 0xFF
                require(last != 0) { "cell $i is marked partial but its last byte is empty" }
                var used = 7
                while ((last ushr (7 - used)) and 1 == 0) used--
                (byteLen - 1) * 8 + used
            }
            val refs = IntArray(refCount) { un(sizeBytes) }
            for (r in refs) require(r in 0 until count) { "cell $i references $r, which does not exist" }
            descriptors.add(Triple(raw, bits, refs))
        }

        if (hasCrc) {
            require(p + 4 <= boc.size) { "checksum missing" }
            val want = crc32c(boc.copyOfRange(0, p))
            val got = (boc[p].toInt() and 0xFF) or
                ((boc[p + 1].toInt() and 0xFF) shl 8) or
                ((boc[p + 2].toInt() and 0xFF) shl 16) or
                ((boc[p + 3].toInt() and 0xFF) shl 24)
            require(want == got) { "bag of cells failed its checksum" }
        }

        // Standard envelopes reference only later cells, so a single backward
        // pass builds every child before the parent that needs it.
        val built = arrayOfNulls<Cell>(count)
        for (i in count - 1 downTo 0) {
            val (raw, bits, refs) = descriptors[i]
            val children = refs.map {
                require(it > i) { "cell $i references $it, which is not later in the bag" }
                built[it] ?: error("unreachable: child $it unbuilt")
            }
            built[i] = Cell(raw.copyOf((bits + 7) / 8), bits, children)
        }
        return built[rootIndex] ?: error("unreachable: root unbuilt")
    }

    /**
     * CRC-32C (Castagnoli), which is not the CRC in `java.util.zip`.
     *
     * Bitwise rather than table-driven: a few hundred bytes per message makes a
     * lookup table pure overhead, and there is less here to get wrong.
     */
    internal fun crc32c(bytes: ByteArray): Int {
        var crc = -1
        for (b in bytes) {
            crc = crc xor (b.toInt() and 0xFF)
            repeat(8) {
                crc = if (crc and 1 != 0) (crc ushr 1) xor 0x82F63B78.toInt() else crc ushr 1
            }
        }
        return crc.inv()
    }
}
