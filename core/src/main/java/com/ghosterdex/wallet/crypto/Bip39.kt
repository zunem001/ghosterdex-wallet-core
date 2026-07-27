package com.ghosterdex.wallet.crypto

import android.content.Context
import com.ghosterdex.wallet.R
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.text.Normalizer
import kotlin.math.min

/**
 * BIP39 mnemonic generation, validation and seed derivation.
 *
 * Implemented directly against Bouncy Castle's lightweight primitives rather
 * than pulled in as a third-party wallet library. This is the one code path
 * where a compromised dependency means total, silent loss of user funds, so it
 * is worth the ~150 lines to own it.
 *
 * ## On wiping memory
 *
 * Secrets are handled as [CharArray] and [ByteArray] and wiped with [wipe] as
 * soon as they are dead. This is meaningfully better than using [String]. Which
 * is immutable and cannot be cleared, so a mnemonic held as a String lingers in
 * the heap until GC decides otherwise, and can be captured by a heap dump.
 *
 * It is not a guarantee. The JVM may relocate arrays during GC and leave copies
 * behind. The design goal is to shrink the window, not to claim it is closed -
 * the real protection is that this material never leaves Kotlin.
 */
object Bip39 {

    /** BIP39 fixes both of these; they are not tunable. */
    private const val PBKDF2_ITERATIONS = 2048
    private const val SEED_BITS = 512

    @Volatile
    private var wordlist: List<String>? = null

    /** Index lookup for validation/decoding. A linear scan of 2048 words per input word adds up. */
    @Volatile
    private var wordIndex: Map<String, Int>? = null

    /**
     * Loads and caches the bundled English wordlist.
     *
     * The list is verified at build time (2048 unique, sorted, lowercase words,
     * sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
     * The size check here guards against a corrupted or substituted resource:
     * a short list would silently change every derived key.
     */
    @Synchronized
    private fun words(context: Context): List<String> {
        wordlist?.let { return it }
        val loaded = context.resources.openRawResource(R.raw.bip39_english)
            .bufferedReader(StandardCharsets.UTF_8)
            .useLines { lines -> lines.map { it.trim() }.filter { it.isNotEmpty() }.toList() }

        require(loaded.size == 2048) {
            "BIP39 wordlist is corrupt: expected 2048 words, found ${loaded.size}"
        }

        wordlist = loaded
        wordIndex = loaded.withIndex().associate { (i, w) -> w to i }
        return loaded
    }

    /**
     * Words from the bundled list that begin with [prefix], for the restore
     * screen's suggestions.
     *
     * The suggestions have to come from here rather than from the keyboard.
     * A system dictionary that "corrects" a recovery word is a known way to
     * lose a wallet, which is why every phrase field sets
     * `TYPE_TEXT_FLAG_NO_SUGGESTIONS` and asks for no personalised learning.
     * This offers the same convenience from the only list that is actually
     * authoritative, offline, with nothing typed leaving the process.
     *
     * BIP39 guarantees the first four letters identify a word, so a prefix of
     * four or more can only match one entry, and the caller can accept it
     * without ambiguity.
     */
    fun suggest(context: Context, prefix: String, limit: Int = 24): List<String> {
        if (prefix.isEmpty()) return emptyList()
        val list = words(context)
        // The list is sorted, so matches for a prefix are one contiguous run:
        // binary search to its start and walk while the prefix still holds.
        var lo = 0
        var hi = list.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (list[mid] < prefix) lo = mid + 1 else hi = mid
        }
        val out = ArrayList<String>(min(limit, 8))
        var i = lo
        while (i < list.size && out.size < limit && list[i].startsWith(prefix)) {
            out.add(list[i])
            i++
        }
        return out
    }

    /** True when [word] is in the bundled list exactly. */
    fun isWord(context: Context, word: String): Boolean {
        words(context)
        return wordIndex?.containsKey(word) == true
    }

    /**
     * Generates a fresh mnemonic.
     *
     * @param strengthBits 128 for 12 words, 256 for 24. Defaults to 256. The
     *   extra six words cost the user nothing at backup time and this is a key
     *   that cannot be rotated after funds arrive.
     */
    fun generate(context: Context, strengthBits: Int = 256): CharArray {
        require(strengthBits == 128 || strengthBits == 160 || strengthBits == 192 || strengthBits == 224 || strengthBits == 256) {
            "strengthBits must be one of 128/160/192/224/256"
        }
        val entropy = ByteArray(strengthBits / 8)
        // SecureRandom with no seeding call: on Android this is backed by the
        // kernel CSPRNG. Never substitute Random or a time-based seed here.
        SecureRandom().nextBytes(entropy)
        return try {
            fromEntropy(context, entropy)
        } finally {
            wipe(entropy)
        }
    }

    /**
     * Encodes entropy as a mnemonic: entropy bits followed by a checksum of the
     * first ENT/32 bits of sha256(entropy), split into 11-bit word indices.
     */
    fun fromEntropy(context: Context, entropy: ByteArray): CharArray {
        val list = words(context)
        val checksumBits = entropy.size * 8 / 32
        val hash = sha256(entropy)

        val bits = StringBuilder(entropy.size * 8 + checksumBits)
        for (b in entropy) bits.append(byteToBits(b))
        bits.append(byteToBits(hash[0]).substring(0, checksumBits.coerceAtMost(8)))
        if (checksumBits > 8) bits.append(byteToBits(hash[1]).substring(0, checksumBits - 8))
        wipe(hash)

        val picked = ArrayList<String>(bits.length / 11)
        for (i in 0 until bits.length / 11) {
            picked.add(list[bits.substring(i * 11, (i + 1) * 11).toInt(2)])
        }

        val out = picked.joinToString(" ").toCharArray()
        // The StringBuilder held every entropy bit as text; clear it explicitly.
        bits.setLength(0)
        picked.clear()
        return out
    }

    /**
     * Validates word membership, length, and the embedded checksum.
     *
     * The checksum is what makes a single mistyped word fail loudly instead of
     * silently deriving a different, empty wallet. The classic way users
     * conclude an import "lost" their funds.
     */
    fun validate(context: Context, mnemonic: CharArray): Boolean {
        words(context)
        val index = wordIndex ?: return false

        // Normalised in place. Previously this did `String(mnemonic).trim()`
        // with no lowercasing, so a phrase pasted with capitals failed
        // validation even though toSeed would derive from it correctly. And it
        // left an unwipeable String of the entire phrase on the heap.
        val normalized = Secrets.normalizeWords(mnemonic)
        try {
            val ranges = Secrets.wordRanges(normalized)
            if (ranges.size !in VALID_WORD_COUNTS) return false

            val bits = StringBuilder(ranges.size * 11)
            for (r in ranges) {
                val word = String(normalized, r.first, r.last - r.first + 1)
                val i = index[word] ?: return false
                bits.append(i.toString(2).padStart(11, '0'))
            }
            return checksumHolds(bits, ranges.size)
        } finally {
            Secrets.wipe(normalized)
        }
    }

    /** BIP39 permits these lengths; TON only ever uses 24. */
    val VALID_WORD_COUNTS = setOf(12, 15, 18, 21, 24)

    private fun checksumHolds(bits: StringBuilder, wordCount: Int): Boolean {
        val entropyBits = wordCount * 11 * 32 / 33
        val checksumBits = wordCount * 11 - entropyBits
        val entropy = ByteArray(entropyBits / 8)
        for (i in entropy.indices) {
            entropy[i] = bits.substring(i * 8, (i + 1) * 8).toInt(2).toByte()
        }

        val hash = sha256(entropy)
        val expected = buildString {
            append(byteToBits(hash[0]).substring(0, checksumBits.coerceAtMost(8)))
            if (checksumBits > 8) append(byteToBits(hash[1]).substring(0, checksumBits - 8))
        }
        val actual = bits.substring(entropyBits)

        wipe(entropy)
        wipe(hash)
        bits.setLength(0)

        // Constant-time-ish: these are public-derived values, but comparing with
        // a plain == on Strings of equal short length is fine here.
        return expected == actual
    }

    /**
     * Derives the 64-byte BIP39 seed: PBKDF2-HMAC-SHA512, 2048 iterations,
     * password = NFKD(mnemonic), salt = NFKD("mnemonic" + passphrase).
     *
     * Caller owns the returned array and must [wipe] it.
     */
    fun toSeed(mnemonic: CharArray, passphrase: CharArray = CharArray(0)): ByteArray {
        // Word normalisation happens HERE, not at the call sites.
        //
        // It used to be the caller's job, and every existing caller did it -
        // but a caller that forgets produces a silently different seed and so
        // an empty wallet, with nothing failing anywhere. Making it
        // unconditional means a new call site cannot get this wrong.
        val words = Secrets.normalizeWords(mnemonic)
        val normalizedMnemonic = try {
            normalizeToUtf8(words)
        } finally {
            Secrets.wipe(words)
        }

        // The passphrase is deliberately NOT put through normalizeWords: BIP39
        // requires NFKD only, and lowercasing or collapsing spaces inside a
        // user-chosen passphrase would change the seed it produces.
        val saltChars = ("mnemonic".toCharArray() + passphrase)
        val normalizedSalt = normalizeToUtf8(saltChars)

        return try {
            val gen = PKCS5S2ParametersGenerator(SHA512Digest())
            gen.init(normalizedMnemonic, normalizedSalt, PBKDF2_ITERATIONS)
            (gen.generateDerivedParameters(SEED_BITS) as KeyParameter).key
        } finally {
            wipe(normalizedMnemonic)
            wipe(normalizedSalt)
            saltChars.fill(' ')
        }
    }

    // ── internals ────────────────────────────────────────────────────────────

    private fun sha256(data: ByteArray): ByteArray {
        val d = SHA256Digest()
        d.update(data, 0, data.size)
        val out = ByteArray(d.digestSize)
        d.doFinal(out, 0)
        return out
    }

    private fun byteToBits(b: Byte): String =
        (b.toInt() and 0xFF).toString(2).padStart(8, '0')

    /**
     * NFKD-normalizes and UTF-8 encodes without ever materialising a String.
     *
     * [Normalizer] only accepts CharSequence, so a CharBuffer wrapper is used -
     * it views the same char[] rather than copying it the way String would.
     */
    private fun normalizeToUtf8(chars: CharArray): ByteArray {
        val normalized: CharArray = if (Normalizer.isNormalized(CharBuffer.wrap(chars), Normalizer.Form.NFKD)) {
            chars.copyOf()
        } else {
            // The normalizing path is the one case a String is unavoidable;
            // it is dropped immediately and is not the long-lived copy.
            Normalizer.normalize(CharBuffer.wrap(chars), Normalizer.Form.NFKD).toCharArray()
        }

        return try {
            val encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val buffer = encoder.encode(CharBuffer.wrap(normalized))
            val out = ByteArray(buffer.remaining())
            buffer.get(out)
            // Overwrite the encoder's backing buffer before releasing it.
            if (buffer.hasArray()) buffer.array().fill(0)
            out
        } finally {
            normalized.fill(' ')
        }
    }

    fun wipe(data: ByteArray?) = data?.fill(0)

    fun wipe(data: CharArray?) = data?.fill(' ')
}
