package com.ghosterdex.wallet.crypto

import android.content.Context
import com.ghosterdex.wallet.R
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * TON's mnemonic scheme, **not** BIP39.
 *
 * GhosterDex authorises every transaction with a TON Connect `signData`
 * signature made by the user's TON wallet key (see the Worker's
 * `verifyWalletSig`). So this, not [Bip39], is the derivation that actually
 * moves funds.
 *
 * Ported from `@ton/crypto`, the library the mini app itself depends on, which
 * in turn mirrors tonlib's `Mnemonic.cpp`:
 *
 * ```
 * entropy = HMAC-SHA512(key = words.join(" "), data = password)
 * seed    = PBKDF2-HMAC-SHA512(entropy, "TON default seed", 100000, 64)
 * privkey = seed[0..32]
 * ```
 *
 * Differences from BIP39 that matter, because getting any of them wrong yields
 * a valid-looking wallet at the wrong address:
 *
 *  - An HMAC step first; BIP39 has none.
 *  - Salt is `"TON default seed"`, not `"mnemonic"`.
 *  - 100,000 iterations, not 2,048.
 *  - There is **no checksum in the words**. Validity is instead a property of
 *    the derived entropy ([isBasicSeed]), so generation must retry until it
 *    holds. This is why [generate] loops.
 *
 * The wordlist is byte-identical to the BIP39 English list, verified by diffing
 * all 2048 entries against `@ton/crypto`'s copy, so the same bundled resource
 * is reused.
 */
object TonMnemonic {

    private const val PBKDF_ITERATIONS = 100_000
    private const val SEED_SALT = "TON default seed"
    private const val BASIC_SEED_SALT = "TON seed version"
    private const val PASSWORD_SEED_SALT = "TON fast seed version"
    private const val WORD_COUNT = 24

    @Volatile
    private var wordlist: List<String>? = null

    @Synchronized
    private fun words(context: Context): List<String> {
        wordlist?.let { return it }
        val loaded = context.resources.openRawResource(R.raw.bip39_english)
            .bufferedReader(StandardCharsets.UTF_8)
            .useLines { lines -> lines.map { it.trim() }.filter { it.isNotEmpty() }.toList() }
        require(loaded.size == 2048) { "Wordlist is corrupt: expected 2048 words, found ${loaded.size}" }
        wordlist = loaded
        return loaded
    }

    /**
     * Generates a valid 24-word TON mnemonic.
     *
     * Loops until the derived entropy satisfies [isBasicSeed] and does not look
     * password-protected. Exactly `mnemonicNew` in `@ton/crypto`. Expected
     * iterations are small (the check passes roughly 1 in 256), but each one
     * costs a 390-round PBKDF2, so this is not instant.
     */
    fun generate(context: Context, password: CharArray = CharArray(0)): CharArray {
        val list = words(context)
        val random = SecureRandom()

        while (true) {
            val picked = ArrayList<String>(WORD_COUNT)
            repeat(WORD_COUNT) {
                // nextInt over the full range, not a modulo of nextBytes. Modulo
                // on 2048 would be uniform here, but relying on that is the kind
                // of shortcut that breaks silently if the count ever changes.
                picked.add(list[random.nextInt(list.size)])
            }
            val candidate = picked.joinToString(" ").toCharArray()

            val entropy = toEntropy(candidate, password)
            val valid = try {
                // A passwordless mnemonic must be a basic seed and must not
                // already look like a password seed, or adding a password later
                // would silently select a different wallet.
                if (password.isEmpty()) isBasicSeed(entropy) && !isPasswordSeed(entropy)
                else isBasicSeed(entropy)
            } finally {
                entropy.fill(0)
            }

            if (valid) return candidate
            candidate.fill(' ')
            picked.clear()
        }
    }

    /**
     * Validates an existing mnemonic.
     *
     * With no word checksum to lean on, this checks membership, length and the
     * seed-version property. A single mistyped word will almost always fail
     * [isBasicSeed]. But not certainly, so this is weaker evidence than a BIP39
     * checksum and the UI should still show the derived address for the user to
     * recognise before funds are sent.
     */
    fun validate(context: Context, mnemonic: CharArray, password: CharArray = CharArray(0)): Boolean {
        val list = words(context).toHashSet()
        val normalized = Secrets.normalizeWords(mnemonic)
        try {
            val ranges = Secrets.wordRanges(normalized)
            if (ranges.size != WORD_COUNT) return false
            for (r in ranges) {
                // Membership needs a String for the hash lookup. Individual
                // words are far less revealing than the ordered phrase, which
                // stays in char arrays throughout. See Secrets.
                val word = String(normalized, r.first, r.last - r.first + 1)
                if (word !in list) return false
            }
            val entropy = toEntropy(normalized, password)
            return try {
                isBasicSeed(entropy)
            } finally {
                entropy.fill(0)
            }
        } finally {
            Secrets.wipe(normalized)
        }
    }

    /**
     * Words that are not in the BIP39 list, in the order they appear.
     *
     * Restore is where users lose funds to typos. "Invalid recovery phrase" is
     * useless when you have 24 words and one is wrong; naming the offenders
     * turns an unrecoverable dead end into a two-second fix. Only reports
     * membership failures. A phrase whose words are all real but whose order
     * is wrong cannot be localised this way, and is reported separately.
     */
    fun unknownWords(context: Context, mnemonic: CharArray): List<String> {
        val list = words(context).toHashSet()
        val normalized = Secrets.normalizeWords(mnemonic)
        return try {
            Secrets.wordRanges(normalized)
                .map { String(normalized, it.first, it.last - it.first + 1) }
                .filter { it !in list }
        } finally {
            Secrets.wipe(normalized)
        }
    }

    /** Word count after normalisation, for telling "too few" from "misspelled". */
    fun wordCount(mnemonic: CharArray): Int {
        val normalized = Secrets.normalizeWords(mnemonic)
        return try {
            Secrets.wordRanges(normalized).size
        } finally {
            Secrets.wipe(normalized)
        }
    }

    /**
     * TON's seed-version predicates alone, with no wordlist or length checks.
     *
     * Exists for [RecoveryPhrase.generate], which feeds in phrases already
     * known to be well-formed BIP39 and only needs to know whether they also
     * satisfy TON. Running the membership check there would be wasted work on
     * every one of the ~256 expected attempts.
     *
     * @param requirePasswordless mirrors `mnemonicNew`: a phrase intended to be
     *   used without a password must also not look like a password seed, or
     *   adding one later would silently select a different wallet.
     */
    internal fun satisfiesSeedVersion(
        mnemonic: CharArray,
        requirePasswordless: Boolean = true,
    ): Boolean {
        val normalized = Secrets.normalizeWords(mnemonic)
        val entropy = toEntropy(normalized, CharArray(0))
        return try {
            isBasicSeed(entropy) && (!requirePasswordless || !isPasswordSeed(entropy))
        } finally {
            entropy.fill(0)
            Secrets.wipe(normalized)
        }
    }

    /**
     * Derives the 32-byte Ed25519 private scalar.
     *
     * Caller owns the result and must wipe it.
     */
    fun toPrivateKey(mnemonic: CharArray, password: CharArray = CharArray(0)): ByteArray {
        // Normalised in place. The previous String chain here created five
        // unwipeable copies of the full phrase on a path that runs on every
        // single signature.
        val normalized = Secrets.normalizeWords(mnemonic)
        val entropy = toEntropy(normalized, password)
        return try {
            val seed = pbkdf2(entropy, SEED_SALT, PBKDF_ITERATIONS)
            try {
                seed.copyOfRange(0, 32)
            } finally {
                seed.fill(0)
            }
        } finally {
            entropy.fill(0)
            Secrets.wipe(normalized)
        }
    }

    // ── internals (mirroring tonlib Mnemonic.cpp) ────────────────────────────

    /** `hmac_sha512(key = joined words, data = password)`. Note the argument order. */
    private fun toEntropy(mnemonic: CharArray, password: CharArray): ByteArray {
        val key = Secrets.charsToUtf8(mnemonic)
        val data = Secrets.charsToUtf8(password)
        return try {
            val mac = HMac(SHA512Digest())
            mac.init(KeyParameter(key))
            mac.update(data, 0, data.size)
            ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
        } finally {
            key.fill(0)
            data.fill(0)
        }
    }

    /** `pbkdf2(entropy, "TON seed version", max(1, 100000/256))[0] == 0` */
    private fun isBasicSeed(entropy: ByteArray): Boolean {
        val hash = pbkdf2(entropy, BASIC_SEED_SALT, maxOf(1, PBKDF_ITERATIONS / 256))
        return try {
            hash[0].toInt() == 0
        } finally {
            hash.fill(0)
        }
    }

    /** `pbkdf2(entropy, "TON fast seed version", 1)[0] == 1` */
    private fun isPasswordSeed(entropy: ByteArray): Boolean {
        val hash = pbkdf2(entropy, PASSWORD_SEED_SALT, 1)
        return try {
            hash[0].toInt() == 1
        } finally {
            hash.fill(0)
        }
    }

    /** PBKDF2-HMAC-SHA512 with the entropy as password and [salt] as salt. Always 64 bytes. */
    private fun pbkdf2(entropy: ByteArray, salt: String, iterations: Int): ByteArray {
        val gen = PKCS5S2ParametersGenerator(SHA512Digest())
        gen.init(entropy, salt.toByteArray(StandardCharsets.UTF_8), iterations)
        return (gen.generateDerivedParameters(512) as KeyParameter).key
    }

}
