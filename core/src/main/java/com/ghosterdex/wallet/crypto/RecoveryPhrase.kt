package com.ghosterdex.wallet.crypto

import android.content.Context

/**
 * Chain-agnostic recovery-phrase handling.
 *
 * GhosterDex presents one wallet. A user pasting a phrase should never be asked
 * which ecosystem it came from, and should never be told, so this reports what
 * a phrase *is* without leaking that into the UI's vocabulary.
 *
 * ## Validation is evidence, not permission
 *
 * Neither derivation function needs a phrase to validate. [TonMnemonic.toPrivateKey]
 * and [Bip39.toSeed] are total on arbitrary text, they never consult the
 * wordlist. A phrase always yields a key.
 *
 * So the checks here answer only "is this the phrase the user thinks it is?".
 * They are a typo detector with a **1-in-256 false-accept rate on each side**,
 * which is far too weak to be the last line of defence. The real backstop is
 * showing the user an address and a balance they recognise, see SECURITY.md.
 *
 * ## Word counts
 *
 * BIP39 allows 12/15/18/21/24. TON only ever defines 24. A 12-word phrase from
 * a mainstream wallet is therefore perfectly importable even though it can
 * never satisfy TON's check, which is why word count and scheme are reported
 * separately rather than collapsed into one "valid" flag.
 */
object RecoveryPhrase {

    /**
     * Generates a phrase valid under **both** schemes.
     *
     * ## Why both
     *
     * A phrase valid under only one is refused by the other ecosystem's import
     * screen 255 times out of 256. Since a self-custodial wallet's whole promise
     * is "you can take your money elsewhere", a one-sided phrase quietly breaks
     * the promise: the user holds the keys but no other app will accept them.
     * Dual-valid keeps both exit doors open.
     *
     * ## Why this costs nothing extra
     *
     * The obvious approach, draw 24 random words, test both predicates,
     * needs 2⁻¹⁶, or ~65,536 attempts. **256× more expensive than today.**
     *
     * Instead, entropy is drawn and encoded with [Bip39.fromEntropy], which
     * makes the BIP39 checksum correct *by construction*, it is computed, not
     * guessed. Only TON's seed-version predicate is then searched, at 2⁻⁸. So
     * the expected work is ~256 attempts, the same as the TON-only generator
     * this replaces, for a phrase that is valid in both ecosystems.
     *
     * ## Entropy is not weakened
     *
     * This samples uniformly from the ~1/256 of 256-bit entropy values whose
     * derived TON entropy begins with a zero byte, roughly 2²⁴⁸ candidates
     * remain. The constraint is a public property of a PRF output, not
     * structure an attacker can exploit.
     *
     * Slow enough (~1–3s) that callers must keep it off the UI thread.
     */
    fun generate(context: Context): CharArray {
        val random = java.security.SecureRandom()
        // A degraded entropy source produces output that still looks correct,
        // so it is tested before any seed is drawn rather than trusted, and
        // every draw is mixed across independent sources. See Entropy.kt.
        Entropy.assertHealthy(context, random)
        val entropy = ByteArray(32) // 32 bytes -> 24 words

        try {
            // Generous bound. At p = 1/256 per attempt the chance of reaching
            // this is astronomically small, so hitting it means the RNG is
            // broken, which must fail loudly, never silently return a weak
            // phrase.
            repeat(MAX_GENERATION_ATTEMPTS) {
                Entropy.strengthened(random, entropy)
                val candidate = Bip39.fromEntropy(context, entropy)
                if (TonMnemonic.satisfiesSeedVersion(candidate)) {
                    return candidate
                }
                Secrets.wipe(candidate)
            }
        } finally {
            entropy.fill(0)
        }

        throw IllegalStateException(
            "Could not generate a dual-valid recovery phrase after " +
                "$MAX_GENERATION_ATTEMPTS attempts. The random source may be faulty."
        )
    }

    private const val MAX_GENERATION_ATTEMPTS = 100_000

    data class Check(
        val wordCount: Int,
        /** Words absent from the 2048-word list, in order of appearance. */
        val unknownWords: List<String>,
        /** Passes TON's seed-version check. Only ever true at 24 words. */
        val tonValid: Boolean,
        /** Passes the BIP39 checksum. */
        val bip39Valid: Boolean,
    ) {
        val lengthSupported: Boolean get() = wordCount in Bip39.VALID_WORD_COUNTS

        /**
         * We have positive evidence this phrase is intact.
         *
         * Not the same as "usable", an unrecognised phrase still derives keys
         * perfectly well. It means we have no evidence the user typed it right.
         */
        val recognised: Boolean get() = tonValid || bip39Valid
    }

    fun check(context: Context, phrase: CharArray): Check {
        val count = TonMnemonic.wordCount(phrase)
        val unknown = TonMnemonic.unknownWords(context, phrase)

        // No point running checksums over words that are not in the list.
        if (count !in Bip39.VALID_WORD_COUNTS || unknown.isNotEmpty()) {
            return Check(count, unknown, tonValid = false, bip39Valid = false)
        }

        return Check(
            wordCount = count,
            unknownWords = emptyList(),
            // TON defines no 12/15/18/21-word form, so asking is meaningless.
            tonValid = count == 24 && TonMnemonic.validate(context, phrase),
            bip39Valid = Bip39.validate(context, phrase),
        )
    }

    /**
     * A human-readable problem, or null if the phrase is good to import.
     *
     * Copy rules: no "TON", "NEAR", "BIP39", "mnemonic", "seed" or "chain". The
     * user has a *recovery phrase* for their *wallet*, and which ecosystem it
     * belongs to is not their problem.
     */
    fun problem(context: Context, phrase: CharArray): String? {
        val check = check(context, phrase)

        if (check.wordCount == 0) return "Enter your recovery phrase."

        if (!check.lengthSupported) {
            return "A recovery phrase is usually 12 or 24 words. You entered ${check.wordCount}."
        }

        if (check.unknownWords.isNotEmpty()) {
            val shown = check.unknownWords.take(3).joinToString(", ")
            val more = if (check.unknownWords.size > 3) {
                " (+${check.unknownWords.size - 3} more)"
            } else {
                ""
            }
            return if (check.unknownWords.size == 1) {
                "“$shown” isn't a recovery word. Check that one."
            } else {
                "These aren't recovery words: $shown$more."
            }
        }

        if (!check.recognised) {
            // Deliberately not "invalid": the phrase derives a key perfectly
            // well, we simply have no evidence it is the right one. Saying
            // "invalid" would send a user with a genuine phrase away, when the
            // overwhelmingly likely cause is two words transposed.
            return "Every word is real, but we couldn't verify the phrase. Check the order."
        }

        return null
    }
}
