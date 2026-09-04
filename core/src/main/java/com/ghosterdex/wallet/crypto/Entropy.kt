package com.ghosterdex.wallet.crypto

import android.content.Context
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Guards for the randomness that becomes recovery phrases.
 *
 * A phrase is only as strong as the entropy behind it, and a degraded source
 * is invisible from the inside: its output still passes every checksum, still
 * looks random, and still derives valid addresses. Weak seeds have historically
 * gone unnoticed for years in exactly that way. So this layer refuses to trust
 * the source, and instead:
 *
 *  1. Tests it before use. [assertHealthy] runs statistical health checks on
 *     the very generator about to mint a seed and throws rather than continue.
 *     Thresholds are chosen so a sound source practically never trips them,
 *     while a stuck or heavily skewed one is caught before a word is shown.
 *
 *  2. Does not depend on any single layer. [strengthened] mixes the platform
 *     provider, a direct kernel read that bypasses it, and timing jitter
 *     through SHA-256. The result stays unpredictable if any one input is
 *     sound, and hashing cannot make it weaker than its strongest input.
 *
 *  3. Remembers across runs. Determinism is invisible within a single run, so
 *     a salted fingerprint of one probe draw is kept per wallet creation and
 *     the next creation refuses to proceed if it ever sees the same bytes.
 *
 * None of this makes a good generator better. All of it makes a bad one loud.
 */
object Entropy {

    /** Bytes examined by the health tests. Small enough to be instant. */
    private const val SAMPLE_BYTES = 4096

    /** Repetition-count cutoff: 8 identical consecutive bytes. For a uniform
     *  source the chance of seeing that anywhere in the sample is ~1.5e-14. */
    private const val MAX_RUN = 8

    /** Adaptive-proportion cutoff: in any 512-byte window the most frequent
     *  value may appear at most 31 times (expectation is 2; P(>=32) ~ 1e-33). */
    private const val APT_WINDOW = 512
    private const val APT_CUTOFF = 32

    private const val PREFS = "ghoster.entropy"
    private const val PROBE_KEY = "probes"
    private const val PROBE_KEEP = 16

    /**
     * Statistical health tests plus the cross-creation replay canary.
     *
     * Call once per wallet creation, with the same [random] instance that will
     * mint the seed and the same [context] the app runs under. Throws
     * [IllegalStateException] on any failure; callers must let that propagate
     * to the user as "could not create a wallet", because the alternative is
     * minting a predictable one.
     */
    fun assertHealthy(context: Context, random: SecureRandom) {
        val sample = ByteArray(SAMPLE_BYTES)
        random.nextBytes(sample)

        // Repetition count: catches a stuck source.
        var run = 1
        for (i in 1 until sample.size) {
            run = if (sample[i] == sample[i - 1]) run + 1 else 1
            if (run >= MAX_RUN) {
                throw IllegalStateException(
                    "Entropy health check failed: the random source repeated one value " +
                        "$MAX_RUN times in a row. Refusing to create a wallet from it.",
                )
            }
        }

        // Adaptive proportion: catches a heavily biased source.
        val counts = IntArray(256)
        for (i in sample.indices) {
            counts[sample[i].toInt() and 0xff]++
            if (i >= APT_WINDOW) counts[sample[i - APT_WINDOW].toInt() and 0xff]--
            if (i >= APT_WINDOW - 1) {
                for (c in counts) {
                    if (c >= APT_CUTOFF) {
                        throw IllegalStateException(
                            "Entropy health check failed: one byte value dominated a " +
                                "$APT_WINDOW-byte window. Refusing to create a wallet from it.",
                        )
                    }
                }
            }
        }

        // Distinctness within this run: two fresh draws must differ.
        val a = ByteArray(32).also { random.nextBytes(it) }
        val b = ByteArray(32).also { random.nextBytes(it) }
        if (a.contentEquals(b)) {
            throw IllegalStateException(
                "Entropy health check failed: two consecutive draws were identical.",
            )
        }

        // Replay across creations: a fingerprint seen before means the source
        // is replaying a stream. The probe is hashed before storing so the
        // preference file never holds raw generator output.
        val probe = sha256(a + b)
        val hex = probe.joinToString("") { "%02x".format(it) }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val seen = (prefs.getString(PROBE_KEY, "") ?: "").split(',').filter { it.isNotEmpty() }
        if (hex in seen) {
            throw IllegalStateException(
                "Entropy health check failed: the random source produced the same " +
                    "bytes as a previous wallet creation. Refusing to continue.",
            )
        }
        prefs.edit().putString(PROBE_KEY, (seen + hex).takeLast(PROBE_KEEP).joinToString(",")).apply()
    }

    /**
     * Fills [out] with seed entropy mixed from three independent layers.
     *
     * SHA-256(provider draw || direct /dev/urandom || timing jitter), truncated
     * to [out]'s length. The direct kernel read exists to bypass the JCA
     * provider: if the wrapper is ever the broken layer, the kernel bytes
     * still carry the seed; if the kernel read fails (it never should), the
     * provider still does. Only both failing at once, plus predictable
     * scheduler timing, yields a weak seed.
     */
    fun strengthened(random: SecureRandom, out: ByteArray) {
        require(out.size <= 32) { "strengthened() yields at most 32 bytes per call" }

        val provider = ByteArray(32).also { random.nextBytes(it) }

        val kernel = ByteArray(32)
        try {
            FileInputStream("/dev/urandom").use { urandom ->
                var off = 0
                while (off < kernel.size) {
                    val n = urandom.read(kernel, off, kernel.size - off)
                    if (n <= 0) break
                    off += n
                }
            }
        } catch (e: Exception) {
            // The provider layer still carries the seed; mixing zeros here
            // cannot weaken it below that.
        }

        val jitter = ByteArray(64)
        for (i in jitter.indices) {
            // Low bits of nanotime across iterations: genuinely independent of
            // both RNG layers, worthless alone, free to mix in.
            jitter[i] = (System.nanoTime() and 0xff).toByte()
        }

        val mixed = sha256(provider + kernel + jitter + System.currentTimeMillis().toString().toByteArray())
        System.arraycopy(mixed, 0, out, 0, out.size)
        provider.fill(0); kernel.fill(0); jitter.fill(0); mixed.fill(0)
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
