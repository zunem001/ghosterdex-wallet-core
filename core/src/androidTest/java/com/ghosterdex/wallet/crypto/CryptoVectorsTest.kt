package com.ghosterdex.wallet.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/**
 * Known-answer tests for the key derivation path.
 *
 * These are the tests that matter most in the whole project. A subtly wrong
 * derivation does not crash. It silently produces a *different, valid* wallet.
 * The user backs up a phrase, restores it elsewhere, and finds an empty
 * account, with no way to tell which side was wrong. Published vectors are the
 * only defence.
 */
@RunWith(AndroidJUnit4::class)
class CryptoVectorsTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun hex(b: ByteArray) = b.joinToString("") { String.format(Locale.ROOT, "%02x", it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    // ── BIP39 (official test vectors, passphrase "TREZOR") ───────────────────

    @Test
    fun bip39_allZeroEntropy_12words() {
        val mnemonic = Bip39.fromEntropy(context, unhex("00000000000000000000000000000000"))
        assertEquals(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            String(mnemonic),
        )
    }

    @Test
    fun bip39_allZeroEntropy_24words() {
        val mnemonic = Bip39.fromEntropy(
            context,
            unhex("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        val words = String(mnemonic).split(" ")
        assertEquals(24, words.size)
        assertEquals("abandon", words.first())
        assertEquals("art", words.last())
    }

    @Test
    fun bip39_seedDerivation_matchesVector() {
        val mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val seed = Bip39.toSeed(mnemonic.toCharArray(), "TREZOR".toCharArray())
        assertEquals(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a698" +
                "7599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            hex(seed),
        )
    }

    @Test
    fun bip39_validate_acceptsGoodRejectsBad() {
        val good =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        assertTrue(Bip39.validate(context, good.toCharArray()))

        // Last word carries the checksum. Swapping it must fail, not silently
        // derive a different wallet.
        val badChecksum = good.replace("about", "abandon")
        assertFalse(Bip39.validate(context, badChecksum.toCharArray()))

        // Word not in the list at all.
        assertFalse(Bip39.validate(context, good.replace("about", "ghosterdex").toCharArray()))

        // Wrong length.
        assertFalse(Bip39.validate(context, "abandon abandon about".toCharArray()))
    }

    @Test
    fun bip39_generate_isValidAndDistinct() {
        val a = Bip39.generate(context, 256)
        val b = Bip39.generate(context, 256)
        assertEquals(24, String(a).split(" ").size)
        assertTrue(Bip39.validate(context, a))
        assertTrue(Bip39.validate(context, b))
        // Two generations colliding would mean the RNG is broken.
        assertFalse(String(a) == String(b))
    }

    // ── SLIP-0010 Ed25519 (spec test vector 1) ───────────────────────────────

    @Test
    fun slip10_master_matchesVector() {
        val node = Slip10.derive(unhex("000102030405060708090a0b0c0d0e0f"), intArrayOf())
        assertEquals("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", hex(node.key))
        assertEquals("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", hex(node.chainCode))
    }

    @Test
    fun slip10_hardenedChild_matchesVector() {
        val node = Slip10.derive(
            unhex("000102030405060708090a0b0c0d0e0f"),
            intArrayOf(0 or 0x80000000.toInt()),
        )
        assertEquals("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", hex(node.key))
    }

    @Test(expected = IllegalArgumentException::class)
    fun slip10_rejectsNonHardenedIndex() {
        // Ed25519 has no non-hardened derivation. Accepting one would produce a
        // key that no other wallet agrees with.
        Slip10.derive(unhex("000102030405060708090a0b0c0d0e0f"), intArrayOf(0))
    }

    // ── Base58 ───────────────────────────────────────────────────────────────

    @Test
    fun base58_roundTripsAndPreservesLeadingZeros() {
        val withLeadingZero = unhex("0000287fb4cd")
        assertEquals("11233QC4", Base58.encode(withLeadingZero))
        assertArrayEquals(withLeadingZero, Base58.decode("11233QC4"))

        val random = ByteArray(32) { (it * 7 + 3).toByte() }
        assertArrayEquals(random, Base58.decode(Base58.encode(random)))
    }

    // ── End to end ───────────────────────────────────────────────────────────

    @Test
    fun nearKey_derivesStableIdentityAndVerifiableSignature() {
        val mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val seed = Bip39.toSeed(mnemonic.toCharArray())

        val first = NearKey.fromSeed(seed).use { it.publicKey to it.implicitAccountId }
        val second = NearKey.fromSeed(seed).use { it.publicKey to it.implicitAccountId }

        // Same phrase must always give the same account, on every device.
        assertEquals(first, second)
        assertTrue(first.first.startsWith("ed25519:"))
        // NEAR implicit account ids are the 64-char lowercase hex of the pubkey.
        assertEquals(64, first.second.length)
        assertTrue(first.second.matches(Regex("[0-9a-f]{64}")))

        // Signature verifies against the derived public key.
        NearKey.fromSeed(seed).use { key ->
            val message = "ghosterdex".toByteArray()
            val signature = key.sign(message)
            assertEquals(64, signature.size)

            val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
            verifier.init(
                false,
                org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(key.publicKeyBytes, 0),
            )
            verifier.update(message, 0, message.size)
            assertTrue(verifier.verifySignature(signature))
        }
    }

    @Test
    fun wipe_clearsSecrets() {
        val seed = Bip39.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".toCharArray())
        assertFalse(seed.all { it.toInt() == 0 })
        Bip39.wipe(seed)
        assertTrue(seed.all { it.toInt() == 0 })
    }
}
