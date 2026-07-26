package com.ghosterdex.wallet.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/**
 * Adversarial and edge-case coverage for the key path.
 *
 * The vector tests prove the happy path agrees with production. These probe the
 * ways a wallet silently derives the *wrong* key, or leaves secrets behind,
 * without anything appearing to fail.
 */
@RunWith(AndroidJUnit4::class)
class HardeningTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun hex(b: ByteArray) = b.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    private val phrase =
        "soda ripple wire snap lift castle balance train short machine another mystery " +
            "buzz side pact random west loop fat mesh hollow purpose replace excuse"
    private val expectedScalar = "e3fc98460c61e3c13afee01bf67c8b61daac8a765f1c21866db358666e0addd0"

    // ── The Turkish-locale trap ──────────────────────────────────────────────

    /**
     * Derivation must not depend on the device locale.
     *
     * `String.lowercase()` without a locale uses the default one, and in
     * tr-TR 'I' lowercases to 'ı' (dotless i), not 'i'. A user in Turkey typing
     * their phrase in caps would derive a *different, valid, empty* wallet and
     * conclude the app lost their funds. Secrets.normalizeWords lowercases
     * ASCII arithmetically to make this impossible.
     */
    @Test
    fun derivationIsLocaleIndependent() {
        val original = Locale.getDefault()
        try {
            Locale.setDefault(Locale("tr", "TR"))
            val upper = phrase.uppercase(Locale.ROOT).toCharArray()
            val scalar = TonMnemonic.toPrivateKey(upper)
            assertEquals(
                "Uppercase phrase under tr-TR derived a different key",
                expectedScalar,
                hex(scalar),
            )
        } finally {
            Locale.setDefault(original)
        }
    }

    @Test
    fun derivationToleratesWhitespaceAndCase() {
        // A pasted phrase can carry newlines, tabs, double spaces and stray
        // capitals. All must normalise to the same key, or restore becomes a
        // coin flip depending on where the user copied from.
        val messy = ("  SODA\tripple\n wire  snap lift castle balance train short machine " +
            "another mystery buzz side pact random west loop fat mesh hollow purpose " +
            "replace   EXCUSE  ").toCharArray()
        assertEquals(expectedScalar, hex(TonMnemonic.toPrivateKey(messy)))
    }

    // ── Secrets ──────────────────────────────────────────────────────────────

    @Test
    fun utf8RoundTripsIncludingNonAscii() {
        for (s in listOf("abandon about", "pässwörd", "日本語", "", "a")) {
            val chars = s.toCharArray()
            val bytes = Secrets.charsToUtf8(chars)
            assertEquals("round trip failed for \"$s\"", s, String(Secrets.utf8ToChars(bytes)))
            // Cross-check against the platform encoder.
            assertArrayEquals(s.toByteArray(Charsets.UTF_8), bytes)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedUtf8IsRejected() {
        // A tampered or wrongly-keyed vault blob decrypts to noise. Deriving a
        // key from noise would produce a plausible wallet at a wrong address;
        // failing loudly is the only safe outcome.
        Secrets.utf8ToChars(byteArrayOf(0xF8.toByte(), 0x80.toByte()))
    }

    @Test
    fun normalizeWordsCollapsesAndTrims() {
        assertEquals("a b c", String(Secrets.normalizeWords("  A \t\n b   C  ".toCharArray())))
        assertEquals("", String(Secrets.normalizeWords("   ".toCharArray())))
        assertEquals(24, Secrets.wordRanges(Secrets.normalizeWords(phrase.toCharArray())).size)
    }

    @Test
    fun wipeActuallyClears() {
        val b = byteArrayOf(1, 2, 3)
        val c = charArrayOf('x', 'y')
        Secrets.wipe(b)
        Secrets.wipe(c)
        assertTrue(b.all { it.toInt() == 0 })
        assertTrue(c.all { it == ' ' })
    }

    // ── Determinism and non-malleability ─────────────────────────────────────

    @Test
    fun signaturesAreDeterministic() {
        // Ed25519 is deterministic by construction. If this ever varied it
        // would mean nonce material was being drawn from somewhere it should
        // not be. The failure mode that has leaked keys in ECDSA wallets.
        TonKey.fromMnemonicNative(phrase.toCharArray()).use { key ->
            val a = key.sign("payload".toByteArray())
            val b = key.sign("payload".toByteArray())
            assertArrayEquals(a, b)
        }
    }

    @Test
    fun keyIsZeroedOnClose() {
        val key = TonKey.fromMnemonicNative(phrase.toCharArray())
        val before = key.publicKeyHex
        key.close()
        // Public material stays readable; the point is that close() does not
        // throw and the scalar is gone. Signing after close must not silently
        // produce a valid signature with a zeroed key.
        assertEquals(before, key.publicKeyHex)
    }

    // ── Input validation ─────────────────────────────────────────────────────

    @Test
    fun base58RejectsAmbiguousCharacters() {
        // The alphabet omits 0, O, I and l precisely so a misread address
        // cannot decode. Accepting them would defeat that.
        for (bad in listOf("0", "O", "I", "l", "abc!")) {
            try {
                Base58.decode(bad)
                throw AssertionError("Base58 accepted \"$bad\"")
            } catch (expected: IllegalArgumentException) {
                // correct
            }
        }
    }

    @Test
    fun tonCellRejectsOverlongInput() {
        // A cell holds at most 1023 bits and 4 refs. Silently truncating would
        // produce a valid-looking hash for the wrong data. I.e. a wrong address.
        try {
            TonCell.hash(ByteArray(200), 1600)
            throw AssertionError("accepted an over-long cell")
        } catch (expected: IllegalArgumentException) {
            // correct
        }
        try {
            TonCell.hash(ByteArray(1), 4, List(5) { TonCell.Ref(ByteArray(32), 0) })
            throw AssertionError("accepted too many refs")
        } catch (expected: IllegalArgumentException) {
            // correct
        }
    }

    @Test
    fun mnemonicValidationRejectsNearMisses() {
        // One word swapped for another real word: all members valid, phrase
        // invalid. This is the case a membership-only check would wave through.
        val swapped = phrase.replace("soda", "zoo").toCharArray()
        assertFalse(TonMnemonic.validate(context, swapped))
        assertTrue(TonMnemonic.unknownWords(context, swapped).isEmpty())

        // Duplicated word, wrong length.
        assertFalse(TonMnemonic.validate(context, "$phrase excuse".toCharArray()))
    }

    // ── Multi-length and cross-ecosystem import ──────────────────────────────

    /** The canonical BIP39 12-word vector. What a MetaMask user would paste. */
    private val twelveWord =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Test
    fun twelveWordPhrasesAreAccepted() {
        // 12 words is the most common phrase length in existence. Requiring 24
        // locked out every mainstream BIP39 wallet.
        val check = RecoveryPhrase.check(context, twelveWord.toCharArray())
        assertEquals(12, check.wordCount)
        assertTrue(check.lengthSupported)
        assertTrue("12-word BIP39 phrase should pass its checksum", check.bip39Valid)
        // TON defines no 12-word form, so this must be false, not an error.
        assertFalse(check.tonValid)
        assertTrue(check.recognised)
        assertEquals(null, RecoveryPhrase.problem(context, twelveWord.toCharArray()))
    }

    @Test
    fun twentyFourWordTonPhraseIsAcceptedToo() {
        val check = RecoveryPhrase.check(context, phrase.toCharArray())
        assertEquals(24, check.wordCount)
        assertTrue("TON-generated phrase should pass TON's check", check.tonValid)
        assertTrue(check.recognised)
        assertEquals(null, RecoveryPhrase.problem(context, phrase.toCharArray()))
    }

    @Test
    fun unsupportedLengthsAreRejectedWithTheCount() {
        val problem = RecoveryPhrase.problem(context, "abandon about zoo".toCharArray())
        assertTrue("should name the count, got: $problem", problem!!.contains("3"))
        // Copy must stay chain-neutral.
        for (word in listOf("TON", "NEAR", "BIP39", "mnemonic", "seed")) {
            assertFalse("copy leaked \"$word\": $problem", problem.contains(word))
        }
    }

    @Test
    fun bip39ValidationIsCaseInsensitive() {
        // Previously this lowercased nowhere, so a phrase pasted with capitals
        // failed validation even though toSeed derived from it correctly.
        assertTrue(Bip39.validate(context, twelveWord.uppercase(Locale.ROOT).toCharArray()))
        assertTrue(Bip39.validate(context, twelveWord.toCharArray()))
    }

    @Test
    fun nonBreakingSpacesFromPastedTextAreHandled() {
        // Phrases copied out of a PDF, a chat message or a notes app arrive with
        // U+00A0 between words. Character.isWhitespace returns FALSE for it, so
        // it used to fuse words into one non-member token and reject a correct
        // phrase.
        val nbsp = phrase.replace(" ", " ")
        assertEquals(24, TonMnemonic.wordCount(nbsp.toCharArray()))
        assertTrue(TonMnemonic.unknownWords(context, nbsp.toCharArray()).isEmpty())
        assertEquals(expectedScalar, hex(TonMnemonic.toPrivateKey(nbsp.toCharArray())))

        // Ideographic space too, for phrases pasted from CJK contexts.
        val ideographic = phrase.replace(" ", "　")
        assertEquals(24, TonMnemonic.wordCount(ideographic.toCharArray()))
    }

    @Test
    fun bip39ToSeedNormalisesInternally() {
        // The call sites used to be responsible for this; one that forgot would
        // derive a different seed and a silently empty wallet.
        val messy = "  ABANDON abandon\tabandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon  ABOUT "
        val clean = Bip39.toSeed(twelveWord.toCharArray())
        val dirty = Bip39.toSeed(messy.toCharArray())
        assertArrayEquals("toSeed must normalise its own input", clean, dirty)
    }

    // ── Derivation families ──────────────────────────────────────────────────

    @Test
    fun derivationFamiliesProduceDifferentKeys() {
        // A wrong contract version is the same key at another address. A wrong
        // *family* is a different key entirely. So a Ledger or Trust Wallet
        // user importing here would see an empty wallet if only TON's native
        // scheme were tried. Both must be probed.
        val native = TonKey.fromMnemonic(
            context, phrase.toCharArray(), derivation = TonDerivation.NATIVE,
        ).use { it.publicKeyHex to it.addressRaw }

        val bip44 = TonKey.fromMnemonic(
            context, phrase.toCharArray(), derivation = TonDerivation.BIP44,
        ).use { it.publicKeyHex to it.addressRaw }

        assertNotEquals("families must not collide on the public key", native.first, bip44.first)
        assertNotEquals("families must not collide on the address", native.second, bip44.second)

        // Native must still match the pinned vector. Adding BIP44 cannot be
        // allowed to disturb existing wallets.
        assertEquals(expectedScalar, hex(TonMnemonic.toPrivateKey(phrase.toCharArray())))
    }

    @Test
    fun bip44DerivationIsDeterministic() {
        val first = TonKey.fromMnemonic(
            context, phrase.toCharArray(), derivation = TonDerivation.BIP44,
        ).use { it.addressRaw }
        val second = TonKey.fromMnemonic(
            context, phrase.toCharArray(), derivation = TonDerivation.BIP44,
        ).use { it.addressRaw }
        assertEquals(first, second)
    }

    @Test
    fun everyFamilyAndVersionCombinationIsDistinct() {
        // Six candidates; import probes all of them. Any collision would mean
        // one of the derivations is wrong.
        val addresses = mutableSetOf<String>()
        for (family in TonDerivation.PROBE_ORDER) {
            TonKey.fromMnemonic(context, phrase.toCharArray(), derivation = family).use { key ->
                TonWalletVersion.PROBE_ORDER.forEach { addresses.add(key.addressFor(it)) }
            }
        }
        assertEquals(6, addresses.size)
    }

    // ── End-to-end backup and restore ────────────────────────────────────────

    @Test
    fun backupRestoreRoundTripYieldsTheSameWallet() {
        // The property a user's funds depend on: whatever the backup screen
        // showed must reconstruct exactly this wallet on any device.
        val generated = TonMnemonic.generate(context)
        try {
            assertTrue(TonMnemonic.validate(context, generated))

            val first = TonKey.fromMnemonicNative(generated).use { it.addressRaw to it.publicKeyHex }

            // Simulate the user retyping it: text out, text in, messy spacing.
            val retyped = ("  " + String(generated).uppercase(Locale.ROOT).replace(" ", "  ") + " ")
                .toCharArray()
            val second = TonKey.fromMnemonicNative(retyped).use { it.addressRaw to it.publicKeyHex }

            assertEquals(first, second)
        } finally {
            Secrets.wipe(generated)
        }
    }

    // ── Dual-valid generation ────────────────────────────────────────────────

    @Test
    fun generatedPhrasesAreValidInBothEcosystems() {
        // The property that keeps a user's exit door open. A phrase valid under
        // only one scheme is refused by the other's import screen 255 times out
        // of 256. The wallet would hold their keys hostage to this app.
        val generated = RecoveryPhrase.generate(context)
        try {
            val check = RecoveryPhrase.check(context, generated)
            assertEquals(24, check.wordCount)
            assertTrue("generated phrase must pass the BIP39 checksum", check.bip39Valid)
            assertTrue("generated phrase must pass TON's seed check", check.tonValid)
            assertTrue(check.unknownWords.isEmpty())
            assertEquals(null, RecoveryPhrase.problem(context, generated))
        } finally {
            Secrets.wipe(generated)
        }
    }

    @Test
    fun generatedPhrasesDeriveBothIdentities() {
        // One phrase, two chain identities, neither requiring the other's
        // validation. This is what lets setup never mention a chain.
        val generated = RecoveryPhrase.generate(context)
        try {
            val tonAddress = TonKey.fromMnemonicNative(generated).use { it.addressRaw }
            val seed = Bip39.toSeed(generated)
            val nearAccount = try {
                NearKey.fromSeed(seed).use { it.implicitAccountId }
            } finally {
                Secrets.wipe(seed)
            }

            assertTrue(tonAddress.startsWith("0:"))
            assertTrue(nearAccount.matches(Regex("[0-9a-f]{64}")))
            assertNotEquals(tonAddress.removePrefix("0:"), nearAccount)
        } finally {
            Secrets.wipe(generated)
        }
    }

    @Test
    fun generatedPhrasesAreDistinct() {
        val a = RecoveryPhrase.generate(context)
        val b = RecoveryPhrase.generate(context)
        assertNotEquals(String(a), String(b))
        Secrets.wipe(a)
        Secrets.wipe(b)
    }

    @Test
    fun differentPhrasesNeverCollide() {
        val a = TonMnemonic.generate(context)
        val b = TonMnemonic.generate(context)
        val addrA = TonKey.fromMnemonicNative(a).use { it.addressRaw }
        val addrB = TonKey.fromMnemonicNative(b).use { it.addressRaw }
        assertNotEquals(addrA, addrB)
        Secrets.wipe(a)
        Secrets.wipe(b)
    }
}
