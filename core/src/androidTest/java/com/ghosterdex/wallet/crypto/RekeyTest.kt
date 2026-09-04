package com.ghosterdex.wallet.crypto

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets

/**
 * Changing a wallet's lock must never change the wallet.
 *
 * Re-keying decrypts the phrase and re-seals it under a new Keystore key. The
 * whole point is that everything a user cares about, the phrase, and so the
 * address their money sits at, comes through byte-identical. If that ever
 * stopped being true, the failure would look like a wallet quietly emptying
 * itself, so it is pinned here.
 *
 * Runs on [SecurityPolicy.NONE] in both directions because that is the pair
 * that needs no prompt; the auth-gated policies share the identical code path
 * with a BiometricPrompt in front (see WalletPlugin.changeLock).
 */
@RunWith(AndroidJUnit4::class)
class RekeyTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val slot = "9101"
    private val phrase =
        "soda ripple wire snap lift castle balance train short machine another mystery " +
            "buzz side pact random west loop fat mesh hollow purpose replace excuse"

    @After
    fun cleanUp() {
        SecureVault(context, slot).clear()
    }

    private fun seal(vault: SecureVault, policy: SecurityPolicy) {
        vault.store(vault.encryptCipher(policy), phrase.toByteArray(StandardCharsets.UTF_8))
        vault.storeSecurityPolicy(policy)
    }

    /** Re-key by hand, the way WalletPlugin.changeLock drives it. */
    private fun rekey(vault: SecureVault, to: SecurityPolicy) {
        val loaded = vault.load(vault.decryptCipher())
        val gen = vault.nextGeneration()
        vault.commitRekey(gen, vault.rekeyCipher(gen, to), loaded, to)
        loaded.fill(0)
    }

    @Test
    fun phraseSurvivesARekeyUnchanged() {
        val vault = SecureVault(context, slot)
        seal(vault, SecurityPolicy.NONE)

        rekey(vault, SecurityPolicy.NONE)

        assertEquals(SecurityPolicy.NONE, vault.securityPolicy())
        assertEquals(phrase, String(vault.load(vault.decryptCipher())))
        assertTrue(vault.hasWallet())
    }

    /**
     * The blob must actually be re-encrypted, not merely relabelled, a new
     * key that never touched the ciphertext would leave the old key able to
     * open it, which is the one thing changing a lock must prevent.
     */
    @Test
    fun rekeyProducesANewCiphertext() {
        val vault = SecureVault(context, slot)
        seal(vault, SecurityPolicy.NONE)

        val prefs = context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
        val before = prefs.getString("sealed_mnemonic.$slot", null)!!
        val ivBefore = prefs.getString("sealed_iv.$slot", null)!!

        rekey(vault, SecurityPolicy.NONE)

        assertNotEquals(before, prefs.getString("sealed_mnemonic.$slot", null))
        assertNotEquals(ivBefore, prefs.getString("sealed_iv.$slot", null))
    }

    /** Repeated changes keep working, the generation counter must advance. */
    @Test
    fun survivesRepeatedRekeys() {
        val vault = SecureVault(context, slot)
        seal(vault, SecurityPolicy.NONE)

        repeat(3) { rekey(vault, SecurityPolicy.NONE) }

        assertEquals(phrase, String(vault.load(vault.decryptCipher())))
    }

    /**
     * A re-key abandoned before its commit must leave the wallet exactly as it
     * was, this is the interrupted-user case, and the reason the new key is
     * built at a *pending* generation rather than over the live one.
     */
    @Test
    fun abandonedRekeyLeavesTheWalletIntact() {
        val vault = SecureVault(context, slot)
        seal(vault, SecurityPolicy.NONE)

        val prefs = context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
        val before = prefs.getString("sealed_mnemonic.$slot", null)

        // Build the pending key, then walk away, as a cancelled prompt does.
        val gen = vault.nextGeneration()
        vault.rekeyCipher(gen, SecurityPolicy.NONE)
        vault.abandonRekey(gen)

        assertEquals("blob must be untouched", before, prefs.getString("sealed_mnemonic.$slot", null))
        assertEquals(phrase, String(vault.load(vault.decryptCipher())))
    }

    /** Clearing a re-keyed wallet must still destroy it completely. */
    @Test
    fun clearWorksAfterRekey() {
        val vault = SecureVault(context, slot)
        seal(vault, SecurityPolicy.NONE)
        rekey(vault, SecurityPolicy.NONE)

        vault.clear()
        assertTrue(!vault.hasWallet())

        // And the slot is reusable from scratch afterwards.
        seal(vault, SecurityPolicy.NONE)
        assertEquals(phrase, String(vault.load(vault.decryptCipher())))
    }
}
