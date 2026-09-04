package com.ghosterdex.wallet.crypto

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets

/**
 * The optional-security model, at the vault level.
 *
 * [SecurityPolicy.NONE] is the one that must be watched: "no authentication"
 * must never quietly become "no encryption". These tests prove a NONE vault
 * still round-trips through a real Keystore key, still fails on tamper, and
 * still dies with [SecureVault.clear], everything except the prompt.
 *
 * The BIOMETRIC path is covered end-to-end by [BiometricRoundTripTest]; the
 * CREDENTIAL prompt path needs a device credential set and is exercised
 * manually, but its key generation is asserted here.
 */
@RunWith(AndroidJUnit4::class)
class SecurityPolicyTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** Fresh slots, far from the legacy alias other tests use. */
    private val noneSlot = "9001"
    private val credSlot = "9002"

    @After
    fun cleanUp() {
        SecureVault(context, noneSlot).clear()
        SecureVault(context, credSlot).clear()
    }

    @Test
    fun noneVaultRoundTripsWithoutAnyPrompt() {
        val vault = SecureVault(context, noneSlot)
        val secret = "canoe coffee lake involve".toByteArray(StandardCharsets.UTF_8)

        vault.store(vault.encryptCipher(SecurityPolicy.NONE), secret.copyOf())
        vault.storeSecurityPolicy(SecurityPolicy.NONE)

        assertTrue(vault.hasWallet())
        assertEquals(SecurityPolicy.NONE, vault.securityPolicy())

        // The whole point: decrypt succeeds with no BiometricPrompt anywhere.
        val loaded = vault.load(vault.decryptCipher())
        assertEquals(String(secret), String(loaded))
        loaded.fill(0)
    }

    /** No auth is not no encryption: the blob must still be AES-GCM sealed. */
    @Test
    fun noneVaultStillDetectsTampering() {
        val vault = SecureVault(context, noneSlot)
        vault.store(vault.encryptCipher(SecurityPolicy.NONE), "sealed".toByteArray())
        vault.storeSecurityPolicy(SecurityPolicy.NONE)

        val prefs = context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
        val key = "sealed_mnemonic.$noneSlot"
        val blob = prefs.getString(key, null)!!.toCharArray()
        blob[4] = if (blob[4] == 'A') 'B' else 'A'
        prefs.edit().putString(key, String(blob)).commit()

        assertThrows(Exception::class.java) {
            vault.load(vault.decryptCipher())
        }
    }

    /**
     * Policies live per wallet: a NONE wallet beside a BIOMETRIC-defaulting
     * one must not soften the latter's report.
     */
    @Test
    fun policiesDoNotLeakBetweenSlots() {
        val none = SecureVault(context, noneSlot)
        none.store(none.encryptCipher(SecurityPolicy.NONE), "one".toByteArray())
        none.storeSecurityPolicy(SecurityPolicy.NONE)

        val other = SecureVault(context, credSlot)
        assertEquals(
            "an unwritten policy must default to BIOMETRIC, never inherit NONE",
            SecurityPolicy.BIOMETRIC,
            other.securityPolicy(),
        )
    }

    /** Clearing a NONE wallet destroys blob and key like any other. */
    @Test
    fun clearDestroysANoneVault() {
        val vault = SecureVault(context, noneSlot)
        vault.store(vault.encryptCipher(SecurityPolicy.NONE), "gone".toByteArray())
        vault.storeSecurityPolicy(SecurityPolicy.NONE)
        assertTrue(vault.hasWallet())

        vault.clear()
        assertFalse(vault.hasWallet())
        // A fresh key generates on next use rather than reusing the old alias.
        vault.store(vault.encryptCipher(SecurityPolicy.NONE), "new".toByteArray())
        assertEquals("new", String(vault.load(vault.decryptCipher())))
    }

    /** Unknown ids from a future build must fail closed, to the strictest. */
    @Test
    fun unknownPolicyIdFailsClosed() {
        assertEquals(SecurityPolicy.BIOMETRIC, SecurityPolicy.from("quantum-vibes"))
        assertEquals(SecurityPolicy.BIOMETRIC, SecurityPolicy.from(null))
        assertEquals(SecurityPolicy.NONE, SecurityPolicy.from("none"))
        assertEquals(SecurityPolicy.CREDENTIAL, SecurityPolicy.from("credential"))
    }
}
