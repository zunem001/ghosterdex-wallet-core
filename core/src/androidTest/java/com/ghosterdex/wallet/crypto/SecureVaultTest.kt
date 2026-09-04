package com.ghosterdex.wallet.crypto

import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies the vault's security property directly: **there is no path to a
 * usable key without a live biometric.**
 *
 * This is deliberately written to assert something meaningful in both
 * environments, because most CI devices and emulators have no biometric
 * enrolled and it would be easy to write a test that silently passes by doing
 * nothing there.
 *
 *  - Biometrics enrolled → the key exists, but using it without authenticating
 *    must throw [UserNotAuthenticatedException].
 *  - No biometrics → key *generation* must fail outright. The failure mode that
 *    matters is the one this rules out: quietly falling back to an unprotected
 *    key so the app "works", which would leave the phrase sealed behind nothing.
 */
@RunWith(AndroidJUnit4::class)
class SecureVaultTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var vault: SecureVault

    private fun biometricsAvailable(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    @Before
    fun setUp() {
        vault = SecureVault(context)
        vault.clear()
    }

    @After
    fun tearDown() {
        vault.clear()
    }

    @Test
    fun walletVersionIsStoredAndRoundTrips() {
        // The address is a hash of the deployed code, so a release that moved
        // TonWalletVersion.DEFAULT would relocate every existing wallet if this
        // were inferred rather than recorded.
        vault.storePublicIdentity("abc123", "0:deadbeef", TonWalletVersion.V4R2)
        assertEquals(TonWalletVersion.V4R2, vault.walletVersion())

        vault.storePublicIdentity("abc123", "0:deadbeef", TonWalletVersion.V5R1)
        assertEquals(TonWalletVersion.V5R1, vault.walletVersion())
    }

    @Test
    fun walletVersionDefaultsToV4R2ForPreExistingInstalls() {
        // Wallets created before the version was recorded predate the V5R1
        // default, so an absent value must mean V4R2, not "today's default",
        // which would silently move their address.
        vault.clear()
        assertEquals(TonWalletVersion.V4R2, vault.walletVersion())
    }

    @Test
    fun freshVault_hasNothing() {
        assertFalse(vault.hasWallet())
        assertNull(vault.publicIdentity())
    }

    @Test
    fun publicIdentity_isReadableWithoutAuthentication() {
        // Public keys are not secrets. Gating them would mean a biometric
        // prompt just to render the home screen.
        vault.storePublicIdentity("abc123", "0:deadbeef", TonWalletVersion.V5R1)
        val identity = vault.publicIdentity()
        assertTrue(identity != null && identity.first == "abc123" && identity.second == "0:deadbeef")
    }

    /**
     * Walks the cause chain for evidence that the *Keystore* refused on
     * authentication grounds.
     *
     * Necessary because the platform does not surface this as one exception
     * type. On keystore2 (API 30+) an unauthenticated per-use key fails at
     * `doFinal` with [javax.crypto.IllegalBlockSizeException] wrapping a
     * `KeyStoreException(KEY_USER_NOT_AUTHENTICATED)`; other configurations
     * throw [UserNotAuthenticatedException] at `init`. Asserting on the type
     * alone would pass for the wrong reason, or fail while the gate is
     * working, which is what happened the first time this test ran on an
     * enrolled device.
     */
    private fun isAuthRefusal(t: Throwable): Boolean {
        var e: Throwable? = t
        while (e != null) {
            if (e is UserNotAuthenticatedException) return true
            val msg = e.message ?: ""
            if (msg.contains("KEY_USER_NOT_AUTHENTICATED") ||
                msg.contains("Key user not authenticated", ignoreCase = true)
            ) return true
            e = e.cause
        }
        return false
    }

    @Test
    fun keyIsUnusableWithoutBiometricAuthentication() {
        if (biometricsAvailable()) {
            val cipher = vault.encryptCipher()
            // The key was created with a zero-second auth window, so the OS
            // must refuse until a CryptoObject-bound prompt has succeeded.
            try {
                cipher.doFinal("secret".toByteArray())
                throw AssertionError(
                    "Vault encrypted without authentication, the biometric gate is not enforced"
                )
            } catch (e: AssertionError) {
                throw e
            } catch (e: Exception) {
                // Assert the *reason*, not merely that something threw: a
                // padding or key-size bug would also throw, and would look
                // like security while providing none.
                assertTrue(
                    "Operation failed, but not because the user was unauthenticated: $e",
                    isAuthRefusal(e),
                )
            }
        } else {
            // Without an enrolment there is no way to build an authentication-
            // required key, and we must fail rather than degrade.
            try {
                vault.encryptCipher()
                throw AssertionError(
                    "Vault created a key with no biometric enrolled, it would not be auth-protected"
                )
            } catch (expected: UserNotAuthenticatedException) {
                // Also correct: some versions surface it this way.
            } catch (expected: Exception) {
                assertTrue(
                    "Unexpected failure type: ${expected::class.java.name}: ${expected.message}",
                    expected is java.security.InvalidAlgorithmParameterException ||
                        expected is IllegalStateException ||
                        expected is java.security.ProviderException,
                )
            }
        }
    }

    @Test
    fun clear_removesEverything() {
        vault.storePublicIdentity("abc123", "0:deadbeef", TonWalletVersion.V5R1)
        vault.clear()
        assertFalse(vault.hasWallet())
        assertNull(vault.publicIdentity())
    }
}
