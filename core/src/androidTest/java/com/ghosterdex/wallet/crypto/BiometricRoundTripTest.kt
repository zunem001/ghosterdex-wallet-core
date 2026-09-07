package com.ghosterdex.wallet.crypto

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghosterdex.wallet.MainActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher

/**
 * The biometric **success** path, end to end.
 *
 * [SecureVaultTest] proves the vault refuses without authentication. This
 * proves it *works* with it, the half that cannot be tested without an
 * enrolled biometric, and therefore the half that silently goes unverified on
 * a default emulator.
 *
 * The chain exercised here is the whole wallet: a live fingerprint unlocks a
 * hardware-backed Keystore key, which decrypts the sealed phrase, which derives
 * the TON key, which must produce the exact address from the known vector. If
 * any link is wrong the address will not match.
 *
 * ## Running it
 *
 * Requires a fingerprint enrolled **and** something feeding the sensor while
 * the prompt is up, because the test cannot touch its own hardware:
 *
 * ```
 * # host, in parallel with the test run
 * while ($true) { adb emu finger touch 1; Start-Sleep -Milliseconds 500 }
 * ```
 *
 * Without an enrolment the test skips via [assumeTrue] rather than failing ,
 * a green run on a bare emulator must not be mistaken for coverage.
 */
@RunWith(AndroidJUnit4::class)
class BiometricRoundTripTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var vault: SecureVault

    /** From TonVectorsTest, same phrase, so the expected address is known. */
    private val phrase =
        "soda ripple wire snap lift castle balance train short machine another mystery " +
            "buzz side pact random west loop fat mesh hollow purpose replace excuse"
    private val expectedAddress = "0:40a42ae8d0aea047bb718e1d04a5b7c2af161b3c5225f56f874a46170e17a21c"

    private fun biometricsAvailable(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    @Before
    fun setUp() {
        assumeTrue("No STRONG biometric enrolled, skipping success-path test", biometricsAvailable())
        vault = SecureVault(context)
        vault.clear()
    }

    @After
    fun tearDown() {
        if (this::vault.isInitialized) vault.clear()
    }

    /**
     * Runs one CryptoObject-bound prompt and returns the authenticated Cipher.
     *
     * Mirrors [com.ghosterdex.wallet.WalletPlugin]'s configuration exactly ,
     * STRONG only, no device credential, so this tests the real policy rather
     * than a laxer one that happens to pass.
     */
    private fun authenticate(
        scenario: ActivityScenario<MainActivity>,
        cipher: Cipher,
        label: String,
    ): Cipher {
        val latch = CountDownLatch(1)
        var authed: Cipher? = null
        var failure: String? = null

        scenario.onActivity { activity ->
            val prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(context),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        authed = result.cryptoObject?.cipher
                        latch.countDown()
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        failure = "[$label] error $code: $message"
                        latch.countDown()
                    }
                },
            )
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle("GhosterDex test")
                    .setSubtitle(label)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Cancel")
                    .setConfirmationRequired(true)
                    .build(),
                BiometricPrompt.CryptoObject(cipher),
            )
        }

        assertTrue(
            "[$label] prompt never resolved, is something feeding `adb emu finger touch 1`?",
            latch.await(60, TimeUnit.SECONDS),
        )
        assertEquals(null, failure)
        assertNotNull("[$label] authentication returned no cipher", authed)
        return authed!!
    }

    @Test
    fun fingerprintUnlocksVaultAndDerivesTheRightWallet() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.use {
            // ── seal ─────────────────────────────────────────────────────────
            val phraseBytes = phrase.toByteArray(StandardCharsets.UTF_8)
            val sealCipher = authenticate(it, vault.encryptCipher(), "seal")
            vault.store(sealCipher, phraseBytes)
            phraseBytes.fill(0)

            assertTrue("Vault reports no wallet after storing one", vault.hasWallet())

            // ── open ─────────────────────────────────────────────────────────
            // A second, independent authentication. The zero-second auth window
            // means the seal above grants nothing here; this must stand on its
            // own or the "every transaction" policy is not real.
            val openCipher = authenticate(it, vault.decryptCipher(), "open")
            val recovered = vault.load(openCipher)

            try {
                assertEquals(
                    "Recovered phrase does not match what was sealed",
                    phrase,
                    String(recovered, StandardCharsets.UTF_8),
                )

                // The end-to-end assertion: the recovered phrase must derive the
                // same wallet the vectors expect. Catches any corruption between
                // Keystore, GCM, storage and derivation.
                // Pinned to V4R2 because that is what this vector was computed
                // under; the property being tested is that the vault round-trip
                // preserves the phrase, not which contract version is default.
                TonKey.fromMnemonicNative(
                    String(recovered, StandardCharsets.UTF_8).toCharArray(),
                    version = TonWalletVersion.V4R2,
                ).use { key ->
                    assertEquals(expectedAddress, key.addressRaw)
                }
            } finally {
                recovered.fill(0)
            }
        }
    }
}
