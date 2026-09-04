package com.ghosterdex.wallet.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * The app's own lock: one passcode for the whole wallet, not one per account.
 *
 * ## What this protects, and what it does not
 *
 * This is a **gate on the app**, and it is honest about being exactly that.
 * The thing standing between an attacker and your coins is still
 * [SecureVault]: the recovery phrase is sealed with a key that lives in the
 * Android Keystore, is not extractable, and is released only under whatever
 * authentication that wallet was created with. This lock does not replace any
 * of that and does not re-encrypt the phrase.
 *
 * What it does defend against is the overwhelmingly common case: someone
 * picking up a phone that is already unlocked. Before this existed, a wallet
 * created with "No lock" was one tap away for anyone holding the device.
 *
 * Saying it plainly matters, because the alternative design is tempting and
 * dangerous. Wrapping the vault in a passcode-derived key would make the
 * passcode the single thing standing between a user and their money, and a
 * forgotten six digits would burn a wallet that its owner still has the phrase
 * for. Here, forgetting the passcode costs the local copy and nothing else:
 * reset, restore from the phrase, carry on.
 *
 * ## How the passcode is checked
 *
 * Not by storing it. A random 32-byte secret is generated when the lock is
 * turned on, and two independently wrapped copies are kept:
 *
 *  - one encrypted under a key derived from the passcode with PBKDF2, salted,
 *    at [PBKDF2_ITERATIONS] iterations. Entering the right digits is the only
 *    way to derive the key that opens it;
 *  - one encrypted under a Keystore key that requires biometric
 *    authentication, written only if the user turns biometrics on.
 *
 * Unlocking means recovering that secret by either route. Storing a hash of
 * the passcode would have been simpler and worse: a six-digit space is a
 * million guesses, which is nothing offline, whereas PBKDF2 at this iteration
 * count makes each guess cost real time, and the Keystore copy cannot be
 * attacked off the device at all.
 *
 * Attempts are rate limited on top ([lockoutRemainingMs]), because a million
 * guesses is only nothing if you are allowed to make them quickly.
 */
object AppLock {

    private const val PREFS = "ghoster_applock"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_SALT = "salt"
    private const val KEY_VERIFIER = "verifier"
    private const val KEY_VERIFIER_IV = "verifier_iv"
    private const val KEY_BIO_BLOB = "bio_blob"
    private const val KEY_BIO_IV = "bio_iv"
    private const val KEY_BIO_ON = "bio_on"
    private const val KEY_AUTOLOCK = "autolock_ms"
    private const val KEY_FAILURES = "failures"
    private const val KEY_LOCKED_UNTIL = "locked_until"

    private const val BIO_KEY_ALIAS = "ghosterdex_applock_bio_v1"
    private const val PBKDF2_ITERATIONS = 150_000
    private const val SECRET_BYTES = 32
    private const val GCM_TAG_BITS = 128

    /** Digits in a passcode. Six is the shape people expect from a phone. */
    const val PASSCODE_LENGTH = 6

    /** Wrong tries allowed before the pad starts refusing for a while. */
    private const val FREE_ATTEMPTS = 5

    /**
     * Deriving a key is meant to be slow. 150,000 PBKDF2 rounds is what makes
     * guessing a six digit code expensive, and the same arithmetic that costs
     * an attacker time costs the UI thread a visible freeze: run on the main
     * looper it produced an "isn't responding" dialog on the first wrong code.
     * Every entry point that derives therefore has an async twin, and the
     * synchronous ones are for tests and background callers only.
     */
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "applock-kdf").apply { isDaemon = true }
    }

    private fun onMain(block: () -> Unit) =
        android.os.Handler(android.os.Looper.getMainLooper()).post(block)

    /** [verify] off the UI thread. Takes ownership of [passcode] and wipes it. */
    fun verifyAsync(context: Context, passcode: CharArray, onResult: (Boolean) -> Unit) {
        worker.execute {
            val ok = verify(context, passcode)
            Secrets.wipe(passcode)
            onMain { onResult(ok) }
        }
    }

    /** [enable] off the UI thread. Takes ownership of [passcode] and wipes it. */
    fun enableAsync(context: Context, passcode: CharArray, onResult: (Boolean) -> Unit) {
        worker.execute {
            val ok = enable(context, passcode)
            Secrets.wipe(passcode)
            onMain { onResult(ok) }
        }
    }

    /**
     * [biometricEnrollCipher] off the UI thread. The passcode is NOT wiped:
     * the caller still needs it to commit the biometric copy afterwards.
     */
    fun biometricEnrollCipherAsync(context: Context, passcode: CharArray, onResult: (Cipher?) -> Unit) {
        worker.execute {
            val c = biometricEnrollCipher(context, passcode)
            onMain { onResult(c) }
        }
    }

    // ── preferences ──────────────────────────────────────────────────────────

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** True when the user has turned the app lock on. */
    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, false) && prefs(context).contains(KEY_VERIFIER)

    /** True when unlocking with a fingerprint or face is allowed as well. */
    fun isBiometricEnabled(context: Context): Boolean =
        isEnabled(context) && prefs(context).getBoolean(KEY_BIO_ON, false) && prefs(context).contains(KEY_BIO_BLOB)

    /**
     * How long the app may sit in the background before it locks again.
     *
     * Zero means lock the moment it leaves the foreground, which is the safest
     * and the default. A short grace period exists because locking during the
     * two seconds someone spends copying an address out of another app turns a
     * security feature into a reason to switch it off.
     */
    fun autoLockMs(context: Context): Long = prefs(context).getLong(KEY_AUTOLOCK, 0L)

    fun setAutoLockMs(context: Context, ms: Long) {
        prefs(context).edit().putLong(KEY_AUTOLOCK, ms).apply()
    }

    // ── turning it on and off ────────────────────────────────────────────────

    /**
     * Turn the lock on with [passcode]. Returns false only if the platform
     * refuses the key derivation, which should not happen on any supported
     * device but is reported rather than crashed on.
     */
    fun enable(context: Context, passcode: CharArray): Boolean {
        return try {
            val secret = ByteArray(SECRET_BYTES).also { SecureRandom().nextBytes(it) }
            val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val key = deriveKey(passcode, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            val verifier = cipher.doFinal(secret)
            prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_SALT, b64(salt))
                .putString(KEY_VERIFIER, b64(verifier))
                .putString(KEY_VERIFIER_IV, b64(cipher.iv))
                .remove(KEY_BIO_BLOB)
                .remove(KEY_BIO_IV)
                .putBoolean(KEY_BIO_ON, false)
                .putInt(KEY_FAILURES, 0)
                .putLong(KEY_LOCKED_UNTIL, 0L)
                .apply()
            Secrets.wipe(secret)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Turn the lock off. Requires the current passcode, so someone who picked
     * up an unlocked phone cannot simply switch the protection off.
     */
    fun disable(context: Context, passcode: CharArray): Boolean {
        if (!verify(context, passcode)) return false
        prefs(context).edit()
            .remove(KEY_ENABLED)
            .remove(KEY_SALT)
            .remove(KEY_VERIFIER)
            .remove(KEY_VERIFIER_IV)
            .remove(KEY_BIO_BLOB)
            .remove(KEY_BIO_IV)
            .remove(KEY_BIO_ON)
            .remove(KEY_FAILURES)
            .remove(KEY_LOCKED_UNTIL)
            .apply()
        deleteBioKey()
        return true
    }

    /** Change the passcode, proving the old one first. */
    fun change(context: Context, current: CharArray, next: CharArray): Boolean {
        if (!verify(context, current)) return false
        val hadBio = isBiometricEnabled(context)
        if (!enable(context, next)) return false
        // The biometric copy wrapped the OLD secret, so it is now meaningless.
        // Say so rather than leaving a stale blob that would fail to unlock.
        if (hadBio) deleteBioKey()
        return true
    }

    /**
     * Forget everything this object stores.
     *
     * Used by the reset path, where the user has forgotten their passcode and
     * chooses to wipe the app and restore from their recovery phrase. Wiping
     * the wallets themselves is the caller's job; this only takes the lock off
     * so the fresh start is actually reachable.
     */
    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
        deleteBioKey()
    }

    // ── unlocking ────────────────────────────────────────────────────────────

    /**
     * Is this the right passcode?
     *
     * Deliberately returns only true or false: the caller cannot learn how
     * close a guess was, because there is nothing to learn. A correct answer
     * clears the failure count; a wrong one advances it.
     */
    fun verify(context: Context, passcode: CharArray): Boolean {
        val p = prefs(context)
        val salt = unb64(p.getString(KEY_SALT, null) ?: return false)
        val verifier = unb64(p.getString(KEY_VERIFIER, null) ?: return false)
        val iv = unb64(p.getString(KEY_VERIFIER_IV, null) ?: return false)
        return try {
            val key = deriveKey(passcode, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            val secret = cipher.doFinal(verifier) // throws unless the key is right
            Secrets.wipe(secret)
            p.edit().putInt(KEY_FAILURES, 0).putLong(KEY_LOCKED_UNTIL, 0L).apply()
            true
        } catch (e: Exception) {
            noteFailure(context)
            false
        }
    }

    /** How long the pad must stay closed, in ms. Zero when it is open. */
    fun lockoutRemainingMs(context: Context): Long {
        val until = prefs(context).getLong(KEY_LOCKED_UNTIL, 0L)
        val left = until - System.currentTimeMillis()
        return if (left > 0) left else 0
    }

    /** Wrong attempts since the last success, for the "N tries left" line. */
    fun failureCount(context: Context): Int = prefs(context).getInt(KEY_FAILURES, 0)

    /**
     * Back off after repeated wrong guesses.
     *
     * A six digit code is a million possibilities, which sounds like a lot and
     * is not: a script that could try them freely would be through the space
     * in an afternoon. The delay grows with each failure past the first few,
     * capped at five minutes so a genuine user who fumbles is inconvenienced
     * rather than locked out of their own money.
     */
    private fun noteFailure(context: Context) {
        val p = prefs(context)
        val n = p.getInt(KEY_FAILURES, 0) + 1
        val editor = p.edit().putInt(KEY_FAILURES, n)
        if (n > FREE_ATTEMPTS) {
            val step = (n - FREE_ATTEMPTS).coerceAtMost(6)
            val waitMs = (1L shl step) * 5_000L // 10s, 20s, 40s … capped below
            editor.putLong(KEY_LOCKED_UNTIL, System.currentTimeMillis() + waitMs.coerceAtMost(300_000L))
        }
        editor.apply()
    }

    // ── biometric ────────────────────────────────────────────────────────────

    /**
     * A cipher for turning biometric unlock ON, to be handed to a
     * `BiometricPrompt` as a `CryptoObject`. The prompt succeeding is what
     * authorises the key, and only then can [commitBiometric] store anything.
     */
    fun biometricEnrollCipher(context: Context, passcode: CharArray): Cipher? {
        if (!verify(context, passcode)) return null
        return try {
            deleteBioKey()
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            gen.init(
                KeyGenParameterSpec.Builder(
                    BIO_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)
                    // Every unlock proves itself. A time window would let a
                    // recent unrelated authentication open the wallet.
                    .apply {
                        if (android.os.Build.VERSION.SDK_INT >= 30) {
                            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        } else {
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(-1)
                        }
                        // Enrolling a new finger must invalidate this key, or
                        // anyone who can add a fingerprint to an unlocked phone
                        // inherits the wallet.
                        setInvalidatedByBiometricEnrollment(true)
                        if (android.os.Build.VERSION.SDK_INT >= 28) setUnlockedDeviceRequired(true)
                    }
                    .build(),
            )
            val key = gen.generateKey()
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Store the biometric copy of the secret, using a cipher the user has just
     * authenticated. Called from the prompt's success callback.
     */
    fun commitBiometric(context: Context, passcode: CharArray, cipher: Cipher): Boolean {
        return try {
            val secret = recoverSecret(context, passcode) ?: return false
            val blob = cipher.doFinal(secret)
            Secrets.wipe(secret)
            prefs(context).edit()
                .putString(KEY_BIO_BLOB, b64(blob))
                .putString(KEY_BIO_IV, b64(cipher.iv))
                .putBoolean(KEY_BIO_ON, true)
                .apply()
            true
        } catch (e: Exception) {
            false
        }
    }

    /** A cipher for unlocking by biometric, or null if that is not set up. */
    fun biometricUnlockCipher(context: Context): Cipher? {
        if (!isBiometricEnabled(context)) return null
        val iv = unb64(prefs(context).getString(KEY_BIO_IV, null) ?: return null)
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = ks.getKey(BIO_KEY_ALIAS, null) as? SecretKey ?: return null
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (e: Exception) {
            // A wiped or invalidated key (new fingerprint enrolled, say) lands
            // here. The passcode still works, which is the whole point of
            // keeping two independent routes to the same secret.
            null
        }
    }

    /** Finish a biometric unlock with the authenticated cipher. */
    fun unlockWithBiometric(context: Context, cipher: Cipher): Boolean {
        val blob = unb64(prefs(context).getString(KEY_BIO_BLOB, null) ?: return false)
        return try {
            val secret = cipher.doFinal(blob)
            Secrets.wipe(secret)
            prefs(context).edit().putInt(KEY_FAILURES, 0).putLong(KEY_LOCKED_UNTIL, 0L).apply()
            true
        } catch (e: Exception) {
            false
        }
    }

    /** True when this device can actually do strong biometrics right now. */
    fun biometricAvailable(context: Context): Boolean {
        val mgr = androidx.biometric.BiometricManager.from(context)
        return mgr.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    }

    fun disableBiometric(context: Context) {
        prefs(context).edit().putBoolean(KEY_BIO_ON, false).remove(KEY_BIO_BLOB).remove(KEY_BIO_IV).apply()
        deleteBioKey()
    }

    // ── internals ────────────────────────────────────────────────────────────

    private fun recoverSecret(context: Context, passcode: CharArray): ByteArray? {
        val p = prefs(context)
        val salt = unb64(p.getString(KEY_SALT, null) ?: return null)
        val verifier = unb64(p.getString(KEY_VERIFIER, null) ?: return null)
        val iv = unb64(p.getString(KEY_VERIFIER_IV, null) ?: return null)
        return try {
            val key = deriveKey(passcode, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(verifier)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * PBKDF2 over the digits. The passcode never becomes a String on the way
     * in, for the same reason the recovery phrase never does: a String cannot
     * be wiped and lingers wherever the heap leaves it.
     */
    private fun deriveKey(passcode: CharArray, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(passcode, salt, PBKDF2_ITERATIONS, 256)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val bytes = factory.generateSecret(spec).encoded
            val key = SecretKeySpec(bytes, "AES")
            Secrets.wipe(bytes)
            return key
        } finally {
            spec.clearPassword()
        }
    }

    private fun deleteBioKey() {
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(BIO_KEY_ALIAS)
        } catch (e: Exception) {
            /* nothing to delete */
        }
    }

    private fun b64(b: ByteArray): String = android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)

    private fun unb64(s: String): ByteArray = android.util.Base64.decode(s, android.util.Base64.NO_WRAP)
}
