package com.ghosterdex.wallet.crypto

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import com.ghosterdex.wallet.WalletRegistry
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted-at-rest storage for the recovery phrase.
 *
 * The phrase is sealed under an AES-256-GCM key that lives in the Android
 * Keystore, hardware-backed, and in StrongBox on devices that have a secure
 * element. The key material itself is never readable by this process; we can
 * only ask the Keystore to perform operations with it.
 *
 * ## Why the phrase and not the derived key
 *
 * The stored secret is the 24-word TON recovery phrase, not the Ed25519 scalar.
 * That costs a PBKDF2 pass on every unlock, 100,000 rounds, since TON's
 * derivation is not BIP39's, and buys two things: the backup screen can show
 * the user their actual phrase, and new key types can be derived from the same
 * root later, which is what adding NEAR ML-DSA-65 will need, since that key has
 * to come from the same root to avoid a second thing to back up.
 *
 * ## Why the Keystore cannot just do the signing
 *
 * Android Keystore supports RSA, EC on NIST curves, AES and HMAC. It does not
 * support Ed25519 (nor ML-DSA). So chain signatures cannot be produced inside
 * the secure element; the seed must be decrypted into process memory and signed
 * there. The Keystore's job here is to make that decryption impossible without
 * a live biometric, and to keep the sealed blob worthless if the device is
 * rooted or the data partition is imaged.
 */
class SecureVault(
    context: Context,
    /**
     * Which wallet this instance opens.
     *
     * Defaults to the active one, so every existing call site keeps working
     * unchanged and "the wallet" continues to mean "the wallet in use".
     */
    private val slot: String = WalletRegistry.activeSlot(context),
) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Storage keys, suffixed per slot, except the first.
     *
     * Slot [WalletRegistry.LEGACY_SLOT] keeps the exact unsuffixed keys and
     * Keystore alias the single-wallet build wrote. An existing wallet is
     * therefore adopted in place: nothing is re-encrypted, nothing is copied,
     * and there is no migration step that can fail halfway and strand someone's
     * only phrase.
     */
    private fun key(base: String): String =
        if (slot == WalletRegistry.LEGACY_SLOT) base else "$base.$slot"

    /**
     * Which generation of this slot's Keystore key is in force.
     *
     * Android bakes a key's auth requirements in at generation and will not
     * change them, but the *vault* is not the key. Changing a wallet's lock
     * re-seals the same phrase under a **new** key, and this counter is what
     * makes that swap survivable: the new key is built at generation n+1 while
     * generation n keeps guarding the live blob, and a single preferences
     * commit moves the wallet across. Interrupt it anywhere before that commit
     * and the old key and old blob are still exactly where they were.
     *
     * Absent for every wallet sealed before re-keying existed, which is
     * generation 0, the unsuffixed alias those wallets already use.
     */
    private fun generation(): Int = prefs.getInt(key(KEY_KEY_GEN), 0)

    private fun aliasFor(gen: Int): String {
        val base = if (slot == WalletRegistry.LEGACY_SLOT) KEY_ALIAS else "$KEY_ALIAS.$slot"
        return if (gen == 0) base else "$base.g$gen"
    }

    private val keyAlias: String get() = aliasFor(generation())

    // ── Public surface ───────────────────────────────────────────────────────

    fun hasWallet(): Boolean = prefs.contains(key(KEY_BLOB)) && prefs.contains(key(KEY_IV))

    /**
     * Public identity, stored in the clear next to the sealed phrase.
     *
     * Public keys are not secrets, and gating them behind a biometric would
     * mean prompting the user just to render their own home screen. Only the
     * phrase is sealed.
     */
    fun publicIdentity(): Pair<String, String>? {
        val pk = prefs.getString(key(KEY_PUBKEY), null) ?: return null
        val acct = prefs.getString(key(KEY_ACCOUNT), null) ?: return null
        return pk to acct
    }

    /**
     * The contract version this wallet's address was derived under.
     *
     * Stored, never inferred. The address is a hash of the deployed code, so a
     * release that changed [TonWalletVersion.DEFAULT] would otherwise silently
     * relocate every existing wallet, the app would show a different, empty
     * address and the user's funds would appear to have vanished.
     *
     * Wallets created before this was recorded predate the V5R1 default and
     * were therefore V4R2; that is what the fallback encodes.
     */
    fun walletVersion(): TonWalletVersion =
        prefs.getString(key(KEY_VERSION), null)
            ?.let { TonWalletVersion.from(it) }
            ?: TonWalletVersion.V4R2

    /**
     * How this wallet's key was derived from its phrase.
     *
     * Stored for the same reason as [walletVersion], but the stakes are higher:
     * a wrong contract version gives the same key at another address, whereas a
     * wrong derivation family gives an entirely different key. Installs
     * predating this field used TON's native scheme.
     */
    fun walletDerivation(): TonDerivation =
        prefs.getString(key(KEY_DERIVATION), null)
            ?.let { TonDerivation.from(it) }
            ?: TonDerivation.NATIVE

    fun storePublicIdentity(
        publicKey: String,
        accountId: String,
        version: TonWalletVersion,
        derivation: TonDerivation = TonDerivation.NATIVE,
    ) {
        prefs.edit()
            .putString(key(KEY_PUBKEY), publicKey)
            .putString(key(KEY_ACCOUNT), accountId)
            .putString(key(KEY_VERSION), version.id)
            .putString(key(KEY_DERIVATION), derivation.id)
            .apply()
    }

    /**
     * How this wallet's key is gated. Absent for pre-policy wallets, which
     * were all biometric, see [SecurityPolicy.from].
     */
    fun securityPolicy(): SecurityPolicy =
        SecurityPolicy.from(prefs.getString(key(KEY_POLICY), null))

    /**
     * Records the policy the key was generated under.
     *
     * Descriptive, not prescriptive: the enforcement lives in the Keystore
     * key's own parameters, which cannot be altered after generation. This
     * field only lets the app know which prompt to show. Editing the
     * preference by hand changes nothing about what the key will accept.
     */
    fun storeSecurityPolicy(policy: SecurityPolicy) {
        prefs.edit().putString(key(KEY_POLICY), policy.id).apply()
    }

    /**
     * True when the vault key exists but the OS has invalidated it.
     *
     * Happens when biometric enrolment changes, a new fingerprint or face
     * added, or all of them removed. That invalidation is intentional (see
     * [setInvalidatedByBiometricEnrollment] below); the recovery phrase is the
     * way back, which is why the backup step is not optional.
     */
    fun isKeyInvalidated(): Boolean = try {
        decryptCipher()
        false
    } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
        true
    } catch (e: Exception) {
        false
    }

    /**
     * A Cipher ready to seal the phrase.
     *
     * Under [SecurityPolicy.BIOMETRIC] or [SecurityPolicy.CREDENTIAL] it must
     * be wrapped in a `BiometricPrompt.CryptoObject` and is unusable until the
     * prompt succeeds. Under [SecurityPolicy.NONE] it is usable immediately.
     *
     * [policy] matters only when this call is the one that generates the key ,
     * i.e. at wallet creation. An existing key keeps the parameters it was
     * born with, whatever is passed here.
     */
    fun encryptCipher(policy: SecurityPolicy = securityPolicy()): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, secretKey(policy))
        }

    /** As [encryptCipher], but for opening the vault; reads the stored IV. */
    fun decryptCipher(): Cipher {
        val iv = Base64.decode(
            prefs.getString(key(KEY_IV), null) ?: error("No wallet stored"),
            Base64.NO_WRAP,
        )
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        }
    }

    /**
     * Seals [mnemonicUtf8] with an already-authenticated [cipher].
     *
     * The caller owns [mnemonicUtf8] and must wipe it; this does not.
     */
    fun store(cipher: Cipher, mnemonicUtf8: ByteArray) {
        val sealed = cipher.doFinal(mnemonicUtf8)
        prefs.edit()
            .putString(key(KEY_BLOB), Base64.encodeToString(sealed, Base64.NO_WRAP))
            .putString(key(KEY_IV), Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .apply()
        sealed.fill(0)
    }

    /**
     * Opens the vault with an already-authenticated [cipher].
     *
     * Returns the mnemonic as UTF-8 bytes; the caller must wipe them.
     * A GCM tag mismatch throws, so a tampered blob fails loudly.
     */
    fun load(cipher: Cipher): ByteArray {
        val sealed = Base64.decode(
            prefs.getString(key(KEY_BLOB), null) ?: error("No wallet stored"),
            Base64.NO_WRAP,
        )
        return try {
            cipher.doFinal(sealed)
        } finally {
            sealed.fill(0)
        }
    }

    // ── Changing the lock ────────────────────────────────────────────────────
    //
    // A wallet's lock is not permanent, even though its key is. Re-keying
    // decrypts the phrase under the old policy and re-seals it under a brand
    // new key built to the new one. The wallet is untouched by this, same
    // phrase, same derivation, same address, only the wrapper changes.
    //
    // ## The ordering is the safety
    //
    //   1. unlock and hold the phrase          (old key still primary)
    //   2. build the new key at generation n+1 (old key still primary)
    //   3. seal the phrase with it             (old key still primary)
    //   4. ONE commit: generation, blob, iv, policy   ← the wallet moves here
    //   5. destroy the old key                 (nothing depends on it now)
    //
    // Every step before 4 is reversible by doing nothing, and step 4 is a
    // single atomic preferences write. A crash, a cancelled prompt, a killed
    // process, the wallet is either fully on the old key or fully on the new
    // one, never in between. Deleting the old key first would open a window
    // where a cancelled biometric prompt destroys the wallet outright.

    /** The generation a re-key will build into. Nothing is mutated. */
    fun nextGeneration(): Int = generation() + 1

    /**
     * An encrypt cipher for the *pending* key at [gen], creating that key
     * under [policy]. The live key is left completely alone.
     */
    fun rekeyCipher(gen: Int, policy: SecurityPolicy): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, secretKeyAt(gen, policy))
        }

    /**
     * Seals [mnemonicUtf8] with the authenticated [cipher] and moves the
     * wallet onto generation [gen] in one commit, then destroys the key it
     * left behind. Uses `commit()`, not `apply()`: the old key is deleted
     * immediately after, and that must never outrun the write that makes the
     * new one authoritative.
     */
    fun commitRekey(gen: Int, cipher: Cipher, mnemonicUtf8: ByteArray, policy: SecurityPolicy) {
        val previous = generation()
        val sealed = cipher.doFinal(mnemonicUtf8)
        try {
            val ok = prefs.edit()
                .putString(key(KEY_BLOB), Base64.encodeToString(sealed, Base64.NO_WRAP))
                .putString(key(KEY_IV), Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .putInt(key(KEY_KEY_GEN), gen)
                .putString(key(KEY_POLICY), policy.id)
                .commit()
            if (!ok) error("Could not save the re-keyed wallet")
        } finally {
            sealed.fill(0)
        }
        // Only now is nothing reachable through the old key.
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                .deleteEntry(aliasFor(previous))
        }
    }

    /** Drops a half-built pending key when the user backs out of a re-key. */
    fun abandonRekey(gen: Int) {
        if (gen == generation()) return // never the live one
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                .deleteEntry(aliasFor(gen))
        }
    }

    /** Removes the sealed phrase and destroys the Keystore key. */
    fun clear() {
        prefs.edit()
            .remove(key(KEY_BLOB)).remove(key(KEY_IV))
            .remove(key(KEY_PUBKEY)).remove(key(KEY_ACCOUNT))
            .remove(key(KEY_VERSION)).remove(key(KEY_DERIVATION))
            .remove(key(KEY_POLICY)).remove(key(KEY_KEY_GEN))
            .apply()
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        }
    }

    // ── Keystore key ─────────────────────────────────────────────────────────

    private fun secretKey(policy: SecurityPolicy = securityPolicy()): SecretKey =
        secretKeyAt(generation(), policy)

    private fun secretKeyAt(gen: Int, policy: SecurityPolicy): SecretKey {
        val alias = aliasFor(gen)
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        return generateKey(alias, policy)
    }

    private fun generateKey(alias: String, policy: SecurityPolicy): SecretKey {
        // StrongBox is a discrete secure element (Pixel 3+, recent Samsung).
        // Not every device has one, and asking for it where it is absent throws
        // rather than degrading, so fall back explicitly.
        return try {
            generateKey(alias, policy, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generateKey(alias, policy, strongBox = false)
        }
    }

    private fun generateKey(alias: String, policy: SecurityPolicy, strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        /* The key is unusable while the screen is locked - but ONLY for a
         * wallet that has no other lock.
         *
         * ## What this protects, and where it is redundant
         *
         * With [SecurityPolicy.NONE] this is the single thing standing between
         * the key and anything else running on the phone: no prompt gates it,
         * so without this flag the key is usable while the device sits locked
         * in someone else's hand.
         *
         * Under BIOMETRIC or CREDENTIAL it protects nothing that is not
         * already protected. Those keys demand fresh user authentication for
         * every single operation, driven from a CryptoObject prompt that only
         * a foreground app can raise - and an app is not foreground on a
         * locked phone. The device is necessarily unlocked before the key can
         * be touched at all.
         *
         * ## Why redundant is not free
         *
         * This flag is enforced by the TEE, and its "device is unlocked" state
         * is refreshed by the lock screen. On this project's Galaxy S10 - a
         * Keymaster 4 HAL wrapped by km_compat rather than a native KeyMint -
         * that state goes stale, and the key then refuses in ways that surface
         * as everything except the truth: onboarding shown to an owner who has
         * a wallet, and "User not authenticated" over a signature nobody was
         * ever asked to authorise.
         *
         * The tell was the owner's own remedy, found before the code knew why
         * it worked: lock the screen and unlock it, and it starts working. That
         * is exactly the event that refreshes this flag's state. Wallets that
         * do not bind their keys to the TEE this way never meet it.
         *
         * So it is kept where it is the only guard and dropped where a
         * per-operation prompt already says more. An existing key keeps the
         * parameters it was born with; this decides what NEW keys ask for.
         */
        if (policy == SecurityPolicy.NONE &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        ) {
            builder.setUnlockedDeviceRequired(true)
        }

        when (policy) {
            SecurityPolicy.BIOMETRIC -> {
                // Fresh authentication for every use. Not a session, not a
                // threshold, per operation.
                builder.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Timeout 0 forces the caller through a CryptoObject-bound
                    // BiometricPrompt. STRONG excludes convenience biometrics
                    // that miss Android's spoof thresholds.
                    builder.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG,
                    )
                } else {
                    // Pre-API 30 equivalent: -1 means per-operation auth.
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(-1)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    // Enrolling a new fingerprint invalidates this key. That is
                    // the point: someone holding an unlocked phone cannot add
                    // their own biometric and then drain the wallet. The cost
                    // is that legitimate re-enrolment forces a restore.
                    builder.setInvalidatedByBiometricEnrollment(true)
                }
            }

            SecurityPolicy.CREDENTIAL -> {
                builder.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Device credential cannot do per-operation (timeout 0)
                    // CryptoObject auth, the OS requires a validity window.
                    // Five seconds: enough to go from prompt to doFinal, short
                    // enough that the key is locked again before the user has
                    // put the phone down.
                    builder.setUserAuthenticationParameters(
                        CREDENTIAL_VALIDITY_SECONDS,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(
                        CREDENTIAL_VALIDITY_SECONDS,
                    )
                }
                // No setInvalidatedByBiometricEnrollment: this key is not
                // biometric-bound, and a user who chose PIN must not lose the
                // wallet because they enrolled a fingerprint later.
            }

            SecurityPolicy.NONE -> {
                // The user's explicit choice, made on a screen that states the
                // consequence. The key is still hardware-backed and the blob
                // still worthless off-device; only the auth gate is absent.
                builder.setUserAuthenticationRequired(false)
            }
        }

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "ghosterdex.vault.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val PREFS = "ghosterdex.vault"
        const val KEY_BLOB = "sealed_mnemonic"
        const val KEY_IV = "sealed_iv"
        const val KEY_PUBKEY = "public_key"
        const val KEY_ACCOUNT = "account_id"
        const val KEY_VERSION = "wallet_version"
        const val KEY_DERIVATION = "wallet_derivation"
        const val KEY_POLICY = "security_policy"
        const val KEY_KEY_GEN = "key_generation"

        /** See the CREDENTIAL branch of [generateKey]. */
        const val CREDENTIAL_VALIDITY_SECONDS = 5
    }
}
