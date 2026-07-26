package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.Closeable
import java.util.Locale

/**
 * Signature schemes this wallet can produce.
 *
 * [ML_DSA_65] is declared but not yet implemented. It is present from the first
 * commit on purpose: NEAR shipped ML-DSA-65 (FIPS-204) to mainnet in the v2.13
 * upgrade, and carrying the scheme through the API now means adding
 * post-quantum keys later is additive rather than a refactor of every call site.
 */
enum class SignatureScheme(val id: String) {
    ED25519("ed25519"),
    ML_DSA_65("ml-dsa-65");

    companion object {
        fun from(id: String?): SignatureScheme =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) }
                ?: throw IllegalArgumentException("Unknown signature scheme: $id")
    }
}

/**
 * A live, in-memory signing key.
 *
 * Deliberately [Closeable]: the private scalar exists only between [fromSeed]
 * and [close], which should be a single signing operation. Always use it in a
 * `use { }` block so an exception cannot leave key material resident.
 *
 * This type never escapes Kotlin. The Capacitor bridge exposes verbs
 * ("sign this") and returns results. Never an instance of this class, and
 * never its bytes.
 */
class NearKey private constructor(
    private val params: Ed25519PrivateKeyParameters,
    private val privateScalar: ByteArray,
) : Closeable {

    /** Raw 32-byte Ed25519 public key. Safe to expose. */
    val publicKeyBytes: ByteArray = params.generatePublicKey().encoded

    /** NEAR's canonical public key form, e.g. `ed25519:6E8sCci9…`. */
    val publicKey: String get() = "${SignatureScheme.ED25519.id}:${Base58.encode(publicKeyBytes)}"

    /**
     * The NEAR implicit account id. The lowercase hex of the public key.
     *
     * Note that ML-DSA-65 keys have **no implicit-account form**, so a
     * post-quantum key can never be the account's origin; it has to be added to
     * an account that already exists. That asymmetry is why Ed25519 stays the
     * seed-derived root key here.
     */
    val implicitAccountId: String
        get() = publicKeyBytes.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    /** Detached Ed25519 signature over [message]. Returns 64 bytes. */
    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, params)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    override fun close() {
        privateScalar.fill(0)
    }

    companion object {
        /**
         * Derives the wallet key from a BIP39 seed.
         *
         * The caller still owns [seed] and must wipe it. This does not consume
         * it, because an import flow may need it for more than one derivation.
         */
        fun fromSeed(seed: ByteArray, path: IntArray = Slip10.NEAR_PATH): NearKey {
            val node = Slip10.derive(seed, path)
            return try {
                // Copy before the node is wiped; Ed25519PrivateKeyParameters
                // keeps its own internal copy, but we hold one to zero on close.
                val scalar = node.key.copyOf()
                NearKey(Ed25519PrivateKeyParameters(scalar, 0), scalar)
            } finally {
                node.wipe()
            }
        }
    }
}
