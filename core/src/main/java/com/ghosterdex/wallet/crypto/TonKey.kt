package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.Closeable
import java.util.Locale

/**
 * A TON wallet key, the key that actually authorises GhosterDex transactions.
 *
 * The Worker verifies every `/api/execute` against the bound TON wallet's
 * ed25519 public key, so this is the identity the whole flow hangs off. The
 * NEAR key in [NearKey] is a separate thing and does not sign these.
 *
 * The version this key derives under is chosen per wallet and stored with
 * it, never compiled in. A NEW wallet takes [TonWalletVersion.DEFAULT], which
 * is W5; an IMPORTED one takes whichever version the chain says already holds
 * funds, which [WalletDiscovery] establishes by probing every candidate.
 *
 * The same key lands at a different address under each version, so that
 * stored value is load-bearing for the life of the wallet: it cannot be
 * changed afterwards without moving the funds on chain to a new account.
 */
class TonKey private constructor(
    private val params: Ed25519PrivateKeyParameters,
    private val privateScalar: ByteArray,
    /** The contract version this key's address is computed under. */
    val version: TonWalletVersion,
    /** How this key was derived from the phrase. */
    val derivation: TonDerivation,
) : Closeable {

    /** Raw 32-byte Ed25519 public key, this is what the Worker stores as `boundWallet.publicKey`. */
    val publicKeyBytes: ByteArray = params.generatePublicKey().encoded

    val publicKeyHex: String
        get() = publicKeyBytes.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    /**
     * Raw-form address, `0:<64 hex>`, the form the Worker compares against.
     *
     * Uses [version], which is fixed when the key is constructed and stored
     * alongside the wallet. It must never be inferred from a compiled-in
     * default: a future release that changes the default would silently move
     * every existing user's address.
     */
    val addressRaw: String get() = addressFor(version)

    /** This key's address under an arbitrary contract version. */
    fun addressFor(target: TonWalletVersion): String =
        "$WORKCHAIN:${stateInitHash(target).joinToString("") { String.format(Locale.ROOT, "%02x", it) }}"

    /**
     * Every address this key could plausibly own, most likely first.
     *
     * Import must probe all of these: the same phrase in Tonkeeper (V5R1) and
     * in an older wallet (V4R2) yields entirely different addresses, and
     * checking only one shows a funded user an empty wallet.
     */
    fun candidateAddresses(): Map<TonWalletVersion, String> =
        TonWalletVersion.PROBE_ORDER.associateWith { addressFor(it) }

    /** Ed25519 signature over [message]. Returns 64 bytes. */
    fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, params)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    override fun close() {
        privateScalar.fill(0)
    }

    /**
     * `sha256(repr(StateInit{ code, data }))`.
     *
     * StateInit here is five bits, `split_depth:0`, `special:0`, `code:1`,
     * `data:1`, `library:0`, with the code and data cells as refs.
     */
    private fun stateInitHash(target: TonWalletVersion): ByteArray =
        target.stateInit(publicKeyBytes).hash

    companion object {
        private const val WORKCHAIN = 0

        /**
         * Derives the wallet key from a TON mnemonic.
         *
         * Uses [TonMnemonic], not [Bip39], TON's derivation is a different
         * algorithm despite sharing the same wordlist.
         *
         * [version] must come from stored wallet metadata for an existing
         * wallet. Letting it fall back to the default would change the address
         * of every wallet created before the default last moved.
         */
        fun fromMnemonic(
            context: android.content.Context,
            mnemonic: CharArray,
            password: CharArray = CharArray(0),
            version: TonWalletVersion = TonWalletVersion.DEFAULT,
            derivation: TonDerivation = TonDerivation.DEFAULT,
        ): TonKey {
            val scalar = derivation.scalarFor(context, mnemonic, password)
            return TonKey(Ed25519PrivateKeyParameters(scalar, 0), scalar, version, derivation)
        }

        /**
         * Native derivation without a Context.
         *
         * TON's own scheme needs no wordlist, so it can run where a Context is
         * awkward, tests, and the signing path. [TonDerivation.BIP44] cannot,
         * because BIP39 seed derivation is reached through [Bip39].
         */
        fun fromMnemonicNative(
            mnemonic: CharArray,
            password: CharArray = CharArray(0),
            version: TonWalletVersion = TonWalletVersion.DEFAULT,
        ): TonKey {
            val scalar = TonMnemonic.toPrivateKey(mnemonic, password)
            return TonKey(
                Ed25519PrivateKeyParameters(scalar, 0), scalar, version, TonDerivation.NATIVE,
            )
        }

        /** For tests and re-derivation from an already-computed scalar. */
        fun fromPrivateScalar(
            scalar: ByteArray,
            version: TonWalletVersion = TonWalletVersion.DEFAULT,
            derivation: TonDerivation = TonDerivation.DEFAULT,
        ): TonKey {
            require(scalar.size == 32) { "TON private scalar must be 32 bytes" }
            val copy = scalar.copyOf()
            return TonKey(Ed25519PrivateKeyParameters(copy, 0), copy, version, derivation)
        }
    }
}
