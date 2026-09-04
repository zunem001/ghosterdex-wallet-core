package com.ghosterdex.wallet.crypto

/**
 * The two ways a recovery phrase becomes a TON key.
 *
 * This is a sharper problem than [TonWalletVersion]. A wrong wallet version
 * gives the *same key* at a different address; a wrong derivation family gives
 * a **completely different key**, and therefore a different address, a
 * different public key, and no relationship whatsoever to the user's funds.
 *
 * Both are in real-world use:
 *
 * | Family | Used by |
 * |---|---|
 * | [NATIVE] | Tonkeeper, MyTonWallet, Telegram Wallet, TON's own scheme |
 * | [BIP44] | Ledger, FoxWallet, Tether WDK, SLIP-0044 coin type 607 |
 *
 * So a Ledger or FoxWallet user importing their phrase would, under native
 * derivation alone, get a valid key that has never held anything, and be told
 * their wallet is empty. Import therefore derives both families and probes
 * every address of each.
 *
 * The chosen family is stored with the wallet, exactly like the contract
 * version: it can never be re-guessed later without moving the user's address.
 */
enum class TonDerivation(val id: String) {

    /**
     * TON's own scheme: HMAC-SHA512 over the joined words, then
     * PBKDF2-HMAC-SHA512 with salt `"TON default seed"` at 100,000 iterations.
     * No BIP39 involvement at all.
     */
    NATIVE("native"),

    /**
     * BIP39 seed then SLIP-0010 hardened Ed25519 on `m/44'/607'/0'`.
     *
     * 607 is TON's SLIP-0044 registration. Note that path *depth* varies
     * between implementations, some append further levels, so a wallet that
     * still reports empty after both families are tried is most likely using a
     * deeper variant of this one.
     */
    BIP44("bip44");

    companion object {
        /** What a newly created wallet uses. */
        val DEFAULT = NATIVE

        /**
         * Order to try on import.
         *
         * Native first: it is what the TON-ecosystem wallets use, and it is the
         * only family a TON-only phrase can belong to.
         */
        val PROBE_ORDER = listOf(NATIVE, BIP44)

        fun from(id: String?): TonDerivation =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: DEFAULT
    }

    /**
     * Derives the 32-byte Ed25519 scalar for this family.
     *
     * Caller owns the result and must wipe it. Neither path validates the
     * phrase, both are total on arbitrary words, which is what makes probing
     * possible at all.
     */
    internal fun scalarFor(
        context: android.content.Context,
        mnemonic: CharArray,
        password: CharArray = CharArray(0),
    ): ByteArray = when (this) {
        NATIVE -> TonMnemonic.toPrivateKey(mnemonic, password)

        BIP44 -> {
            val seed = Bip39.toSeed(mnemonic, password)
            try {
                val node = Slip10.derive(seed, Slip10.TON_PATH)
                try {
                    node.key.copyOf()
                } finally {
                    node.wipe()
                }
            } finally {
                Secrets.wipe(seed)
            }
        }
    }
}
