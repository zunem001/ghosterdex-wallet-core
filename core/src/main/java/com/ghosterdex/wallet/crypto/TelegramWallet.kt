package com.ghosterdex.wallet.crypto

/**
 * The address Telegram's own wallet gives a key. Used by import discovery only.
 *
 * Telegram's wallet (WalletTg, the one Telegram Money creates) runs one
 * immutable trampoline whose real code the validators keep in config
 * parameter -123. Its address is the hash of that trampoline and a data cell
 * holding the wallet's first key, the anchor. Its recovery phrase is 12 BIP-39
 * words, derived at `m/44'/607'/0'`, which is [TonDerivation.BIP44]. After a
 * key change the phrase is 24 words, and the first 12 are still the anchor.
 *
 * This app cannot sign for that contract: its requests are not the v3, v4 or
 * v5 formats [TonTransfer] speaks. So the address is never a wallet here. It
 * answers one question at import: is this phrase a Telegram wallet in use? If
 * it is, the phrase's BIP-39 key is the key Telegram signs with (until a key
 * change) and the key its GhosterDex vault belongs to, so import takes that
 * key even though none of its own v3, v4 or v5 addresses holds anything. TON's
 * native scheme, the fallback for every other phrase, would give a key that no
 * other app derives from these words.
 *
 * Layout from ton-blockchain/docs, contracts/standard/wallets/telegram.
 * `TelegramWalletTest` pins the address against `@ton/core`.
 */
object TelegramWallet {

    /** The trampoline every Telegram wallet runs, whatever code it jumps to. */
    internal const val CODE_HASH = "9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768"

    private const val CODE_BOC = "te6cckEBAQEAGgAAMP8AIJgh10mDCLnyQN+Ahfgz0O0eIO1T2WlCfjk="

    /** The subwallet id of the wallets Telegram Money creates on mainnet. */
    private const val SUBWALLET_ID = 0x7FFF7F11L

    private const val WORKCHAIN = 0

    /**
     * Whether a phrase could be a Telegram wallet's, so import should ask.
     *
     * Telegram's phrases are BIP-39 and never TON's own (TON defines only 24
     * words, and a Telegram phrase is 12, or two 12-word halves). A phrase this
     * app created is valid under both schemes, so it is never asked about and
     * re-imports exactly as it always has. Asking costs one more address shown
     * to the same indexer the other candidates go to.
     */
    fun couldBe(check: RecoveryPhrase.Check): Boolean = check.bip39Valid && !check.tonValid

    /**
     * The first storage layout, the only one an address can commit to:
     * `revision(8) seqno(32) subwallet(32) anchor(256)`, revision and seqno 0.
     */
    fun data(anchor: ByteArray): TonBoc.Cell {
        require(anchor.size == 32) { "Ed25519 public key must be 32 bytes" }
        return TonBoc.Builder()
            .storeUint(0, 8)                      // storage revision 0
            .storeUint(0, 32)                     // seqno
            .storeUint(SUBWALLET_ID, 32)
            .storeBytes(anchor)
            .endCell()
    }

    /** Raw-form address, `0:<64 hex>`, of the Telegram wallet whose anchor is [anchor]. */
    fun addressRaw(anchor: ByteArray): String {
        val stateInit = TonBoc.Builder()
            .storeBit(0)      // no split depth
            .storeBit(0)      // not special
            .storeBit(1)      // has code
            .storeBit(1)      // has data
            .storeBit(0)      // no library
            .storeRef(code())
            .storeRef(data(anchor))
            .endCell()
        return "$WORKCHAIN:${stateInit.hashHex}"
    }

    /** Parsed once, and refused unless it hashes to [CODE_HASH]. */
    @Volatile
    private var codeCell: TonBoc.Cell? = null

    private fun code(): TonBoc.Cell {
        codeCell?.let { return it }
        val parsed = TonBoc.parse(TonBase64.decode(CODE_BOC))
        check(parsed.hashHex == CODE_HASH) { "bundled Telegram wallet code does not match its pinned hash" }
        codeCell = parsed
        return parsed
    }
}
