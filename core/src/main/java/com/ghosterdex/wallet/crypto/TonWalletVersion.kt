package com.ghosterdex.wallet.crypto

/**
 * TON wallet contract versions.
 *
 * The same private key produces a **completely different address** under each
 * version, because a TON address is the hash of the deployed state-init, code
 * cell included. So the version is not cosmetic: choose the wrong one on import
 * and the user's funds are perfectly safe at an address the app never looks at,
 * which is indistinguishable from "my money is gone".
 *
 * Verified for the same public key:
 * ```
 * v5R1  0:dcced75998cdf8dcb53977aa51b9e91b6cfdc7d5dfb41d7d22424a675fbb6dce
 * v4R2  0:40a42ae8d0aea047bb718e1d04a5b7c2af161b3c5225f56f874a46170e17a21c
 * v3R2  0:1f20f387f972de5891f9b385e88c979a69154bf2b89afb92a8702ed4035f48ab
 * ```
 *
 * [V5R1] is the ecosystem default: the W5 standard was finalised in July 2024
 * and Tonkeeper and the other major wallets create new accounts with it. A
 * wallet imported from Tonkeeper in the last two years is almost certainly V5R1,
 * which is why the app must derive more than one candidate and let the user
 * recognise their balance.
 *
 * The code cells, their hashes and their depths all come from `@ton/ton`
 * 16.3.0. The hash is the authority: [code] parses the bundled bag of cells and
 * refuses to return it unless it hashes to the pinned value, so the two can
 * never drift apart unnoticed. `TonVectorsTest` re-derives each address and
 * compares against that library, which would fail immediately if any constant
 * here were wrong.
 */
enum class TonWalletVersion(
    val id: String,
    internal val codeHash: String,
    internal val codeDepth: Int,
    private val codeBoc: String,
) {
    /** W5. The current default across the TON ecosystem. */
    V5R1(
        id = "v5r1",
        codeHash = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f",
        codeDepth = 6,
        codeBoc = "te6cckECFAEAAoEAART/APSkE/S88sgLAQIBIAINAgFIAwQC3NAg10nBIJFbj2Mg1wsfIIIQZXh0br0hghBz" +
            "aW50vbCSXwPgghBleHRuuo60gCDXIQHQdNch+kAw+kT4KPpEMFi9kVvg7UTQgQFB1yH0BYMH9A5voTGRMOGAQNch" +
            "cH/bPOAxINdJgQKAuZEw4HDiEA8CASAFDAIBIAYJAgFuBwgAGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AC" +
            "AUgKCwAXsyX7UTQcdch1wsfgABGyYvtRNDXCgCAAGb5fD2omhAgKDrkPoCwBAvIOAR4g1wsfghBzaWduuvLgin8P" +
            "AeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQ" +
            "B7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwh" +
            "jkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe7" +
            "8uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR" +
            "7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgk" +
            "ji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNC01sNe",
    ),

    /** The previous default; still holds a great deal of value. */
    V4R2(
        id = "v4r2",
        codeHash = "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0",
        codeDepth = 7,
        codeBoc = "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIPAgFIAwYC5tAB0NMDIXGwkl8E4CLXScEgkl8E4ALTHyGC" +
            "EHBsdWe9IoIQZHN0cr2wkl8F4AP6QDAg+kQByMoHy//J0O1E0IEBQNch9AQwXIEBCPQKb6Exs5JfB+AF0z/IJYIQ" +
            "cGx1Z7qSODDjDQOCEGRzdHK6kl8G4w0EBQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY" +
            "+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQ" +
            "BcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAHDgIBIAgNAgFYCQoAPbKd+1E0IEBQNch9AQwAsjKB8v/ydAB" +
            "gQEI9ApvoTGACASALDAAZrc52omhAIGuQ64X/wAAZrx32omhAEGuQ64WPwAARuMl+1E0NcLH4AFm9JCtvaiaECAo" +
            "GuQ+gIYRw1AgIR6STfSmRDOaQPp/5g3gSgBt4EBSJhxWfMYQE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//Q" +
            "E0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wD" +
            "oMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZ" +
            "QBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZ" +
            "QBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8" +
            "Syz/Jc/sAAAr0AMntVAj45Sg=",
    ),

    /** Older, but common in long-dormant wallets. No plugins dictionary. */
    V3R2(
        id = "v3r2",
        codeHash = "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599",
        codeDepth = 0,
        codeBoc = "te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gj" +
            "E7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0=",
    );

    companion object {
        /**
         * What a newly created wallet uses.
         *
         * Matching the ecosystem default matters beyond convention: someone
         * who later imports this phrase into Tonkeeper finds the same address
         * waiting rather than an empty one.
         *
         * Not for the fees, though, and an earlier version of this comment had
         * that wrong. Measured against `@ton/ton` 16.3.0, a single-transfer
         * external message is LARGER under W5 than under v4R2, 202 bytes
         * against 189, because the action list wrapper costs bytes and forward
         * fees scale with size. What W5 does win is a smaller code cell, 657
         * bytes against 740, so slightly less rent and code-load gas; and
         * batching, where the wrapper amortises away across up to 255 messages
         * under one signature, against v4R2's ceiling of 4. Neither helps the
         * one-message-per-transfer sends this app actually makes.
         *
         * The capability genuinely worth having is gasless. W5 accepts a
         * signed payload delivered inside an INTERNAL message, so a third
         * party can pay the fee, which would remove the "holds tokens, no coin
         * for gas" dead end. It is not wired up: [TonTransfer] speaks only the
         * signed-external opcode, and a relayer is needed as well as a
         * version.
         */
        val DEFAULT = V5R1

        /** Order to probe on import: most likely to hold funds first. */
        val PROBE_ORDER = listOf(V5R1, V4R2, V3R2)

        fun from(id: String?): TonWalletVersion =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: DEFAULT

        /** `698983191 + workchain`, shared by v3 and v4. */
        private const val SUBWALLET_ID = 698983191

        /**
         * v5R1 stores `networkGlobalId XOR context`, not a plain subwallet id.
         *
         * For mainnet defaults, networkGlobalId -239, workchain 0, version
         * v5r1, subwallet 0, the context is `1` followed by 31 zero bits
         * (-2147483648), giving `-239 xor -2147483648` = 2147483409 (0x7FFFFF11).
         */
        private const val V5R1_WALLET_ID = 2147483409
    }

    /**
     * The wallet id signed into every transfer, and stored in the data cell.
     *
     * It binds a signature to one wallet on one network, so a message signed
     * for this wallet cannot be replayed against a different subwallet or a
     * different chain.
     */
    internal val walletId: Long
        get() = when (this) {
            V5R1 -> V5R1_WALLET_ID.toLong()
            V4R2, V3R2 -> SUBWALLET_ID.toLong()
        }

    /**
     * Builds this version's data cell for [publicKey].
     *
     * The layouts genuinely differ, this is not one format with optional
     * fields:
     * ```
     * v3R2  seqno(32) walletId(32) pubkey(256)                        = 320 bits
     * v4R2  seqno(32) walletId(32) pubkey(256) plugins(1)             = 321 bits
     * v5R1  auth(1) seqno(32) walletId(32) pubkey(256) plugins(1)     = 322 bits
     * ```
     */
    fun data(publicKey: ByteArray): TonBoc.Cell {
        require(publicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        val b = TonBoc.Builder()
        return when (this) {
            V3R2 -> b
                .storeUint(0, 32)                     // seqno
                .storeUint(walletId, 32)
                .storeBytes(publicKey)
                .endCell()

            V4R2 -> b
                .storeUint(0, 32)                     // seqno
                .storeUint(walletId, 32)
                .storeBytes(publicKey)
                .storeBit(0)                          // empty plugins dictionary
                .endCell()

            // Everything after the leading auth bit is offset by one, so the
            // whole payload is bit-shifted rather than byte-aligned.
            V5R1 -> b
                .storeBit(1)                          // is_signature_auth_allowed
                .storeUint(0, 32)                     // seqno
                .storeUint(walletId, 32)
                .storeBytes(publicKey)
                .storeBit(0)                          // empty extensions dictionary
                .endCell()
        }
    }

    internal fun dataCell(publicKey: ByteArray): TonCell.Ref =
        data(publicKey).let { TonCell.Ref(it.hash, it.depth) }

    /**
     * This version's compiled contract.
     *
     * Parsed from the bundled bag of cells, then checked against [codeHash] ,
     * the constant that address derivation has always used and that the vector
     * tests pin. So a corrupted or mistyped BOC fails here, loudly, instead of
     * quietly relocating every wallet of this version to an address nobody
     * holds a key to.
     *
     * Needed for sending, not just for addresses: the first message a wallet
     * ever sends must carry the code that deploys it.
     */
    fun code(): TonBoc.Cell {
        codeCell?.let { return it }
        // The package's own base64, so this runs on the JVM the unit tests use as well as on the phone.
        val parsed = TonBoc.parse(TonBase64.decode(codeBoc))
        check(parsed.hashHex == codeHash) {
            "bundled $id code does not match its pinned hash"
        }
        check(parsed.depth == codeDepth) {
            "bundled $id code has depth ${parsed.depth}, expected $codeDepth"
        }
        codeCell = parsed
        return parsed
    }

    /**
     * `StateInit{ code, data }`, five bits and two references.
     *
     * `split_depth:0 special:0 code:1 data:1 library:0`. Hashing this is what
     * produces the address; sending it is what deploys the contract.
     */
    fun stateInit(publicKey: ByteArray): TonBoc.Cell = TonBoc.Builder()
        .storeBit(0)      // no split depth
        .storeBit(0)      // not special
        .storeBit(1)      // has code
        .storeBit(1)      // has data
        .storeBit(0)      // no library
        .storeRef(code())
        .storeRef(data(publicKey))
        .endCell()

    /** Parsed once per version; the check above runs on the first use only. */
    @Volatile
    private var codeCell: TonBoc.Cell? = null
}
