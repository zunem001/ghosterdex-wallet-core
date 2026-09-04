package com.ghosterdex.wallet.crypto

import java.math.BigInteger

/**
 * Composing and signing the messages that move TON and jettons.
 *
 * A jetton transfer is three nested messages, which is worth holding in mind
 * because it explains every fee and every failure mode the user will ever ask
 * about:
 *
 * ```
 * external message        signed by the wallet key, addressed to the wallet
 *   internal message      wallet -> the sender's own jetton wallet, carries gas
 *     transfer body       op 0x0f8a7ea5: amount, recipient, change address
 * ```
 *
 * The user does not hold jettons directly. Each holder has a per-token contract,
 * their "jetton wallet", and a transfer is an instruction sent *to that
 * contract*, which then talks to the recipient's. So the TON attached to the
 * internal message is not the amount being sent; it is the fuel for that
 * conversation, and whatever is not burned comes back to `responseTo`.
 *
 * Layouts follow `@ton/core` 0.63.1 exactly, including its choices about
 * inlining and cell ordering, so the tests can compare byte for byte against
 * it. See [TonBoc] for why matching a published implementation is the point.
 */
object TonTransfer {

    /** TEP-74 `transfer`. */
    const val OP_JETTON_TRANSFER = 0x0f8a7ea5L

    /** A plain text comment, the convention every TON wallet displays. */
    const val OP_TEXT_COMMENT = 0L

    /** Take the fee from the wallet balance, not from the amount being sent. */
    const val MODE_PAY_GAS_SEPARATELY = 1

    /**
     * Ignore errors in this action rather than reverting the whole message.
     *
     * Wallet v5 *requires* this on externally signed actions and will reject a
     * message without it, so it is forced there rather than left to the caller.
     */
    const val MODE_IGNORE_ERRORS = 2

    /** What this app sends. Matches what Tonkeeper and the other major wallets use. */
    const val MODE_DEFAULT = MODE_PAY_GAS_SEPARATELY or MODE_IGNORE_ERRORS

    private const val OP_SEND_MSG = 0x0ec3c86dL
    private const val OP_V5_SIGNED_EXTERNAL = 0x7369676eL

    /**
     * A text comment cell.
     *
     * Text longer than one cell continues into a reference, the "snake"
     * convention. Without that, a long memo would overflow a cell and throw at
     * signing time, which is a poor way to learn that a note was too long.
     */
    fun comment(text: String): TonBoc.Cell {
        val bytes = text.toByteArray(Charsets.UTF_8)
        val head = TonBoc.Builder().storeUint(OP_TEXT_COMMENT, 32)
        return fill(head, bytes, 0)
    }

    private fun fill(builder: TonBoc.Builder, bytes: ByteArray, from: Int): TonBoc.Cell {
        val room = builder.bitsFree / 8
        val take = minOf(room, bytes.size - from)
        builder.storeBytes(bytes.copyOfRange(from, from + take))
        val next = from + take
        if (next < bytes.size) {
            builder.storeRef(fill(TonBoc.Builder(), bytes, next))
        }
        return builder.endCell()
    }

    /**
     * The body of a TEP-74 transfer.
     *
     * [responseTo] receives the unspent gas and the confirmation. Pointing it
     * anywhere but the sender donates the remainder to a stranger, so callers
     * should pass the sending wallet unless they have a specific reason.
     *
     * [forwardTon] is what the recipient's jetton wallet forwards on to the
     * recipient as a notification. Zero means no notification, which is cheaper
     * but leaves some services unaware the transfer happened; one nanoton is the
     * usual minimum that makes the notification fire.
     */
    fun jettonTransferBody(
        amount: BigInteger,
        to: TonAddress,
        responseTo: TonAddress,
        forwardTon: BigInteger = BigInteger.ZERO,
        forwardPayload: TonBoc.Cell? = null,
        customPayload: TonBoc.Cell? = null,
        queryId: Long = 0,
    ): TonBoc.Cell {
        require(amount.signum() > 0) { "A transfer must move a positive amount." }
        val b = TonBoc.Builder()
            .storeUint(OP_JETTON_TRANSFER, 32)
            .storeUint(queryId, 64)
            .storeCoins(amount)
            .storeAddress(to)
            .storeAddress(responseTo)
            .storeMaybeRef(customPayload)
            .storeCoins(forwardTon)
        // forward_payload is Either: one bit says inline or reference. Unlike a
        // Maybe, there is no "absent", an empty inline payload is the nothing.
        if (forwardPayload == null) b.storeBit(0) else b.storeBit(1).storeRef(forwardPayload)
        return b.endCell()
    }

    /**
     * An internal message: what the wallet emits, and what carries the gas.
     *
     * [bounce] should stay true when sending to a contract, so that a message
     * the contract cannot handle returns the money instead of burning it. It is
     * set false only for paying a plain wallet that may not exist yet.
     */
    fun internalMessage(
        to: TonAddress,
        value: BigInteger,
        body: TonBoc.Cell? = null,
        bounce: Boolean = true,
        stateInit: TonBoc.Cell? = null,
    ): TonBoc.Cell {
        val b = TonBoc.Builder()
            .storeBit(0)          // int_msg_info
            .storeBit(1)          // ihr_disabled: instant hypercube routing is unused
            .storeBit(bounce)
            .storeBit(0)          // not itself a bounce
            .storeAddressNone()   // src, filled in by the validator
            .storeAddress(to)
            .storeCoins(value)
            .storeBit(0)          // no extra currencies
            .storeCoins(BigInteger.ZERO) // ihr_fee
            .storeCoins(BigInteger.ZERO) // fwd_fee, set by the network
            .storeUint(0, 64)     // created_lt, set by the network
            .storeUint(0, 32)     // created_at, set by the network

        val payload = body ?: TonBoc.EMPTY
        if (stateInit == null) {
            b.storeBit(0)
        } else {
            b.storeBit(1)
            if (b.bitsFree - 2 >= stateInit.bits) b.storeBit(0).storeInline(stateInit)
            else b.storeBit(1).storeRef(stateInit)
        }
        inlineOrRef(b, payload)
        return b.endCell()
    }

    /**
     * The outermost envelope: unsigned by the network's reckoning, addressed to
     * the wallet itself, and carrying the signed body that authorises it.
     */
    fun externalMessage(
        to: TonAddress,
        body: TonBoc.Cell,
        stateInit: TonBoc.Cell? = null,
    ): TonBoc.Cell {
        val b = TonBoc.Builder()
            .storeUint(2, 2)      // ext_in_msg_info
            .storeAddressNone()   // src: nobody, which is what makes it external
            .storeAddress(to)
            .storeCoins(BigInteger.ZERO) // import_fee, paid from the account

        if (stateInit == null) {
            b.storeBit(0)
        } else {
            b.storeBit(1)
            // Upstream weighs init and body together here, unlike the internal
            // case, and does not count references. Mirrored rather than tidied:
            // a tidier rule would produce different bytes.
            if (b.bitsFree - 2 >= stateInit.bits + body.bits) b.storeBit(0).storeInline(stateInit)
            else b.storeBit(1).storeRef(stateInit)
        }
        inlineOrRef(b, body)
        return b.endCell()
    }

    private fun inlineOrRef(b: TonBoc.Builder, cell: TonBoc.Cell) {
        if (b.bitsFree - 1 >= cell.bits && b.refsUsed + cell.refCount <= 4) {
            b.storeBit(0).storeInline(cell)
        } else {
            b.storeBit(1).storeRef(cell)
        }
    }

    /**
     * Signs one outgoing message, producing the body of an external message.
     *
     * One message per transfer. The wallets can carry up to four, and v5 up to
     * 255, but nothing this app does needs a batch, and every extra slot is
     * another shape to get right on a path where being wrong costs money.
     *
     * The three versions are genuinely three formats. v5 puts the signature
     * *after* the payload and wraps the send in an action list; v4 and v3 put it
     * first and differ from each other by a single opcode byte.
     */
    fun signedBody(
        key: TonKey,
        seqno: Int,
        validUntil: Long,
        message: TonBoc.Cell,
        sendMode: Int = MODE_DEFAULT,
    ): TonBoc.Cell {
        require(seqno >= 0) { "seqno cannot be negative" }
        require(validUntil > 0) { "a transfer needs an expiry" }
        require(sendMode in 0..255) { "send mode out of range: $sendMode" }

        return when (key.version) {
            TonWalletVersion.V5R1 -> {
                val actions = TonBoc.Builder()
                    .storeRef(TonBoc.EMPTY)   // end of the action list, stored first
                    .storeUint(OP_SEND_MSG, 32)
                    .storeUint((sendMode or MODE_IGNORE_ERRORS).toLong(), 8)
                    .storeRef(message)
                    .endCell()

                val signing = TonBoc.Builder()
                    .storeUint(OP_V5_SIGNED_EXTERNAL, 32)
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                    .storeMaybeRef(actions)
                    .storeBit(0)              // no extension actions

                // The signature goes on the tail here, so the same builder is
                // reused rather than a new one being wrapped around it.
                signing.storeBytes(key.sign(signing.endCell().hash))
                signing.endCell()
            }

            TonWalletVersion.V4R2 -> {
                val signing = TonBoc.Builder()
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                    .storeUint(0, 8)          // op 0: an ordinary send, not a plugin
                    .storeUint(sendMode.toLong(), 8)
                    .storeRef(message)
                frontSigned(key, signing)
            }

            TonWalletVersion.V3R2 -> {
                val signing = TonBoc.Builder()
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                    .storeUint(sendMode.toLong(), 8)
                    .storeRef(message)
                frontSigned(key, signing)
            }
        }
    }

    private fun frontSigned(key: TonKey, signing: TonBoc.Builder): TonBoc.Cell =
        TonBoc.Builder()
            .storeBytes(key.sign(signing.endCell().hash))
            .storeBuilder(signing)
            .endCell()

    /**
     * The complete, broadcastable external message.
     *
     * A wallet at seqno 0 has never sent anything, which on TON means its
     * contract is not deployed yet, receiving money does not deploy it. So the
     * first message a wallet ever sends must carry its own code, or the network
     * has nothing to run and rejects it.
     */
    fun signedTransfer(
        key: TonKey,
        address: TonAddress,
        seqno: Int,
        validUntil: Long,
        message: TonBoc.Cell,
        sendMode: Int = MODE_DEFAULT,
    ): TonBoc.Cell = externalMessage(
        to = address,
        body = signedBody(key, seqno, validUntil, message, sendMode),
        stateInit = if (seqno == 0) key.version.stateInit(key.publicKeyBytes) else null,
    )

    /** One outgoing message with its own send mode, for a batch. */
    class Outgoing(val message: TonBoc.Cell, val sendMode: Int = MODE_DEFAULT)

    /**
     * Signs several outgoing messages into one external body.
     *
     * The one-message [signedBody] above stays as it is, because every byte
     * of it is pinned by the vectors. This is the same layout for more than
     * one: v5 builds its action list in order, each action's cell holding a
     * reference to the list before it, so the outermost cell is the LAST
     * message and the innermost the first, which is how `@ton/core` lays it
     * out; v4 and v3 store up to four (mode, reference) pairs in order. Four
     * is the ceiling everywhere: it is what TON Connect allows a dApp to
     * ask for, and what the older wallets can carry at all.
     */
    fun signedBodyMany(
        key: TonKey,
        seqno: Int,
        validUntil: Long,
        messages: List<Outgoing>,
    ): TonBoc.Cell {
        require(messages.isNotEmpty()) { "nothing to sign" }
        require(messages.size <= 4) { "a transfer carries at most four messages" }
        require(seqno >= 0) { "seqno cannot be negative" }
        require(validUntil > 0) { "a transfer needs an expiry" }
        for (m in messages) require(m.sendMode in 0..255) { "send mode out of range: ${m.sendMode}" }

        return when (key.version) {
            TonWalletVersion.V5R1 -> {
                var list = TonBoc.EMPTY
                for (m in messages) {
                    list = TonBoc.Builder()
                        .storeRef(list)
                        .storeUint(OP_SEND_MSG, 32)
                        .storeUint((m.sendMode or MODE_IGNORE_ERRORS).toLong(), 8)
                        .storeRef(m.message)
                        .endCell()
                }
                val signing = TonBoc.Builder()
                    .storeUint(OP_V5_SIGNED_EXTERNAL, 32)
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                    .storeMaybeRef(list)
                    .storeBit(0)
                signing.storeBytes(key.sign(signing.endCell().hash))
                signing.endCell()
            }

            TonWalletVersion.V4R2 -> {
                val signing = TonBoc.Builder()
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                    .storeUint(0, 8)
                for (m in messages) signing.storeUint(m.sendMode.toLong(), 8).storeRef(m.message)
                frontSigned(key, signing)
            }

            TonWalletVersion.V3R2 -> {
                val signing = TonBoc.Builder()
                    .storeUint(key.version.walletId, 32)
                    .storeUint(validUntil, 32)
                    .storeUint(seqno.toLong(), 32)
                for (m in messages) signing.storeUint(m.sendMode.toLong(), 8).storeRef(m.message)
                frontSigned(key, signing)
            }
        }
    }

    /** The complete, broadcastable external message for a batch. See [signedTransfer]. */
    fun signedTransferMany(
        key: TonKey,
        address: TonAddress,
        seqno: Int,
        validUntil: Long,
        messages: List<Outgoing>,
    ): TonBoc.Cell = externalMessage(
        to = address,
        body = signedBodyMany(key, seqno, validUntil, messages),
        stateInit = if (seqno == 0) key.version.stateInit(key.publicKeyBytes) else null,
    )
}
