package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * Produces TON Connect `signData` signatures over text.
 *
 * This is the exact authorisation GhosterDex's Worker checks. The wire format
 * must match `verifyWalletSig` byte for byte, any drift and the server returns
 * "Wallet signature is invalid", with no clue which field diverged.
 *
 * Preimage (all integers big-endian):
 * ```
 * 0xffff
 *   || "ton-connect/sign-data/"
 *   || int32(workchain) || addressHash[32]
 *   || uint32(len(domain)) || domain
 *   || uint64(timestamp)
 *   || "txt" || uint32(len(text)) || text
 * ```
 * The Ed25519 signature is over `sha256(preimage)`, the digest is the message
 * handed to Ed25519, not the preimage itself.
 */
object TonConnectSigner {

    private const val PREFIX = "ton-connect/sign-data/"
    private const val TEXT_TAG = "txt"

    /** A signature in the shape `/api/execute` expects as `walletSig`. */
    data class WalletSig(
        val signatureBase64: String,
        val address: String,
        val timestamp: Long,
        val domain: String,
        val text: String,
    )

    /**
     * Signs [text] for [domain].
     *
     * @param timestamp unix seconds. The Worker rejects anything more than 600s
     *   from its own clock, so this must be real device time, not a counter.
     */
    fun signText(
        key: TonKey,
        text: String,
        domain: String,
        timestamp: Long = System.currentTimeMillis() / 1000,
    ): WalletSig {
        val addressRaw = key.addressRaw
        val parts = addressRaw.split(":")
        require(parts.size == 2) { "Malformed address: $addressRaw" }
        val workchain = parts[0].toInt()
        val addressHash = hexToBytes(parts[1])

        val domainBytes = domain.toByteArray(StandardCharsets.UTF_8)
        val textBytes = text.toByteArray(StandardCharsets.UTF_8)

        val out = ByteArrayOutputStream()
        out.write(0xFF)
        out.write(0xFF)
        out.write(PREFIX.toByteArray(StandardCharsets.UTF_8))
        out.write(be(workchain.toLong(), 4))
        out.write(addressHash)
        out.write(be(domainBytes.size.toLong(), 4))
        out.write(domainBytes)
        out.write(be(timestamp, 8))
        out.write(TEXT_TAG.toByteArray(StandardCharsets.UTF_8))
        out.write(be(textBytes.size.toLong(), 4))
        out.write(textBytes)

        val preimage = out.toByteArray()
        val digest = sha256(preimage)
        val signature = key.sign(digest)

        return WalletSig(
            signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            address = addressRaw,
            timestamp = timestamp,
            domain = domain,
            text = text,
        )
    }

    /** Big-endian encoding of [value] into [bytes] bytes. */
    private fun be(value: Long, bytes: Int): ByteArray = ByteArray(bytes) {
        ((value shr (8 * (bytes - 1 - it))) and 0xFF).toByte()
    }

    private fun sha256(data: ByteArray): ByteArray {
        val d = SHA256Digest()
        d.update(data, 0, data.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    private fun hexToBytes(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
    }
}
