package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * Produces TON Connect `ton_proof` signatures, the wallet-login proof.
 *
 * This is what `/api/tonproof/verify` checks to bind a session to a wallet, and
 * it is **not** the same envelope as [TonConnectSigner]. Two differences, both
 * of which produce a silently invalid signature if missed:
 *
 *  1. **Mixed endianness.** The workchain is big-endian, but the domain length
 *     and the timestamp are *little*-endian. sign-data uses big-endian
 *     throughout. The Worker's own source carries a note about this, which is
 *     a fair sign of how easy it is to get wrong.
 *  2. **Double hashing.** The signature covers
 *     `sha256(0xffff ++ "ton-connect" ++ sha256(message))`, not the message
 *     digest directly.
 *
 * Envelope:
 * ```
 * inner  = sha256( "ton-proof-item-v2/"
 *                  || int32BE(workchain) || addressHash[32]
 *                  || uint32LE(len(domain)) || domain
 *                  || uint64LE(timestamp)
 *                  || payload )
 * digest = sha256( 0xffff || "ton-connect" || inner )
 * ```
 */
object TonProofSigner {

    private const val PREFIX = "ton-proof-item-v2/"
    private const val CONNECT_TAG = "ton-connect"

    /** A `ton_proof` connect item reply, ready to hand back through the bridge. */
    data class Proof(
        val timestamp: Long,
        val domainLengthBytes: Int,
        val domainValue: String,
        val signatureBase64: String,
        val payload: String,
    )

    /**
     * Signs the login proof for [domain] over the server-issued [payload].
     *
     * [payload] comes from `/api/tonproof/challenge` and is what makes the
     * proof unreplayable; it must be passed through untouched.
     */
    fun sign(
        key: TonKey,
        domain: String,
        payload: String,
        timestamp: Long = System.currentTimeMillis() / 1000,
    ): Proof {
        val parts = key.addressRaw.split(":")
        require(parts.size == 2) { "Malformed address: ${key.addressRaw}" }
        val workchain = parts[0].toInt()
        val addressHash = hexToBytes(parts[1])

        val domainBytes = domain.toByteArray(StandardCharsets.UTF_8)

        val message = ByteArrayOutputStream().apply {
            write(PREFIX.toByteArray(StandardCharsets.UTF_8))
            write(be(workchain.toLong(), 4))     // big-endian
            write(addressHash)
            write(le(domainBytes.size.toLong(), 4)) // LITTLE-endian
            write(domainBytes)
            write(le(timestamp, 8))                 // LITTLE-endian
            write(payload.toByteArray(StandardCharsets.UTF_8))
        }.toByteArray()

        val inner = sha256(message)

        val full = ByteArrayOutputStream().apply {
            write(0xFF)
            write(0xFF)
            write(CONNECT_TAG.toByteArray(StandardCharsets.UTF_8))
            write(inner)
        }.toByteArray()

        val signature = key.sign(sha256(full))

        return Proof(
            timestamp = timestamp,
            domainLengthBytes = domainBytes.size,
            domainValue = domain,
            signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP),
            payload = payload,
        )
    }

    private fun be(value: Long, bytes: Int) = ByteArray(bytes) {
        ((value shr (8 * (bytes - 1 - it))) and 0xFF).toByte()
    }

    private fun le(value: Long, bytes: Int) = ByteArray(bytes) {
        ((value shr (8 * it)) and 0xFF).toByte()
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
