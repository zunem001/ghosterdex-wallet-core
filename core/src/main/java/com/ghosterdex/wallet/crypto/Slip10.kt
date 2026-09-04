package com.ghosterdex.wallet.crypto

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.nio.charset.StandardCharsets

/**
 * SLIP-0010 hierarchical key derivation for Ed25519.
 *
 * Ed25519 supports **hardened derivation only**, there is no public parent to
 * public child step, because the curve's scalar clamping breaks the additive
 * relationship that makes non-hardened derivation work on secp256k1. Every
 * index here therefore has the hardened bit set, and a caller asking for a
 * non-hardened index is a bug, not a fallback.
 */
object Slip10 {

    private val ED25519_CURVE = "ed25519 seed".toByteArray(StandardCharsets.UTF_8)
    private const val HARDENED = 0x80000000.toInt()

    /**
     * NEAR's derivation path.
     *
     * This value is load-bearing for recovery-phrase portability. It matches
     * `near-seed-phrase`, which is what NEAR CLI and MyNearWallet use, so a
     * phrase generated here restores in those wallets and vice versa. Changing
     * it would strand every existing user's funds behind this app.
     *
     * (Note that Ledger uses m/44'/397'/0'/0'/1', a different path, and a
     * known source of "my phrase doesn't work" confusion across the ecosystem.)
     */
    val NEAR_PATH = intArrayOf(44 or HARDENED, 397 or HARDENED, 0 or HARDENED)

    /**
     * TON's BIP44 path, SLIP-0044 coin type 607.
     *
     * Used by Ledger, FoxWallet and others *instead of* TON's native
     * mnemonic scheme, producing an entirely different key from the same
     * phrase. See [TonDerivation].
     */
    val TON_PATH = intArrayOf(44 or HARDENED, 607 or HARDENED, 0 or HARDENED)

    /** A derived node. Caller owns both arrays and must wipe them. */
    class Node(val key: ByteArray, val chainCode: ByteArray) {
        fun wipe() {
            key.fill(0)
            chainCode.fill(0)
        }
    }

    /**
     * Derives along [path] from a BIP39 [seed].
     *
     * Every intermediate node is wiped as soon as its child exists, so only the
     * final node survives the call.
     */
    fun derive(seed: ByteArray, path: IntArray = NEAR_PATH): Node {
        var node = master(seed)
        for (index in path) {
            require(index and HARDENED != 0) {
                "Ed25519 supports hardened derivation only; index $index is not hardened"
            }
            val child = ckdPriv(node, index)
            node.wipe()
            node = child
        }
        return node
    }

    /** I = HMAC-SHA512("ed25519 seed", seed); left half is the key, right half the chain code. */
    private fun master(seed: ByteArray): Node {
        val i = hmacSha512(ED25519_CURVE, seed)
        val node = Node(i.copyOfRange(0, 32), i.copyOfRange(32, 64))
        i.fill(0)
        return node
    }

    /** I = HMAC-SHA512(chainCode, 0x00 || key || ser32(index)) */
    private fun ckdPriv(parent: Node, index: Int): Node {
        val data = ByteArray(1 + 32 + 4)
        data[0] = 0
        System.arraycopy(parent.key, 0, data, 1, 32)
        data[33] = (index ushr 24 and 0xFF).toByte()
        data[34] = (index ushr 16 and 0xFF).toByte()
        data[35] = (index ushr 8 and 0xFF).toByte()
        data[36] = (index and 0xFF).toByte()

        val i = hmacSha512(parent.chainCode, data)
        data.fill(0)

        val node = Node(i.copyOfRange(0, 32), i.copyOfRange(32, 64))
        i.fill(0)
        return node
    }

    private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA512Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }
}
