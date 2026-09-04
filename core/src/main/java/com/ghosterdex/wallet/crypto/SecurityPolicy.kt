package com.ghosterdex.wallet.crypto

/**
 * How a wallet's sealing key is gated, chosen by the user at creation.
 *
 * ## Why this is per wallet, not per app
 *
 * The policy is baked into the Keystore key at generation time, Android does
 * not allow changing a key's auth requirements afterwards, and every wallet
 * has its own key. Two wallets can therefore have different policies, which is
 * also the honest model: a daily-spend wallet and a savings wallet do not
 * deserve the same friction.
 *
 * ## What NONE actually means
 *
 * The phrase is still sealed under a hardware-backed AES key; the blob is
 * still worthless off-device. What disappears is the *authentication* gate:
 * anyone holding the unlocked phone can sign. The transaction confirmation
 * sheet remains, nothing signs invisibly, but it asks for a tap, not a
 * fingerprint. The choice screen says this in plain words before letting a
 * user pick it.
 */
enum class SecurityPolicy(val id: String) {
    /** STRONG biometric, fresh for every operation. The original policy. */
    BIOMETRIC("biometric"),

    /**
     * The device's own screen lock, PIN, pattern or password, with STRONG
     * biometrics also accepted. A superset on purpose: a user who chose "PIN"
     * and later enrols a fingerprint gets to use it without re-creating the
     * wallet.
     */
    CREDENTIAL("credential"),

    /** No authentication gate. Confirmation sheets only. */
    NONE("none"),
    ;

    companion object {
        /**
         * Legacy wallets default to [BIOMETRIC]: every wallet sealed before
         * this field existed was created under the biometric-only key spec,
         * and reporting anything else would promise an unlock path the key
         * will refuse.
         */
        fun from(id: String?): SecurityPolicy =
            entries.firstOrNull { it.id == id } ?: BIOMETRIC
    }
}
