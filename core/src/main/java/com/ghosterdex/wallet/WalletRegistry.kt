package com.ghosterdex.wallet

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Which wallets exist on this device, and which one is in use.
 *
 * ## Slots, and why the first one is called "1"
 *
 * Each wallet occupies a *slot*, a short id that names its Keystore alias and
 * its sealed-blob key (see [com.ghosterdex.wallet.crypto.SecureVault]). Slot
 * [LEGACY_SLOT] deliberately maps to the exact alias and preference keys the
 * single-wallet build used, so an existing wallet is adopted where it already
 * lies rather than migrated. Nothing is re-encrypted, nothing is moved, and a
 * user with funds is never one failed rewrite away from losing their phrase.
 *
 * ## Slots are never reused
 *
 * [nextSlot] is a monotonic counter, not `size + 1`. Reusing the id of a
 * removed wallet would point a fresh wallet at a Keystore alias that may still
 * exist, and the new phrase would be sealed under the old wallet's key, which
 * decrypts to the wrong thing, or fails, depending on timing.
 *
 * ## Not secret
 *
 * Names, addresses and ordering are public facts. Only the phrase is sealed.
 */
object WalletRegistry {

    /** The slot the pre-multi-wallet build used. Its storage keys are unsuffixed. */
    const val LEGACY_SLOT = "1"

    private const val PREFS = "ghosterdex.wallets"
    private const val KEY_LIST = "wallets"
    private const val KEY_ACTIVE = "active_slot"
    private const val KEY_NEXT = "next_slot"

    /** Not a technical limit; this is about what a phone can sensibly hold. */
    const val MAX_WALLETS = 20

    data class Record(
        val slot: String,
        val name: String,
        val createdAt: Long,
        /**
         * How this wallet looks: `asset:<pack>/<file>.tgs` for a bundled
         * sticker, `file:<name>` for an image imported from the gallery, null
         * for the default ghost. A spec string rather than a path so the
         * gallery copies can live in filesDir and move with the app.
         */
        val avatar: String? = null,
    )

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Every wallet, in creation order.
     *
     * Adopts a pre-existing single wallet on first read, so callers never have
     * to know whether the upgrade has happened yet.
     */
    fun all(context: Context): List<Record> {
        adoptLegacyIfNeeded(context)
        return read(context)
    }

    fun active(context: Context): Record? {
        val wallets = all(context)
        if (wallets.isEmpty()) return null
        val slot = prefs(context).getString(KEY_ACTIVE, null)
        return wallets.firstOrNull { it.slot == slot } ?: wallets.first()
    }

    /**
     * The slot every unqualified vault operation applies to.
     *
     * Falls back to [LEGACY_SLOT] when nothing exists yet, so a first-run
     * create lands in the slot a legacy install would also have used.
     */
    fun activeSlot(context: Context): String = active(context)?.slot ?: LEGACY_SLOT

    fun setActive(context: Context, slot: String) {
        prefs(context).edit().putString(KEY_ACTIVE, slot).apply()
    }

    /**
     * Reserves a slot for a wallet that does not exist yet.
     *
     * Deliberately does **not** add it to the list: a slot is claimed before
     * the phrase is generated and sealed, and that can still fail or be
     * cancelled. [commit] is what makes it real.
     */
    fun reserveSlot(context: Context): String {
        val store = prefs(context)
        adoptLegacyIfNeeded(context)
        val existing = read(context)
        if (existing.isEmpty()) return LEGACY_SLOT

        val next = store.getInt(KEY_NEXT, existing.size + 1).coerceAtLeast(existing.size + 1)
        store.edit().putInt(KEY_NEXT, next + 1).apply()
        return next.toString()
    }

    /**
     * Records a wallet that has been successfully sealed, and activates it.
     *
     * Re-committing an existing slot keeps its name unless a new one is given,
     * restoring over a wallet must not silently rename it back to "Wallet 3".
     */
    fun commit(context: Context, slot: String, name: String? = null): Record {
        val all = read(context)
        val previous = all.firstOrNull { it.slot == slot }
        val others = all.filterNot { it.slot == slot }

        val record = Record(
            slot = slot,
            name = name?.trim()?.takeIf { it.isNotEmpty() }
                ?: previous?.name
                ?: defaultName(others),
            createdAt = previous?.createdAt ?: System.currentTimeMillis(),
            avatar = previous?.avatar,
        )
        write(context, others + record)
        setActive(context, slot)
        return record
    }

    /**
     * Registers [slot] if it is not already listed, leaving everything else be.
     *
     * The bridge's own onboarding (`ensureWallet`) seals a phrase without going
     * through the wallet manager, and a wallet that exists in the vault but not
     * in the registry is invisible, no way to switch to it, rename it or see
     * its backup state. This is the hook that keeps the two in step.
     */
    fun ensureRegistered(context: Context, slot: String) {
        if (read(context).any { it.slot == slot }) return
        commit(context, slot)
    }

    fun rename(context: Context, slot: String, name: String): Boolean {
        val cleaned = name.trim().take(40)
        if (cleaned.isEmpty()) return false
        val updated = read(context).map {
            if (it.slot == slot) it.copy(name = cleaned) else it
        }
        write(context, updated)
        return true
    }

    fun setAvatar(context: Context, slot: String, avatar: String?) {
        write(context, read(context).map {
            if (it.slot == slot) it.copy(avatar = avatar) else it
        })
    }

    /**
     * Forgets a wallet.
     *
     * Only the bookkeeping, the caller must also wipe the sealed phrase and
     * destroy the Keystore key, which is [SecureVault.clear]'s job. Splitting
     * them is deliberate: the vault wipe is the irreversible half and belongs
     * behind its own confirmation.
     */
    fun remove(context: Context, slot: String) {
        val remaining = read(context).filterNot { it.slot == slot }
        write(context, remaining)
        if (prefs(context).getString(KEY_ACTIVE, null) == slot) {
            // Promote the first survivor rather than leaving no active wallet:
            // a null active slot would send the web layer back to onboarding
            // while a perfectly good wallet sits in the list.
            val next = remaining.firstOrNull()
            if (next == null) prefs(context).edit().remove(KEY_ACTIVE).apply()
            else setActive(context, next.slot)
        }
    }

    fun canAdd(context: Context): Boolean = all(context).size < MAX_WALLETS

    // ── Storage ──────────────────────────────────────────────────────────────

    private fun defaultName(existing: List<Record>): String = "Wallet ${existing.size + 1}"

    private fun read(context: Context): List<Record> {
        val raw = prefs(context).getString(KEY_LIST, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { i ->
                val entry = array.optJSONObject(i) ?: return@mapNotNull null
                val slot = entry.optString("slot").takeIf { it.isNotEmpty() }
                    ?: return@mapNotNull null
                Record(
                    slot = slot,
                    name = entry.optString("name").ifEmpty { "Wallet" },
                    createdAt = entry.optLong("createdAt"),
                    avatar = entry.optString("avatar").takeIf { it.isNotEmpty() },
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun write(context: Context, wallets: List<Record>) {
        val array = JSONArray()
        wallets.forEach { record ->
            array.put(
                JSONObject()
                    .put("slot", record.slot)
                    .put("name", record.name)
                    .put("createdAt", record.createdAt)
                    .put("avatar", record.avatar),
            )
        }
        prefs(context).edit().putString(KEY_LIST, array.toString()).apply()
    }

    /**
     * Brings a pre-multi-wallet install into the registry.
     *
     * Detected from the vault's own storage rather than a migration flag, so it
     * is correct however the app was upgraded, and idempotent.
     */
    private fun adoptLegacyIfNeeded(context: Context) {
        if (prefs(context).contains(KEY_LIST)) return

        // Nothing to adopt, and, importantly, nothing is written. Persisting
        // an empty list here would set KEY_LIST on a device that has no wallet
        // yet, and this check would never run again: a wallet created moments
        // later by the bridge's own onboarding would then stay permanently
        // unlisted, invisible to the wallet manager.
        val hadWallet = context.applicationContext
            .getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
            .contains("sealed_mnemonic")
        if (!hadWallet) return

        write(context, listOf(Record(LEGACY_SLOT, "Wallet 1", System.currentTimeMillis())))
        setActive(context, LEGACY_SLOT)
        prefs(context).edit().putInt(KEY_NEXT, 2).apply()
    }
}
