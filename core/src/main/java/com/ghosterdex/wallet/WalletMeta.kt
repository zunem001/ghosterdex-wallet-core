package com.ghosterdex.wallet

import android.content.Context

/**
 * Non-secret facts about each wallet on this device.
 *
 * Chiefly: has the user actually written down that wallet's recovery phrase?
 *
 * That flag is only trustworthy if it means "proved it", not "was shown it".
 * Everyone taps *I've written it down*; far fewer have. So being shown the
 * phrase never sets it. Exactly two things do, and both are the user producing
 * the phrase rather than reading it:
 *
 *  - [BackupVerifyDialog], after they reproduce words from it; and
 *  - importing a wallet, where they typed the entire phrase in from whatever
 *    they keep it on. That is the stronger of the two, so an imported wallet
 *    starts backed up.
 *
 * ## Per wallet, not per app
 *
 * Backup state belongs to a phrase, and every wallet has its own. A single
 * shared flag would mark a freshly added wallet as backed up because a
 * *different* one had been, and the whole point of the flag is that removing
 * a wallet can warn honestly about what is about to be destroyed.
 */
object WalletMeta {

    private const val PREFS = "ghosterdex.meta"
    private const val KEY_BACKED_UP = "backup_verified_at"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Slot [WalletRegistry.LEGACY_SLOT] keeps the unsuffixed key the
     * single-wallet build wrote, so an existing verified backup stays verified
     * across the upgrade rather than silently reverting to "not backed up".
     */
    private fun key(slot: String): String =
        if (slot == WalletRegistry.LEGACY_SLOT) KEY_BACKED_UP else "$KEY_BACKED_UP.$slot"

    /** True once the user has demonstrably reproduced part of that phrase. */
    fun isBackedUp(context: Context, slot: String = WalletRegistry.activeSlot(context)): Boolean =
        prefs(context).getLong(key(slot), 0L) > 0L

    fun markBackedUp(context: Context, slot: String = WalletRegistry.activeSlot(context)) {
        prefs(context).edit().putLong(key(slot), System.currentTimeMillis()).apply()
    }

    /**
     * Sets a newly sealed wallet's backup state from how it got here.
     *
     * A **created** wallet has a phrase nobody has ever seen, so it starts
     * unproven; the reveal-then-verify flow is what can change that.
     *
     * An **imported** one is the opposite case, and used to be handled as if it
     * were the same. The user just typed that phrase in from whatever they keep
     * it on, a stronger demonstration than the verify quiz, which asks for
     * three words chosen from a list shown seconds earlier. Calling that "not
     * backed up" told someone who had *just proved* they held the phrase that
     * they were about to lose it, and backing it up again could not clear the
     * warning, because the only thing that set the flag was a quiz they had
     * already outperformed.
     *
     * A warning that doing the right thing cannot resolve stops being read, and
     * that costs the warnings that do matter.
     */
    fun recordOrigin(context: Context, slot: String, created: Boolean) {
        if (created) clear(context, slot) else markBackedUp(context, slot)
    }

    /** Cleared with the wallet, a new wallet has a new, unproven phrase. */
    fun clear(context: Context, slot: String = WalletRegistry.activeSlot(context)) {
        prefs(context).edit().remove(key(slot)).apply()
    }
}
