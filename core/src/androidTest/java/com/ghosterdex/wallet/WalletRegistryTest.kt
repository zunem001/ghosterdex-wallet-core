package com.ghosterdex.wallet

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The wallet registry. Where multi-wallet can lose someone's money quietly.
 *
 * **Never run this suite against a phone holding a real wallet.** [reset]
 * clears the vault and registry preferences before every test, and Gradle
 * uninstalls the app once the run finishes. Which takes the sealed phrase
 * with it. Both are correct for a test device and catastrophic on a real one.
 *
 * Two failures matter more than the rest, and both are silent:
 *
 *  - **an existing wallet not being adopted**, which would make a funded
 *    wallet vanish from the list after an app update
 *  - **a reused slot**, which would seal a new phrase under an old wallet's
 *    Keystore alias and corrupt both
 */
@RunWith(AndroidJUnit4::class)
class WalletRegistryTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun reset() {
        context.getSharedPreferences("ghosterdex.wallets", Context.MODE_PRIVATE)
            .edit().clear().commit()
        context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
            .edit().clear().commit()
        // Backup flags too, so a test never inherits another's proof state.
        context.getSharedPreferences("ghosterdex.meta", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun startsEmpty() {
        assertTrue(WalletRegistry.all(context).isEmpty())
        assertNull(WalletRegistry.active(context))
    }

    /** A fresh device's first wallet takes the legacy slot's storage keys. */
    @Test
    fun firstWalletUsesTheLegacySlot() {
        assertEquals(WalletRegistry.LEGACY_SLOT, WalletRegistry.reserveSlot(context))
    }

    /**
     * An install that predates multi-wallet must appear in the list.
     *
     * Detected from the vault's own blob, so it is correct regardless of how
     * the upgrade happened. Without this the user's funded wallet would simply
     * not be there.
     */
    @Test
    fun adoptsAPreExistingWallet() {
        context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
            .edit().putString("sealed_mnemonic", "not-a-real-blob").commit()

        val wallets = WalletRegistry.all(context)
        assertEquals(1, wallets.size)
        assertEquals(WalletRegistry.LEGACY_SLOT, wallets.first().slot)
        assertEquals(WalletRegistry.LEGACY_SLOT, WalletRegistry.activeSlot(context))
    }

    /**
     * Reading the registry before any wallet exists must not poison adoption.
     *
     * This is the bug the first live run found: an empty read persisted `[]`,
     * the adoption check keyed off the key's existence and never ran again, and
     * a wallet sealed moments later by the bridge's own onboarding stayed
     * invisible to the wallet manager forever.
     */
    @Test
    fun readingBeforeFirstWalletDoesNotPreventAdoption() {
        assertTrue(WalletRegistry.all(context).isEmpty())

        // The bridge's onboarding seals a phrase without telling the registry.
        context.getSharedPreferences("ghosterdex.vault", Context.MODE_PRIVATE)
            .edit().putString("sealed_mnemonic", "blob").commit()

        val wallets = WalletRegistry.all(context)
        assertEquals("wallet sealed after an early read must still appear", 1, wallets.size)
        assertEquals(WalletRegistry.LEGACY_SLOT, wallets.first().slot)
    }

    /** The belt-and-braces hook the bridge onboarding calls after sealing. */
    @Test
    fun ensureRegisteredIsIdempotentAndKeepsNames() {
        WalletRegistry.ensureRegistered(context, WalletRegistry.LEGACY_SLOT)
        assertEquals(1, WalletRegistry.all(context).size)

        WalletRegistry.rename(context, WalletRegistry.LEGACY_SLOT, "My savings")
        WalletRegistry.ensureRegistered(context, WalletRegistry.LEGACY_SLOT)

        assertEquals(1, WalletRegistry.all(context).size)
        assertEquals("My savings", WalletRegistry.all(context).first().name)
    }

    @Test
    fun commitAddsAndActivates() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "First")
        val second = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, second, "Second")

        assertEquals(2, WalletRegistry.all(context).size)
        assertEquals(second, WalletRegistry.activeSlot(context))
        assertEquals("Second", WalletRegistry.active(context)?.name)
    }

    /**
     * Slots must never be recycled.
     *
     * A reused id would point a new wallet at a Keystore alias that may still
     * exist, sealing its phrase under the removed wallet's key.
     */
    @Test
    fun slotsAreNeverReused() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "First")
        val second = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, second, "Second")

        WalletRegistry.remove(context, second)
        val third = WalletRegistry.reserveSlot(context)

        assertNotEquals("slot was recycled after removal", second, third)
    }

    @Test
    fun removingTheActiveWalletPromotesAnother() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "First")
        val second = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, second, "Second")
        assertEquals(second, WalletRegistry.activeSlot(context))

        WalletRegistry.remove(context, second)

        assertEquals(1, WalletRegistry.all(context).size)
        assertEquals(WalletRegistry.LEGACY_SLOT, WalletRegistry.activeSlot(context))
    }

    @Test
    fun removingTheLastWalletLeavesNoneActive() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "Only")
        WalletRegistry.remove(context, WalletRegistry.LEGACY_SLOT)

        assertTrue(WalletRegistry.all(context).isEmpty())
        assertNull(WalletRegistry.active(context))
    }

    @Test
    fun renameRejectsBlankNames() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "Named")
        assertFalse(WalletRegistry.rename(context, WalletRegistry.LEGACY_SLOT, "   "))
        assertEquals("Named", WalletRegistry.active(context)?.name)

        assertTrue(WalletRegistry.rename(context, WalletRegistry.LEGACY_SLOT, "  Renamed  "))
        assertEquals("Renamed", WalletRegistry.active(context)?.name)
    }

    @Test
    fun namesAreDefaultedAndOrdered() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT)
        val second = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, second)

        assertEquals(listOf("Wallet 1", "Wallet 2"), WalletRegistry.all(context).map { it.name })
    }

    /** Backup state belongs to a phrase, so it must not leak between wallets. */
    @Test
    fun backupStateIsPerWallet() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT, "First")
        val second = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, second, "Second")

        WalletMeta.clear(context, WalletRegistry.LEGACY_SLOT)
        WalletMeta.clear(context, second)
        WalletMeta.markBackedUp(context, WalletRegistry.LEGACY_SLOT)

        assertTrue(WalletMeta.isBackedUp(context, WalletRegistry.LEGACY_SLOT))
        assertFalse(
            "a new wallet must not inherit another's backup state",
            WalletMeta.isBackedUp(context, second),
        )

        WalletMeta.clear(context, WalletRegistry.LEGACY_SLOT)
    }

    /**
     * Restoring a wallet is the user proving they hold its phrase.
     *
     * Reported live 2026-07-26: a wallet restored from its recovery phrase
     * still read "not backed up", and the only thing that could clear that was
     * a three-word quiz. A weaker demonstration than the twenty-four words
     * they had just typed in. The warning was both wrong and unresolvable.
     */
    @Test
    fun importedWalletStartsBackedUp() {
        val slot = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, slot, "Restored")

        WalletMeta.recordOrigin(context, slot, created = false)

        assertTrue(
            "a wallet restored from its phrase is backed up by definition",
            WalletMeta.isBackedUp(context, slot),
        )
    }

    /** The other half: a generated phrase nobody has seen is not backed up. */
    @Test
    fun createdWalletStartsUnproven() {
        val slot = WalletRegistry.reserveSlot(context)
        WalletRegistry.commit(context, slot, "Fresh")
        // Whatever state the slot's storage was in beforehand must not survive.
        WalletMeta.markBackedUp(context, slot)

        WalletMeta.recordOrigin(context, slot, created = true)

        assertFalse(
            "a freshly generated phrase has never been seen by anyone",
            WalletMeta.isBackedUp(context, slot),
        )
    }

    @Test
    fun capIsEnforced() {
        WalletRegistry.commit(context, WalletRegistry.LEGACY_SLOT)
        repeat(WalletRegistry.MAX_WALLETS - 1) {
            WalletRegistry.commit(context, WalletRegistry.reserveSlot(context))
        }
        assertEquals(WalletRegistry.MAX_WALLETS, WalletRegistry.all(context).size)
        assertFalse(WalletRegistry.canAdd(context))
    }
}
