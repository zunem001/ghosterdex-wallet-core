package com.ghosterdex.wallet.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * When "this phrase has no wallet yet" is a conclusion, and when it is a guess.
 *
 * Import is the one place the app decides which contract version a phrase
 * belongs to, and that decision is permanent: the version is stored with the
 * wallet and every later signature re-derives the address from it. Get it
 * wrong and nothing is lost on chain, but the app shows a real, correct, EMPTY
 * address and never looks at the funded one again. From the other side of the
 * screen that is indistinguishable from the money being gone.
 *
 * So the tests below are about one distinction: a candidate that answered
 * "nothing here" versus a candidate that did not answer at all. The second is
 * not evidence of anything, and the whole point of [WalletDiscovery.inconclusive]
 * is to stop it being treated as though it were.
 */
@RunWith(AndroidJUnit4::class)
class WalletDiscoveryTest {

    private fun active(id: String, nano: Long = 1_000_000_000L) =
        WalletDiscovery.Outcome.Active(id, "0:$id", nano, deployed = true)

    private fun empty(id: String) = WalletDiscovery.Outcome.Empty(id, "0:$id")

    private fun down(id: String) =
        WalletDiscovery.Outcome.Unavailable(id, "0:$id", "timeout")

    /** Every candidate answered, none had anything. This really is a new wallet. */
    @Test
    fun allAnsweredEmptyIsConclusive() {
        val outcomes = listOf(empty("v5r1"), empty("v4r2"), empty("v3r2"))
        assertFalse("all reached and all empty is a genuine new wallet",
            WalletDiscovery.inconclusive(outcomes))
    }

    /** One funded candidate is enough to adopt, even if the others went quiet. */
    @Test
    fun oneActiveIsConclusiveEvenWithStalls() {
        val outcomes = listOf(active("v4r2"), down("v5r1"), down("v3r2"))
        assertFalse("a funded candidate is a finding, whatever the others did",
            WalletDiscovery.inconclusive(outcomes))
        assertTrue(WalletDiscovery.unambiguousChoice(outcomes)?.id == "v4r2")
    }

    /** Nothing reachable at all. Obviously not a new wallet. */
    @Test
    fun nothingReachableIsInconclusive() {
        val outcomes = listOf(down("v5r1"), down("v4r2"), down("v3r2"))
        assertTrue(WalletDiscovery.inconclusive(outcomes))
        assertTrue(WalletDiscovery.allUnavailable(outcomes))
    }

    /**
     * The regression this whole guard exists for.
     *
     * One candidate answered "empty" and the rest timed out. [allUnavailable]
     * is FALSE here, so a caller guarding on it concludes "new wallet", adopts
     * the compiled-in default and seals it. If the phrase actually held a v4R2
     * wallet, the candidate that would have said so is one of the ones that
     * never answered.
     *
     * This is the case that must read as unknown, and the assertion pairs the
     * two functions deliberately: it fails the moment anyone swaps the guard
     * back to the weaker one.
     */
    @Test
    fun onePartialAnswerIsStillInconclusive() {
        val outcomes = listOf(empty("v5r1"), down("v4r2"), down("v3r2"))
        assertFalse("precondition: the weaker guard does not fire here",
            WalletDiscovery.allUnavailable(outcomes))
        assertTrue("a single empty answer is not evidence the others are empty",
            WalletDiscovery.inconclusive(outcomes))
    }

    /** Two funded candidates is a question for the user, not an unknown. */
    @Test
    fun severalActiveIsAmbiguousNotInconclusive() {
        val outcomes = listOf(active("v5r1", 5L), active("v4r2", 9L), down("v3r2"))
        assertFalse(WalletDiscovery.inconclusive(outcomes))
        assertTrue("two funded candidates must not be resolved silently",
            WalletDiscovery.unambiguousChoice(outcomes) == null)
    }

    /**
     * An empty probe list is not a licence to invent a wallet either.
     *
     * Unreachable today, since the import path always builds six candidates.
     * It is pinned because the two functions disagree here on purpose:
     * [WalletDiscovery.allUnavailable] answers "did every answer fail", which
     * is false when there were no answers, while [WalletDiscovery.inconclusive]
     * answers "may I call this a new wallet", which nothing supports.
     */
    @Test
    fun emptyOutcomesAreNotAConclusion() {
        assertFalse("nothing was asked, so allUnavailable stays false by contract",
            WalletDiscovery.allUnavailable(emptyList()))
        assertTrue("having asked nothing is not evidence of an unused phrase",
            WalletDiscovery.inconclusive(emptyList()))
    }
}
