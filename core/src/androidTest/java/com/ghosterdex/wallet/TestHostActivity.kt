package com.ghosterdex.wallet

import androidx.fragment.app.FragmentActivity

/**
 * A bare host for tests that need a real Activity.
 *
 * BiometricPrompt attaches to a FragmentActivity and cannot be driven without
 * one. In the shipped app that is MainActivity, which lives in the closed
 * shell; this library has no Activity of its own and should not grow one just
 * for production code that does not need it.
 *
 * So the test brings its own. It does nothing and shows nothing, which is
 * exactly the point: the round-trip under test is the Keystore's, and a host
 * with any behaviour of its own would only add somewhere for the test to lie.
 */
class TestHostActivity : FragmentActivity()
