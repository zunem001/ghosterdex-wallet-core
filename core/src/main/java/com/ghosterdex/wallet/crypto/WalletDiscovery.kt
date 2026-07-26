package com.ghosterdex.wallet.crypto

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Finds which of a key's candidate addresses actually holds anything.
 *
 * ## Why this exists
 *
 * One phrase yields one key, but that key has a different address under every
 * wallet contract version. See [TonWalletVersion]. Guessing wrong shows a
 * funded user an empty wallet, and the phrase-level checks cannot help: they
 * are typo detection with a 1-in-256 false-accept rate, so a phrase that passes
 * them can still be the wrong phrase.
 *
 * The only trustworthy signal is the chain. So import derives a candidate
 * **set**, asks which ones have history, and lets the user recognise their own
 * balance. Recognition, not assertion.
 *
 * ## Privacy cost. Read before enabling this anywhere else
 *
 * This is the app's **only** third-party network call. Everything else it does
 * goes to bundled assets or ghosterdex.com. Probing necessarily discloses the
 * candidate addresses to a public indexer, which can correlate them with the
 * requesting IP.
 *
 * That is a real cost for a wallet that sells confidentiality, and it is why
 * this runs **only during import**, only for addresses the user is in the act
 * of claiming, and never on a schedule or for the active wallet. It must not be
 * repurposed for balance display.
 *
 * ## Never conflate "empty" with "couldn't ask"
 *
 * A failed request rendered as "0.00" is the precise moment a user concludes
 * their money is gone. [Outcome.Unavailable] exists so the UI can say
 * "couldn't check" instead, and so a network blip can never be mistaken for an
 * empty wallet.
 */
object WalletDiscovery {

    /** Public TON indexer. Rate-limited without a key, which is fine for import. */
    private const val ENDPOINT = "https://toncenter.com/api/v2/getAddressInformation"

    /** GhosterDex's own catalogue. Not a third party. */
    private const val TOKENS_ENDPOINT = "https://ghosterdex.com/api/tokens"

    private const val TIMEOUT_MS = 6000

    /**
     * One address to check, tagged with an id the caller understands.
     *
     * Opaque on purpose: a candidate is now a *derivation family* and a
     * contract version, and this layer has no business knowing about either.
     */
    data class Candidate(val id: String, val address: String)

    sealed class Outcome {
        abstract val id: String
        abstract val address: String

        /** Deployed, or holding a balance. This is a wallet the user has used. */
        data class Active(
            override val id: String,
            override val address: String,
            /** In nanotons; 1 TON = 1_000_000_000. */
            val balanceNano: Long,
            val deployed: Boolean,
        ) : Outcome()

        /** Reached the chain; nothing there. A genuinely new wallet looks like this. */
        data class Empty(
            override val id: String,
            override val address: String,
        ) : Outcome()

        /** Could not ask. Explicitly NOT the same as empty. */
        data class Unavailable(
            override val id: String,
            override val address: String,
            val reason: String,
        ) : Outcome()
    }

    /**
     * Probes every candidate, in [TonWalletVersion.PROBE_ORDER].
     *
     * Sequential rather than parallel: three requests against a rate-limited
     * public endpoint, where being throttled would produce [Outcome.Unavailable]
     * and force the user to guess. Import can afford a couple of seconds.
     *
     * Never throws. A failure for one candidate is reported, not propagated,
     * so one bad response cannot hide the others.
     */
    fun probe(candidates: List<Candidate>): List<Outcome> =
        // Distinct by address: two families can coincide on a version, and
        // asking twice would waste a request against a rate-limited endpoint.
        candidates.distinctBy { it.address }.map { probeOne(it.id, it.address) }

    private fun probeOne(id: String, address: String): Outcome {
        var connection: HttpURLConnection? = null
        return try {
            val url = URL("$ENDPOINT?address=${java.net.URLEncoder.encode(address, "UTF-8")}")
            connection = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                requestMethod = "GET"
            }

            if (connection.responseCode != 200) {
                return Outcome.Unavailable(id, address, "HTTP ${connection.responseCode}")
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            if (!json.optBoolean("ok", false)) {
                return Outcome.Unavailable(id, address, "Indexer returned an error")
            }

            val result = json.optJSONObject("result")
                ?: return Outcome.Unavailable(id, address, "Malformed response")

            val balance = result.optString("balance", "0").toLongOrNull() ?: 0L
            // "uninitialized" means the contract was never deployed. It can
            // still hold a balance. Someone may have sent funds to an address
            // whose wallet has not been used yet. So balance is checked too.
            val deployed = result.optString("state", "uninitialized") == "active"

            if (deployed || balance > 0L) {
                Outcome.Active(id, address, balance, deployed)
            } else {
                Outcome.Empty(id, address)
            }
        } catch (e: Exception) {
            Outcome.Unavailable(id, address, e.message ?: e::class.java.simpleName)
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * The native-coin price in USD, from GhosterDex's own token catalogue.
     *
     * Deliberately sourced from `ghosterdex.com/api/tokens` rather than a price
     * oracle: it is a origin the app already talks to, so this adds no new
     * third-party dependency, and it is the same number the rest of the app
     * shows. A chooser quoting a different price to the portfolio would look
     * like a bug.
     *
     * The lookup mirrors the fallback chain the Worker itself uses, because the
     * catalogue's entry for the native coin has moved between listings.
     *
     * Returns null when unavailable. Callers must render that as "unknown",
     * never as zero.
     */
    fun nativeUsdPrice(): Double? {
        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(TOKENS_ENDPOINT).openConnection() as HttpURLConnection).apply {
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                requestMethod = "GET"
            }
            if (connection.responseCode != 200) return null

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val tokens = JSONObject(body).optJSONArray("tokens") ?: return null

            fun find(predicate: (JSONObject) -> Boolean): Double? {
                for (i in 0 until tokens.length()) {
                    val t = tokens.optJSONObject(i) ?: continue
                    if (predicate(t)) {
                        val price = t.optDouble("price", 0.0)
                        if (price > 0.0) return price
                    }
                }
                return null
            }

            find { it.optString("symbol") == "TON" && it.optString("blockchain") == "ton" }
                ?: find { it.optString("assetId") == "nep245:v2_1.omni.hot.tg:1117_" }
                ?: find { it.optString("symbol") == "GRAM" && it.optString("blockchain") == "ton" }
        } catch (e: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * The candidate to adopt, or null when the user must decide.
     *
     * Returns a version only when exactly one candidate is active. Anything
     * else is genuinely ambiguous and must go to the user rather than be
     * guessed. Two funded addresses from one phrase is unusual but entirely
     * possible for someone who has used the same phrase in two wallets.
     */
    fun unambiguousChoice(outcomes: List<Outcome>): Outcome.Active? =
        outcomes.filterIsInstance<Outcome.Active>().singleOrNull()

    /** True when nothing could be checked. The UI must not call this "empty". */
    fun allUnavailable(outcomes: List<Outcome>): Boolean =
        outcomes.isNotEmpty() && outcomes.all { it is Outcome.Unavailable }
}
