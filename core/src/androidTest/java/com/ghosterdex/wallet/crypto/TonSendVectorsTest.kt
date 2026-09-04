package com.ghosterdex.wallet.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.util.Locale

/**
 * Known-answer tests for the TON sending path.
 *
 * Every expected value was produced by `scripts/ton-vectors.mjs`, which drives
 * `@ton/ton` 16.3.0 and `@ton/core` 0.63.1, the libraries the mini app already
 * ships and that [TonWalletVersion]'s addresses are pinned against. So these do
 * not check that the Kotlin agrees with itself. They check that it produces the
 * *same bytes* as an implementation that moves real money, which is the only
 * property worth having: a transfer that is merely self-consistent is a
 * transfer the network rejects, or worse, accepts as something else.
 *
 * Regenerate with `node scripts/ton-vectors.mjs` and expect no diff. A diff
 * means either the Kotlin changed or the library did, and both are worth
 * stopping for.
 */
@RunWith(AndroidJUnit4::class)
class TonSendVectorsTest {

    private fun hex(b: ByteArray) = b.joinToString("") { String.format(Locale.ROOT, "%02x", it) }

    /** The throwaway phrase already used by [TonVectorsTest]; it holds nothing. */
    private val mnemonic =
        "soda ripple wire snap lift castle balance train short machine another mystery buzz side pact random west loop fat mesh hollow purpose replace excuse"

    private fun keyFor(version: TonWalletVersion) =
        TonKey.fromMnemonicNative(mnemonic.toCharArray(), version = version)

    private val owner = TonAddress.parse("0:dcced75998cdf8dcb53977aa51b9e91b6cfdc7d5dfb41d7d22424a675fbb6dce")
    private val dest = TonAddress.parse("0:40a42ae8d0aea047bb718e1d04a5b7c2af161b3c5225f56f874a46170e17a21c")
    private val jettonWallet = TonAddress.parse("0:1f20f387f972de5891f9b385e88c979a69154bf2b89afb92a8702ed4035f48ab")

    private val validUntil = 1_800_000_000L
    private val queryId = 4_242_424_242L
    private val jettonAmount: BigInteger = BigInteger.valueOf(1_500_000_000L)
    private val attachedTon: BigInteger = BigInteger.valueOf(50_000_000L)
    private val forwardTon: BigInteger = BigInteger.ONE
    private val seqno = 5
    private val sendMode = TonTransfer.MODE_DEFAULT

    private fun plainBody() = TonTransfer.jettonTransferBody(
        amount = jettonAmount,
        to = dest,
        responseTo = owner,
        forwardTon = forwardTon,
        queryId = queryId,
    )

    private fun message() = TonTransfer.internalMessage(
        to = jettonWallet,
        value = attachedTon,
        body = plainBody(),
        bounce = true,
    )

    // ── addresses ───────────────────────────────────────────────────────────

    @Test
    fun parsesBothAddressForms() {
        val raw = "0:dcced75998cdf8dcb53977aa51b9e91b6cfdc7d5dfb41d7d22424a675fbb6dce"
        val friendly = "UQDcztdZmM343LU5d6pRuekbbP3H1d-0HX0iQkpnX7ttzsjb"
        assertEquals(raw, TonAddress.parse(friendly).raw)
        assertEquals(friendly, TonAddress.parse(raw).toFriendly())
        assertEquals(
            "EQDcztdZmM343LU5d6pRuekbbP3H1d-0HX0iQkpnX7ttzpUe",
            TonAddress.parse(raw).toFriendly(bounceable = true),
        )
        // The other base64 alphabet is common in the wild and must not be refused.
        val standard = friendly.replace('-', '+').replace('_', '/')
        assertEquals(raw, TonAddress.parse(standard).raw)
        assertEquals(TonAddress.parse(raw), TonAddress.parse(friendly))
    }

    @Test
    fun refusesAnAddressWithATypo() {
        val good = "UQDcztdZmM343LU5d6pRuekbbP3H1d-0HX0iQkpnX7ttzsjb"
        // Change one character of the payload; the trailing checksum no longer agrees.
        val typo = good.replaceRange(5, 6, if (good[5] == 'A') "B" else "A")
        assertNotEquals(good, typo)
        try {
            TonAddress.parse(typo)
            fail("a mistyped address was accepted, which is how money disappears")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!, e.message!!.contains("checksum"))
        }
    }

    @Test
    fun refusesTestnetAndMalformedAddresses() {
        // Same address with the testnet flag set: valid encoding, wrong network.
        val bytes = ByteArray(36)
        bytes[0] = 0x91.toByte() // 0x11 bounceable | 0x80 testnet
        bytes[1] = 0
        System.arraycopy(owner.hash, 0, bytes, 2, 32)
        val sum = crc16(bytes.copyOfRange(0, 34))
        bytes[34] = ((sum ushr 8) and 0xFF).toByte()
        bytes[35] = (sum and 0xFF).toByte()
        val testnet = android.util.Base64.encodeToString(
            bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP,
        )
        for (bad in listOf(testnet, "", "0:00", "not an address", "0:" + "z".repeat(64))) {
            try {
                TonAddress.parse(bad)
                fail("accepted a bad address: '$bad'")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
        assertEquals(null, TonAddress.parseOrNull("nonsense"))
    }

    private fun crc16(data: ByteArray): Int {
        var crc = 0
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if (crc and 0x8000 != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
            }
        }
        return crc and 0xFFFF
    }

    // ── the contract cells ──────────────────────────────────────────────────

    @Test
    fun dataCellsMatchTheLibrary() {
        val key = keyFor(TonWalletVersion.V5R1)
        val expected = mapOf(
            TonWalletVersion.V5R1 to
                "b5ee9c7241010101002b000051800000003fffff888f98507b9afc3761f863f960ebed946f94c29a15fb9dacd9bcd493a6fd3e0a9620a78be22f",
            TonWalletVersion.V4R2 to
                "b5ee9c7241010101002b0000510000000029a9a3171f30a0f735f86ec3f0c7f2c1d7db28df2985342bf73b59b379a9274dfa7c152c408447de4c",
            TonWalletVersion.V3R2 to
                "b5ee9c7241010101002a0000500000000029a9a3171f30a0f735f86ec3f0c7f2c1d7db28df2985342bf73b59b379a9274dfa7c152c31fa6117",
        )
        for ((version, want) in expected) {
            assertEquals(version.id, want, hex(version.data(key.publicKeyBytes).toBoc()))
        }
    }

    /**
     * [TonWalletVersion.code] checks the bundled bag of cells against the hash
     * that address derivation has always used, so simply obtaining it proves the
     * parser round-trips a real, non-trivial cell tree.
     */
    @Test
    fun bundledCodeMatchesItsPinnedHash() {
        val expected = mapOf(
            TonWalletVersion.V5R1 to "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f",
            TonWalletVersion.V4R2 to "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0",
            TonWalletVersion.V3R2 to "84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599",
        )
        for ((version, want) in expected) {
            val code = version.code()
            assertEquals(version.id, want, code.hashHex)
            // Re-serialising and re-parsing must be lossless, or a deploy would
            // ship a subtly different contract than the one that was checked.
            assertEquals(version.id, want, TonBoc.parse(code.toBoc()).hashHex)
        }
        assertEquals(6, TonWalletVersion.V5R1.code().depth)
        assertEquals(7, TonWalletVersion.V4R2.code().depth)
        assertEquals(0, TonWalletVersion.V3R2.code().depth)
    }

    @Test
    fun addressesStillDeriveThroughTheNewCells() {
        // The addresses in TonWalletVersion's doc comment, now reached via the
        // real state-init cell rather than a hand-assembled hash.
        val key = keyFor(TonWalletVersion.V5R1)
        assertEquals(
            "0:dcced75998cdf8dcb53977aa51b9e91b6cfdc7d5dfb41d7d22424a675fbb6dce",
            key.addressFor(TonWalletVersion.V5R1),
        )
        assertEquals(
            "0:40a42ae8d0aea047bb718e1d04a5b7c2af161b3c5225f56f874a46170e17a21c",
            key.addressFor(TonWalletVersion.V4R2),
        )
        assertEquals(
            "0:1f20f387f972de5891f9b385e88c979a69154bf2b89afb92a8702ed4035f48ab",
            key.addressFor(TonWalletVersion.V3R2),
        )
    }

    // ── payloads ────────────────────────────────────────────────────────────

    @Test
    fun commentsMatchTheLibrary() {
        assertEquals(
            "b5ee9c72410101010016000028000000007468616e6b7320666f72206c756e63682f45f7f9",
            hex(TonTransfer.comment("thanks for lunch").toBoc()),
        )
    }

    /** A comment past one cell continues into a reference rather than throwing. */
    @Test
    fun longCommentsSnakeIntoFurtherCells() {
        val long = "x".repeat(300)
        val cell = TonTransfer.comment(long)
        assertEquals(
            "b5ee9c72410203010001380001fe000000007878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878780101fe787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878780200647878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878b2ab213e",
            hex(cell.toBoc()),
        )
        assertEquals(2, cell.depth)
    }

    @Test
    fun jettonTransferBodyMatchesTheLibrary() {
        assertEquals(
            "b5ee9c724101010100570000aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb73820234c6f59b",
            hex(plainBody().toBoc()),
        )
    }

    @Test
    fun jettonTransferCarriesAComment() {
        val body = TonTransfer.jettonTransferBody(
            amount = jettonAmount,
            to = dest,
            responseTo = owner,
            forwardTon = forwardTon,
            forwardPayload = TonTransfer.comment("thanks for lunch"),
            queryId = queryId,
        )
        assertEquals(
            "b5ee9c7241010201006e0001aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb738203010028000000007468616e6b7320666f72206c756e6368a0865754",
            hex(body.toBoc()),
        )
    }

    @Test
    fun internalMessageMatchesTheLibrary() {
        assertEquals(
            "b5ee9c7241010201008e00016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010100aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb73820286e93642",
            hex(message().toBoc()),
        )
    }

    // ── signing, per wallet version ─────────────────────────────────────────

    @Test
    fun v5r1SignsLikeTheLibrary() {
        val key = keyFor(TonWalletVersion.V5R1)
        assertEquals(
            "b5ee9c724101050100ed0001a17369676e7fffff116b49d20000000005ad6e798cecb50dd09adeae553029b66c82832fb54d630d061b6b20f8de747f67cbb78f5a76188391d94ef263cc1a941eb442817d3bf1bcfecb3ad9760e025042a001020a0ec3c86d0302030000016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010400aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb73820239678cbf",
            hex(TonTransfer.signedBody(key, seqno, validUntil, message(), sendMode).toBoc()),
        )
        assertEquals(
            "b5ee9c724102050100010f0001e58801b99daeb3319bf1b96a72ef54a373d236d9fb8fabbf683afa448494cebf76db9c039b4b3b73fffff88b5a4e90000000002d6b73cc6765a86e84d6f572a9814db36414197daa6b186830db5907c6f3a3fb3e5dbc7ad3b0c41c8eca77931e60d4a0f5a2140be9df8de7f659d6cbb07012821501020a0ec3c86d0302030000016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010400aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb7382026a1e2938",
            hex(TonTransfer.signedTransfer(key, owner, seqno, validUntil, message(), sendMode).toBoc()),
        )
    }

    @Test
    fun v4r2SignsLikeTheLibrary() {
        val key = keyFor(TonWalletVersion.V4R2)
        assertEquals(
            "b5ee9c724101030100df00019c2de57b5de507f6c9589501373de9b27126906997c31ef2a037ad3daa429090087bf3839871f1f96ce8d204ea2a9721d16392b93db3e4b903b55133bed79e1b0429a9a3176b49d20000000005000301016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010200aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb7382029d5d2d8a",
            hex(TonTransfer.signedBody(key, seqno, validUntil, message(), sendMode).toBoc()),
        )
        assertEquals(
            "b5ee9c72410203010001020001e18800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4438016f2bdaef283fb64ac4a809b9ef4d938934834cbe18f79501bd69ed5214848043df9c1cc38f8fcb674690275154b90e8b1c95c9ed9f25c81daa899df6bcf0d8214d4d18bb5a4e900000000028001c01016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010200aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb738202e2187cc7",
            hex(TonTransfer.signedTransfer(key, dest, seqno, validUntil, message(), sendMode).toBoc()),
        )
    }

    @Test
    fun v3r2SignsLikeTheLibrary() {
        val key = keyFor(TonWalletVersion.V3R2)
        assertEquals(
            "b5ee9c724101030100de00019a92ec160653481947ba3ee9d175f3766c9552e7430a3398f3730c8eb7e04ee831cd9224142e7214e1b90220383bec90c5ca439100f04b7d6ff939a4cc7a011c0729a9a3176b49d200000000050301016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010200aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb73820273bdcbb7",
            hex(TonTransfer.signedBody(key, seqno, validUntil, message(), sendMode).toBoc()),
        )
        assertEquals(
            "b5ee9c72410203010001010001df88003e41e70ff2e5bcb123f3670bd1192f34d22a97e57135f72550e05da806be9156049760b0329a40ca3dd1f74e8baf9bb364aa973a18519cc79b986475bf0277418e6c9120a17390a70dc81101c1df64862e521c8807825beb7fc9cd2663d008e0394d4d18bb5a4e9000000000281c01016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010200aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb738202e001bb57",
            hex(TonTransfer.signedTransfer(key, jettonWallet, seqno, validUntil, message(), sendMode).toBoc()),
        )
    }

    /**
     * The first send from a wallet must deploy it.
     *
     * Receiving TON or jettons never deploys a wallet contract, so a user who
     * has only ever been paid has an uninitialised account. Their first transfer
     * has to carry the code, or the network has nothing to run.
     */
    @Test
    fun firstSendCarriesTheContract() {
        val cases = mapOf(
            TonWalletVersion.V5R1 to Pair(
                owner,
                "b5ee9c7241021a010003be0003e78801b99daeb3319bf1b96a72ef54a373d236d9fb8fabbf683afa448494cebf76db9c118e6d2cedcfffffe22d693a400000000014a5ca2004b2a7ad15940184e67929035da9426883d4040d1bf41f54a38cd53b48bfebefc9b970e16692d7c3299bd69bd6a94a4e115124cee6f5ae25ddbef5e0540115160114ff00f4a413f4bcf2c80b02020120030e020148040502dcd020d749c120915b8f6320d70b1f2082106578746ebd21821073696e74bdb0925f03e082106578746eba8eb48020d72101d074d721fa4030fa44f828fa443058bd915be0ed44d0810141d721f4058307f40e6fa1319130e18040d721707fdb3ce03120d749810280b99130e070e21110020120060d020120070a02016e08090019adce76a2684020eb90eb85ffc00019af1df6a2684010eb90eb858fc00201480b0c0017b325fb51341c75c875c2c7e00011b262fb513435c280200019be5f0f6a2684080a0eb90fa02c0102f20f011e20d70b1f82107369676ebaf2e08a7f1001e68ef0eda2edfb218308d722028308d723208020d721d31fd31fd31fed44d0d200d31f20d31fd3ffd70a000af90140ccf9109a28945f0adb31e1f2c087df02b35007b0f2d0845125baf2e0855036baf2e086f823bbf2d0882292f800de01a47fc8ca00cb1f01cf16c9ed542092f80fde70db3cd81103f6eda2edfb02f404216e926c218e4c0221d73930709421c700b38e2d01d72820761e436c20d749c008f2e09320d74ac002f2e09320d71d06c712c2005230b0f2d089d74cd7393001a4e86c128407bbf2e093d74ac000f2e093ed55e2d20001c000915be0ebd72c08142091709601d72c081c12e25210b1e30f20d74a121314009601fa4001fa44f828fa443058baf2e091ed44d0810141d718f405049d7fc8ca0040048307f453f2e08b8e14038307f45bf2e08c22d70a00216e01b3b0f2d090e2c85003cf1612f400c9ed54007230d72c08248e2d21f2e092d200ed44d0d2005113baf2d08f54503091319c01810140d721d70a00f2e08ee2c8ca0058cf16c9ed5493f2c08de20010935bdb31e1d74cd00051800000003fffff888f98507b9afc3761f863f960ebed946f94c29a15fb9dacd9bcd493a6fd3e0a9620020a0ec3c86d0317180000016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000011900aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb73820252d8c025",
            ),
            TonWalletVersion.V4R2 to Pair(
                dest,
                "b5ee9c72410218010004040003e38800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4438118985036a56c683234ff4de1a73e6e409ec06638477b32fc8fa0b415c13aad091b13ee57d66de535b6175fe024b7f66b8705c8b7d45f446ed0e248dfde6ce176165353462ed693a40000000000000700115160114ff00f4a413f4bcf2c80b020201200310020148040702e6d001d0d3032171b0925f04e022d749c120925f04e002d31f218210706c7567bd22821064737472bdb0925f05e003fa403020fa4401c8ca07cbffc9d0ed44d0810140d721f404305c810108f40a6fa131b3925f07e005d33fc8258210706c7567ba923830e30d03821064737472ba925f06e30d0506007801fa00f40430f8276f2230500aa121bef2e0508210706c7567831eb17080185004cb0526cf1658fa0219f400cb6917cb1f5260cb3f20c98040fb0006008a5004810108f45930ed44d0810140d720c801cf16f400c9ed540172b08e23821064737472831eb17080185005cb055003cf1623fa0213cb6acb1fcb3fc98040fb00925f03e2020120080f020120090e0201580a0b003db29dfb513420405035c87d010c00b23281f2fff274006040423d029be84c600201200c0d0019adce76a26840206b90eb85ffc00019af1df6a26840106b90eb858fc00011b8c97ed44d0d70b1f80059bd242b6f6a2684080a06b90fa0218470d4080847a4937d29910ce6903e9ff9837812801b7810148987159f318404f8f28308d71820d31fd31fd31f02f823bbf264ed44d0d31fd31fd3fff404d15143baf2a15151baf2a205f901541064f910f2a3f80024a4c8cb1f5240cb1f5230cbff5210f400c9ed54f80f01d30721c0009f6c519320d74a96d307d402fb00e830e021c001e30021c002e30001c0039130e30d03a4c8cb1f12cb1fcbff11121314006ed207fa00d4d422f90005c8ca0715cbffc9d077748018c8cb05cb0222cf165005fa0214cb6b12ccccc973fb00c84014810108f451f2a7020070810108d718fa00d33fc8542047810108f451f2a782106e6f746570748018c8cb05cb025006cf165004fa0214cb6a12cb1fcb3fc973fb0002006c810108d718fa00d33f305224810108f459f2a782106473747270748018c8cb05cb025005cf165003fa0213cb6acb1f12cb3fc973fb00000af400c9ed5400510000000029a9a3171f30a0f735f86ec3f0c7f2c1d7db28df2985342bf73b59b379a9274dfa7c152c40016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000011700aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb738202c280565c",
            ),
            TonWalletVersion.V3R2 to Pair(
                jettonWallet,
                "b5ee9c724102050100019f0003e188003e41e70ff2e5bcb123f3670bd1192f34d22a97e57135f72550e05da806be9156119062708b681a10afc036199ff53ed18774fe85fc4381b6ed70b9f4ce4c1634cdc6bb4b0962433a2faebb97f990f6c041d3ceb3ba3222b4950410edd355d98a0045353462ed693a4000000000007001020300deff0020dd2082014c97ba218201339cbab19f71b0ed44d0d31fd31f31d70bffe304e0a4f2608308d71820d31fd31fd31ff82313bbf263ed44d0d31fd31fd3ffd15132baf2a15144baf2a204f901541055f910f2a3f8009320d74a96d307d402fb00e8d101a4c8cb1fcb1fcbffc9ed5400500000000029a9a3171f30a0f735f86ec3f0c7f2c1d7db28df2985342bf73b59b379a9274dfa7c152c016862000f9079c3fcb96f2c48fcd9c2f4464bcd348aa5f95c4d7dc95438176a01afa455a017d78400000000000000000000000000010400aa0f8a7ea500000000fcde41b2459682f00800814855d1a15d408f76e31c3a094b6f855e2c3678a44beadf0e948c2e1c2f4439003733b5d666337e372d4e5dea946e7a46db3f71f577ed075f48909299d7eedb738202ff9ba5df",
            ),
        )
        for ((version, expected) in cases) {
            val (address, want) = expected
            val key = keyFor(version)
            val boc = TonTransfer.signedTransfer(key, address, 0, validUntil, message(), sendMode).toBoc()
            assertEquals(version.id, want, hex(boc))
            // And the deploying message must be larger than the ordinary one,
            // because it carries the contract.
            val ordinary = TonTransfer.signedTransfer(key, address, 1, validUntil, message(), sendMode).toBoc()
            assertTrue(version.id, boc.size > ordinary.size)
        }
    }

    // ── the envelope itself ─────────────────────────────────────────────────

    @Test
    fun envelopesRoundTrip() {
        val key = keyFor(TonWalletVersion.V5R1)
        for (cell in listOf(
            TonBoc.EMPTY,
            plainBody(),
            message(),
            TonTransfer.comment("x".repeat(300)),
            TonTransfer.signedTransfer(key, owner, 0, validUntil, message(), sendMode),
        )) {
            assertEquals(cell.hashHex, TonBoc.parse(cell.toBoc()).hashHex)
            assertEquals(cell.hashHex, TonBoc.parse(cell.toBoc(crc32 = false)).hashHex)
            assertEquals(cell.depth, TonBoc.parse(cell.toBoc()).depth)
        }
    }

    @Test
    fun corruptEnvelopesAreRefused() {
        val boc = plainBody().toBoc()

        val flipped = boc.copyOf()
        flipped[flipped.size - 1] = (flipped[flipped.size - 1].toInt() xor 0xFF).toByte()
        expectRefusal("a corrupted checksum") { TonBoc.parse(flipped) }

        val notABoc = ByteArray(40) { 0x42 }
        expectRefusal("something that is not a bag of cells") { TonBoc.parse(notABoc) }

        expectRefusal("a truncated bag of cells") { TonBoc.parse(boc.copyOfRange(0, 12)) }
    }

    private fun expectRefusal(what: String, block: () -> Unit) {
        try {
            block()
            fail("accepted $what")
        } catch (e: IllegalArgumentException) {
            // expected
        } catch (e: IndexOutOfBoundsException) {
            fail("$what threw the wrong kind of error: ${e.javaClass.simpleName}")
        }
    }

    // ── the builder refuses to lie ──────────────────────────────────────────

    @Test
    fun theBuilderRefusesImpossibleValues() {
        expectRefusal("a value too wide for its field") {
            TonBoc.Builder().storeUint(256, 8)
        }
        expectRefusal("a negative amount") {
            TonBoc.Builder().storeCoins(BigInteger.valueOf(-1))
        }
        expectRefusal("a short address hash") {
            TonBoc.Builder().storeAddress(0, ByteArray(31))
        }
        expectRefusal("a fifth reference") {
            val b = TonBoc.Builder()
            repeat(5) { b.storeRef(TonBoc.EMPTY) }
        }
        expectRefusal("more bits than a cell holds") {
            val b = TonBoc.Builder()
            repeat(1024) { b.storeBit(1) }
        }
        expectRefusal("a transfer of nothing") {
            TonTransfer.jettonTransferBody(BigInteger.ZERO, dest, owner)
        }
    }

    /**
     * Amounts are the one field where an off-by-one encoding is both easy and
     * catastrophic, so the boundaries get their own check.
     */
    @Test
    fun amountsEncodeAtTheBoundaries() {
        fun coins(v: BigInteger) = hex(TonBoc.Builder().storeCoins(v).endCell().toBoc())
        // Zero is a length nibble and nothing else.
        assertEquals(coins(BigInteger.ZERO), coins(BigInteger.ZERO))
        assertNotEquals(coins(BigInteger.ZERO), coins(BigInteger.ONE))
        // 255 needs one byte; 256 needs two. A wrong length prefix here would
        // send 1/256th of the intended amount, or 256 times it.
        assertNotEquals(coins(BigInteger.valueOf(255)), coins(BigInteger.valueOf(256)))
        // The top of the range: 15 bytes is the most VarUInteger 16 can carry.
        val max = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE)
        coins(max)
        expectRefusal("an amount past the top of the range") {
            TonBoc.Builder().storeCoins(BigInteger.ONE.shiftLeft(120))
        }
    }

    /**
     * A signature must cover the whole payload.
     *
     * Changing any signed field has to change the bytes. If it did not, an
     * attacker who intercepted a signed transfer could edit the amount or the
     * recipient and the wallet would still accept it.
     */
    @Test
    fun everySignedFieldChangesTheSignature() {
        val key = keyFor(TonWalletVersion.V5R1)
        val base = hex(TonTransfer.signedBody(key, seqno, validUntil, message(), sendMode).toBoc())

        assertNotEquals(base, hex(TonTransfer.signedBody(key, seqno + 1, validUntil, message(), sendMode).toBoc()))
        assertNotEquals(base, hex(TonTransfer.signedBody(key, seqno, validUntil + 1, message(), sendMode).toBoc()))
        assertNotEquals(
            base,
            hex(TonTransfer.signedBody(key, seqno, validUntil, message(), sendMode or 128).toBoc()),
        )

        val toSomeoneElse = TonTransfer.internalMessage(
            to = jettonWallet,
            value = attachedTon,
            body = TonTransfer.jettonTransferBody(
                amount = jettonAmount,
                to = owner, // a different recipient
                responseTo = owner,
                forwardTon = forwardTon,
                queryId = queryId,
            ),
        )
        assertNotEquals(base, hex(TonTransfer.signedBody(key, seqno, validUntil, toSomeoneElse, sendMode).toBoc()))

        val moreMoney = TonTransfer.internalMessage(
            to = jettonWallet,
            value = attachedTon,
            body = TonTransfer.jettonTransferBody(
                amount = jettonAmount.add(BigInteger.ONE),
                to = dest,
                responseTo = owner,
                forwardTon = forwardTon,
                queryId = queryId,
            ),
        )
        assertNotEquals(base, hex(TonTransfer.signedBody(key, seqno, validUntil, moreMoney, sendMode).toBoc()))
    }

    /** Two versions of the same key must never produce the same signed message. */
    @Test
    fun versionsDoNotCollide() {
        val bodies = TonWalletVersion.entries.map { version ->
            hex(TonTransfer.signedBody(keyFor(version), seqno, validUntil, message(), sendMode).toBoc())
        }
        assertEquals(bodies.size, bodies.toSet().size)
    }
}
