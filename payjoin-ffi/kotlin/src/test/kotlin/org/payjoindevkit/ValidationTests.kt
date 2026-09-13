package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class ValidationTests {
    @Test
    fun receiverBuilderRejectsBadAddress() {
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        assertFailsWith<ReceiverBuilderException> {
            ReceiverBuilder("not-an-address", "https://example.com", ohttpKeys)
        }
    }

    @Test
    fun inputPairRejectsInvalidOutpoint() {
        // Too-long txid fails outpoint parsing before amount / UTXO checks.
        val tooLongTxid = "00".repeat(64)
        assertFailsWith<InputPairException.InvalidOutPoint> {
            InputPair(
                TxIn(
                    previousOutput = OutPoint(txid = tooLongTxid, vout = 0u),
                    scriptSig = ByteArray(0),
                    sequence = 0u,
                    witness = emptyList(),
                ),
                dummyPsbtInput(TOO_LARGE_AMOUNT_SATS),
                null,
            )
        }
    }

    @Test
    fun inputPairRejectsAmountOverflow() {
        val ex = assertFailsWith<InputPairException.FfiValidation> {
            InputPair(
                TxIn(
                    previousOutput = OutPoint(txid = VALID_TXID, vout = 0u),
                    scriptSig = ByteArray(0),
                    sequence = 0u,
                    witness = emptyList(),
                ),
                dummyPsbtInput(TOO_LARGE_AMOUNT_SATS),
                null,
            )
        }
        assertIs<FfiValidationException.AmountOutOfRange>(ex.v1)
    }

    @Test
    fun receiverBuilderRejectsAmountOverflow() {
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            ohttpKeys,
        ).use { builder ->
            assertFailsWith<FfiValidationException.AmountOutOfRange> {
                builder.withAmount(TOO_LARGE_AMOUNT_SATS)
            }
        }
    }

    @Test
    fun senderBuilderWithAdditionalFeeRejectsAmountOverflow() {
        v2PjUri().use { uri ->
            SenderBuilder(originalPsbt(), uri).use { builder ->
                val ex = assertFailsWith<SenderInputException.FfiValidation> {
                    builder.buildWithAdditionalFee(TOO_LARGE_AMOUNT_SATS, null, 1000u, false)
                }
                assertIs<FfiValidationException.AmountOutOfRange>(ex.v1)
            }
        }
    }

    @Test
    fun senderBuilderWithAdditionalFeeRejectsFeeRateOverflow() {
        v2PjUri().use { uri ->
            SenderBuilder(originalPsbt(), uri).use { builder ->
                val ex = assertFailsWith<SenderInputException.FfiValidation> {
                    builder.buildWithAdditionalFee(1u, null, ULong.MAX_VALUE, false)
                }
                assertIs<FfiValidationException.FeeRateOutOfRange>(ex.v1)
            }
        }
    }

    @Test
    fun senderBuilderRecommendedRejectsFeeRateOverflow() {
        v2PjUri().use { uri ->
            SenderBuilder(originalPsbt(), uri).use { builder ->
                val ex = assertFailsWith<SenderInputException.FfiValidation> {
                    builder.buildRecommended(ULong.MAX_VALUE)
                }
                assertIs<FfiValidationException.FeeRateOutOfRange>(ex.v1)
            }
        }
    }

    @Test
    fun senderBuilderNonIncentivizingRejectsFeeRateOverflow() {
        v2PjUri().use { uri ->
            SenderBuilder(originalPsbt(), uri).use { builder ->
                val ex = assertFailsWith<SenderInputException.FfiValidation> {
                    builder.buildNonIncentivizing(ULong.MAX_VALUE)
                }
                assertIs<FfiValidationException.FeeRateOutOfRange>(ex.v1)
            }
        }
    }

    @Test
    fun pjUriRejectsAmountOverflow() {
        v2PjUri().use { uri ->
            assertFailsWith<FfiValidationException.AmountOutOfRange> {
                uri.setAmountSats(TOO_LARGE_AMOUNT_SATS)
            }
        }
    }

    @Test
    fun senderBuilderRejectsBadPsbt() {
        val uri = Uri.parse(
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com/pj",
        ).checkPjSupported()
        assertFailsWith<SenderInputException> {
            SenderBuilder("not-a-psbt", uri)
        }
    }
}

private const val VALID_TXID = "0000000000000000000000000000000000000000000000000000000000000000"
private val TOO_LARGE_AMOUNT_SATS = 21_000_000uL * 100_000_000uL + 1uL

private fun dummyPsbtInput(amountSat: ULong): PsbtInput =
    PsbtInput(
        witnessUtxo = TxOut(amountSat, byteArrayOf(0x6a)),
        redeemScript = null,
        witnessScript = null,
    )

private fun v2PjUri(): PjUri {
    val persister = InMemoryReceiverPersister()
    val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
    return ReceiverBuilder(
        "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
        "https://example.com",
        ohttpKeys,
    ).build().save(persister).pjUri()
}
