package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Basic input validation already exercised in the Kotlin/Python FFI suites. A focused Java port
 * of the Kotlin bindings' {@code ValidationTests.kt} (amount/fee-rate range checks, InputPair
 * outpoint/amount/script/weight validation) - not every case there, and none of this re-tests
 * BIP77 protocol behavior, which the integration test covers instead.
 * <p>
 * The InputPair tests below exist because of a Kotlin PR #1869 review finding (chavic): asserting
 * only the superclass {@code InputPairException} let a test pass for the wrong reason - a
 * too-long txid was meant to fail outpoint parsing ({@code InvalidOutPoint}), but with a
 * <em>valid</em> txid and no UTXO information the same superclass assertion still passed via a
 * completely different failure ({@code FfiValidation}). Asserting the exact nested variant is
 * required here specifically to catch that.
 */
class ValidationTest {
    // 21_000_000 BTC in sats, plus one - one past Bitcoin's maximum possible supply.
    private static final long TOO_LARGE_AMOUNT_SATS = 21_000_000L * 100_000_000L + 1L;
    private static final String VALID_TXID = "00".repeat(32);

    @Test
    void inputPairRejectsInvalidOutpoint() {
        // Too-long txid fails outpoint parsing before amount/UTXO checks - see the class doc
        // comment on why this asserts the exact nested variant, not just InputPairException.
        String tooLongTxid = "00".repeat(64);
        InputPairException.InvalidOutPoint ex = assertThrows(InputPairException.InvalidOutPoint.class,
                () -> new InputPair(
                        new TxIn(new OutPoint(tooLongTxid, 0), new byte[0], 0, List.of()),
                        new PsbtInput(new TxOut(TOO_LARGE_AMOUNT_SATS, new byte[] {0x51}), null, null),
                        null));
        assertEquals(tooLongTxid, ex.txid());
    }

    @Test
    void inputPairRejectsAmountOverflow() {
        InputPairException.FfiValidation ex = assertThrows(InputPairException.FfiValidation.class,
                () -> new InputPair(
                        new TxIn(new OutPoint(VALID_TXID, 0), new byte[0], 0, List.of()),
                        new PsbtInput(new TxOut(TOO_LARGE_AMOUNT_SATS, new byte[] {0x51}), null, null),
                        null));
        FfiValidationException.AmountOutOfRange detail =
                assertInstanceOf(FfiValidationException.AmountOutOfRange.class, ex.v1());
        assertEquals(TOO_LARGE_AMOUNT_SATS, detail.amountSat());
    }

    @Test
    void inputPairRejectsOversizedScript() {
        byte[] oversizedScript = new byte[10_001];
        java.util.Arrays.fill(oversizedScript, (byte) 0x51);
        InputPairException.FfiValidation ex = assertThrows(InputPairException.FfiValidation.class,
                () -> new InputPair(
                        new TxIn(new OutPoint(VALID_TXID, 0), new byte[0], 0, List.of()),
                        new PsbtInput(new TxOut(1L, oversizedScript), null, null),
                        null));
        FfiValidationException.ScriptTooLarge detail =
                assertInstanceOf(FfiValidationException.ScriptTooLarge.class, ex.v1());
        assertEquals(10_001L, detail.len());
        assertEquals(10_000L, detail.max());
    }

    @Test
    void inputPairRejectsWeightOutOfRange() {
        for (long weight : new long[] {0L, 4_000_001L}) {
            InputPairException.FfiValidation ex = assertThrows(InputPairException.FfiValidation.class,
                    () -> new InputPair(
                            new TxIn(new OutPoint(VALID_TXID, 0), new byte[0], 0, List.of()),
                            new PsbtInput(new TxOut(1L, new byte[] {0x6a}), null, null),
                            new Weight(weight)));
            FfiValidationException.WeightOutOfRange detail =
                    assertInstanceOf(FfiValidationException.WeightOutOfRange.class, ex.v1());
            assertEquals(weight, detail.weightUnits());
            assertEquals(4_000_000L, detail.maxWu());
        }
    }

    @Test
    void receiverBuilderRejectsBadAddress() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        assertThrows(ReceiverBuilderException.class,
                () -> new ReceiverBuilder("not-an-address", "https://example.com", ohttpKeys));
    }

    @Test
    void receiverBuilderRejectsAmountOverflow() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            assertThrows(FfiValidationException.AmountOutOfRange.class,
                    () -> builder.withAmount(TOO_LARGE_AMOUNT_SATS));
        }
    }

    @Test
    void senderBuilderWithAdditionalFeeRejectsAmountOverflow() throws Exception {
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            SenderInputException.FfiValidation ex = assertThrows(SenderInputException.FfiValidation.class,
                    () -> builder.buildWithAdditionalFee(TOO_LARGE_AMOUNT_SATS, null, 1_000L, false));
            assertInstanceOf(FfiValidationException.AmountOutOfRange.class, ex.v1());
        }
    }

    @Test
    void senderBuilderWithAdditionalFeeRejectsFeeRateOverflow() throws Exception {
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            SenderInputException.FfiValidation ex = assertThrows(SenderInputException.FfiValidation.class,
                    () -> builder.buildWithAdditionalFee(1L, null, Long.MAX_VALUE, false));
            assertInstanceOf(FfiValidationException.FeeRateOutOfRange.class, ex.v1());
        }
    }

    @Test
    void senderBuilderRecommendedRejectsFeeRateOverflow() throws Exception {
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            SenderInputException.FfiValidation ex = assertThrows(SenderInputException.FfiValidation.class,
                    () -> builder.buildRecommended(Long.MAX_VALUE));
            assertInstanceOf(FfiValidationException.FeeRateOutOfRange.class, ex.v1());
        }
    }

    @Test
    void senderBuilderNonIncentivizingRejectsFeeRateOverflow() throws Exception {
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            SenderInputException.FfiValidation ex = assertThrows(SenderInputException.FfiValidation.class,
                    () -> builder.buildNonIncentivizing(Long.MAX_VALUE));
            assertInstanceOf(FfiValidationException.FeeRateOutOfRange.class, ex.v1());
        }
    }

    @Test
    void pjUriRejectsAmountOverflow() throws Exception {
        try (PjUri uri = v2PjUri()) {
            assertThrows(FfiValidationException.AmountOutOfRange.class,
                    () -> uri.setAmountSats(TOO_LARGE_AMOUNT_SATS));
        }
    }

    @Test
    void senderBuilderRejectsBadPsbt() throws Exception {
        try (Uri parsed = Uri.parse("bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com/pj");
                PjUri uri = parsed.checkPjSupported()) {
            assertThrows(SenderInputException.class, () -> new SenderBuilder("not-a-psbt", uri));
        }
    }

    private static PjUri v2PjUri() throws Exception {
        InMemoryPersisters.InMemoryReceiverPersister persister = new InMemoryPersisters.InMemoryReceiverPersister();
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        try (ReceiverBuilder receiverBuilder = new ReceiverBuilder(
                "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = receiverBuilder.build()) {
                Initialized initialized = initial.save(persister);
                try {
                    return initialized.pjUri();
                } finally {
                    initialized.close();
                }
            }
        }
    }
}
