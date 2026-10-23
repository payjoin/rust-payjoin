package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Session cancellation, driven end to end through the real protocol transitions rather than by
 * calling the persister's {@code closeSession()} helper directly - a Kotlin PR #1869 review
 * finding (chavic): a test that only calls the persister helper proves the helper works, not that
 * Rust actually invokes it when a session is cancelled.
 * <p>
 * The receiver and sender paths are asymmetric here, confirmed at runtime rather than assumed: the
 * sender always already holds a signed original PSBT from the moment it's built, so
 * {@code cancel().save()} always hands back a real {@code SenderPendingFallback} with something
 * broadcastable, and closing goes through an explicit {@code closeSession()} transition. A receiver
 * that has never received the sender's original payload has nothing to fall back to, so for it
 * {@code cancel().save()} returns {@code null} and closes the session immediately, in the same call
 * - there is no intermediate pending-fallback object to close in that case. Both tests still assert
 * the persister is closed only by a real Rust-driven {@code save()} call, never a bare helper call.
 */
class CancelTest {
    @Test
    void receiverCancelClosesThroughProtocolTransition() throws Exception {
        InMemoryPersisters.InMemoryReceiverPersister persister = new InMemoryPersisters.InMemoryReceiverPersister();
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                Initialized initialized = initial.save(persister);
                try (CancelTransition cancel = initialized.cancel()) {
                    assertFalse(persister.isClosed(),
                            "reaching the cancel transition must not close the persister yet");
                    ReceiverPendingFallback pending = cancel.save(persister);
                    // See the class doc comment: a never-interacted receiver has no fallback tx,
                    // so this save() call is itself what closes the session.
                    assertNull(pending,
                            "a receiver that never received the sender's payload has no fallback");
                }
            }
        }

        assertTrue(persister.isClosed(), "the persister must be closed by the cancel() transition itself");
        try (ReplayResult replay = Payjoin.replayReceiverEventLog(persister)) {
            assertInstanceOf(ReceiveSession.Closed.class, replay.state());
        }
    }

    @Test
    void senderCancelClosesThroughProtocolTransition() throws Exception {
        InMemoryPersisters.InMemorySenderPersister persister = new InMemoryPersisters.InMemorySenderPersister();
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                WithReplyKey withReplyKey = initial.save(persister);
                try (SenderCancelTransition cancel = withReplyKey.cancel()) {
                    SenderPendingFallback pending = cancel.save(persister);
                    try {
                        assertFalse(persister.isClosed(),
                                "reaching the pending-fallback state must not close the persister yet");
                        assertTrue(pending.fallbackTx().length > 0,
                                "the sender's pending-fallback state carries a real, broadcastable fallback tx");

                        try (BroadcastedTransition closeTransition = pending.closeSession()) {
                            closeTransition.save(persister);
                        }
                    } finally {
                        pending.close();
                    }
                }
            }
        }

        assertTrue(persister.isClosed(),
                "the persister must be closed only after the closeSession() transition is saved");
        try (SenderReplayResult replay = Payjoin.replaySenderEventLog(persister)) {
            assertInstanceOf(SendSession.Closed.class, replay.state());
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
