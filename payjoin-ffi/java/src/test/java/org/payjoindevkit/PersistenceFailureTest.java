package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Storage failures on a specific persister operation (save/load/close) must propagate through the
 * generated FFI boundary as a real, specifically-typed exception - not be swallowed, and not
 * surface only as the generic superclass. A focused Java port of Kotlin PR #1875's
 * {@code PersistenceCallbackTests.kt} (synchronous half only - see {@link AsyncPersistenceTest}
 * for the async equivalents), using {@link InMemoryPersisters.ControlledReceiverPersister} /
 * {@link InMemoryPersisters.ControlledSenderPersister} to fail exactly one named operation.
 * <p>
 * The exact exception type differs by call site, and that's the point being tested: the very
 * first {@code save()} on a freshly built transition throws {@link ForeignException} directly
 * (there is no protocol state yet to wrap it in), while every later transition wraps a storage
 * failure in the protocol-specific {@code ReceiverPersistedException}/{@code
 * SenderPersistedException}'s {@code Storage} variant, and a replay load failure surfaces as
 * {@code ReceiverReplayException}/{@code SenderReplayException}.
 */
class PersistenceFailureTest {
    @Test
    void receiverInitialSaveFailurePropagates() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.ControlledReceiverPersister persister =
                new InMemoryPersisters.ControlledReceiverPersister(InMemoryPersisters.Operation.SAVE);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                ForeignException.InternalException ex = assertThrows(ForeignException.InternalException.class,
                        () -> initial.save(persister));
                assertTrue(ex.v1().contains("storage save failed"), ex.v1());
            }
        }
    }

    @Test
    void receiverCloseFailurePropagatesAsPersistedException() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.ControlledReceiverPersister persister =
                new InMemoryPersisters.ControlledReceiverPersister(InMemoryPersisters.Operation.CLOSE);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                Initialized initialized = initial.save(persister);
                try (CancelTransition cancel = initialized.cancel()) {
                    // A never-interacted receiver has no fallback tx, so cancel.save() itself is
                    // the transition that closes the session (see CancelTest's class doc comment) -
                    // that's the call that needs the persister's closeSession() to succeed here,
                    // not a later PendingFallbackTransition as the sender's equivalent test needs.
                    ReceiverPersistedException.Storage ex = assertThrows(
                            ReceiverPersistedException.Storage.class, () -> cancel.save(persister));
                    assertTrue(ex.v1().toString().contains("storage close failed"), ex.v1().toString());
                }
            }
        }
        assertFalse(persister.isClosed(), "the failed close must not mark the persister closed");
    }

    @Test
    void receiverLoadFailurePropagatesOnReplay() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.ControlledReceiverPersister persister =
                new InMemoryPersisters.ControlledReceiverPersister(InMemoryPersisters.Operation.LOAD);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                initial.save(persister).close();
            }
        }
        ReceiverReplayException ex =
                assertThrows(ReceiverReplayException.class, () -> Payjoin.replayReceiverEventLog(persister));
        assertTrue(ex.toString().contains("storage load failed"), ex.toString());
    }

    @Test
    void senderInitialSaveFailurePropagates() throws Exception {
        InMemoryPersisters.ControlledSenderPersister persister =
                new InMemoryPersisters.ControlledSenderPersister(InMemoryPersisters.Operation.SAVE);
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                ForeignException.InternalException ex = assertThrows(ForeignException.InternalException.class,
                        () -> initial.save(persister));
                assertTrue(ex.v1().contains("storage save failed"), ex.v1());
            }
        }
    }

    @Test
    void senderCloseFailurePropagatesAsPersistedException() throws Exception {
        InMemoryPersisters.ControlledSenderPersister persister =
                new InMemoryPersisters.ControlledSenderPersister(InMemoryPersisters.Operation.CLOSE);
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                WithReplyKey withReplyKey = initial.save(persister);
                try (SenderCancelTransition cancel = withReplyKey.cancel()) {
                    SenderPendingFallback pending = cancel.save(persister);
                    try (BroadcastedTransition closeTransition = pending.closeSession()) {
                        SenderPersistedException.Storage ex = assertThrows(
                                SenderPersistedException.Storage.class, () -> closeTransition.save(persister));
                        assertTrue(ex.v1().toString().contains("storage close failed"), ex.v1().toString());
                    } finally {
                        pending.close();
                    }
                }
            }
        }
        assertFalse(persister.isClosed(), "the failed close must not mark the persister closed");
    }

    @Test
    void senderLoadFailurePropagatesOnReplay() throws Exception {
        InMemoryPersisters.ControlledSenderPersister persister =
                new InMemoryPersisters.ControlledSenderPersister(InMemoryPersisters.Operation.LOAD);
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                initial.save(persister).close();
            }
        }
        SenderReplayException ex =
                assertThrows(SenderReplayException.class, () -> Payjoin.replaySenderEventLog(persister));
        assertTrue(ex.toString().contains("storage load failed"), ex.toString());
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
