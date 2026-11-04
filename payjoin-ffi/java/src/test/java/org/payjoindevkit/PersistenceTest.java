package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Session persistence: the synchronous persister API, replay of the event log, and
 * {@code closeSession} semantics. A focused Java port of the Kotlin bindings'
 * {@code PersistenceTests.kt} - the synchronous persister only (see README.md "Async /
 * callbacks" for why the async persister variant isn't separately covered here).
 */
class PersistenceTest {
    @Test
    void receiverPersistence() throws Exception {
        InMemoryPersisters.InMemoryReceiverPersister persister = new InMemoryPersisters.InMemoryReceiverPersister();
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        try (ReceiverBuilder receiverBuilder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = receiverBuilder.build()) {
                Initialized initialized = initial.save(persister);
                initialized.close();
            }
        }

        try (ReplayResult replay = Payjoin.replayReceiverEventLog(persister)) {
            assertInstanceOf(ReceiveSession.Initialized.class, replay.state());
        }
        assertFalse(persister.isClosed());
        persister.closeSession();
        assertTrue(persister.isClosed());
    }

    @Test
    void senderPersistenceReplaysToWithReplyKey() throws Exception {
        InMemoryPersisters.InMemoryReceiverPersister receiverPersister = new InMemoryPersisters.InMemoryReceiverPersister();
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        PjUri uri;
        try (ReceiverBuilder receiverBuilder = new ReceiverBuilder(
                "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = receiverBuilder.build()) {
                Initialized initialized = initial.save(receiverPersister);
                try {
                    uri = initialized.pjUri();
                } finally {
                    initialized.close();
                }
            }
        }

        InMemoryPersisters.InMemorySenderPersister senderPersister = new InMemoryPersisters.InMemorySenderPersister();
        try (uri; SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                WithReplyKey withReplyKey = initial.save(senderPersister);
                withReplyKey.close();
            }
        }

        try (SenderReplayResult replay = Payjoin.replaySenderEventLog(senderPersister)) {
            assertInstanceOf(SendSession.WithReplyKey.class, replay.state());
        }
        assertFalse(senderPersister.isClosed());
        senderPersister.closeSession();
        assertTrue(senderPersister.isClosed());
        receiverPersister.closeSession();
        assertTrue(receiverPersister.isClosed());
    }
}
