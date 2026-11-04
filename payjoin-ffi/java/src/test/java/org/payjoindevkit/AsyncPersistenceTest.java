package org.payjoindevkit;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runtime coverage of the async ({@code CompletableFuture}) persister path - not exercised by
 * {@link PersistenceTest} or {@link CancelTest}, which only drive the synchronous persister API
 * (see README.md "Async / callbacks"). Every test here has an explicit timeout so a real generator
 * regression in the async plumbing fails the test instead of hanging CI.
 * <p>
 * {@link #receiverAsyncSaveStaysPendingUntilReleased} and {@link
 * #senderAsyncCloseStaysPendingUntilReleased} are the "callback stays pending" tests from Kotlin
 * PR #1875's {@code ControlledAsyncPersister.kt}/{@code gated()} helper, adapted to {@code
 * CompletableFuture} (Java has no {@code CompletableDeferred}/{@code supervisorScope}) - they
 * prove the returned future genuinely isn't complete until the Java-side persister future
 * resolves, i.e. the FFI layer isn't silently treating the async callback as fire-and-forget. One
 * save path and one close path is covered, split across receiver and sender rather than
 * duplicating both for both sides.
 */
class AsyncPersistenceTest {
    private static final long TIMEOUT_SECONDS = 10;

    @Test
    void receiverAsyncSaveAndReplayRoundTrip() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.InMemoryReceiverPersisterAsync persister = new InMemoryPersisters.InMemoryReceiverPersisterAsync();
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                Initialized initialized = initial.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                initialized.close();
            }
        }
        try (ReplayResult replay =
                Payjoin.replayReceiverEventLogAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            assertInstanceOf(ReceiveSession.Initialized.class, replay.state());
        }
    }

    @Test
    void senderAsyncSaveAndReplayRoundTrip() throws Exception {
        InMemoryPersisters.InMemorySenderPersisterAsync persister = new InMemoryPersisters.InMemorySenderPersisterAsync();
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                WithReplyKey withReplyKey = initial.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                withReplyKey.close();
            }
        }
        try (SenderReplayResult replay =
                Payjoin.replaySenderEventLogAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            assertInstanceOf(SendSession.WithReplyKey.class, replay.state());
        }
    }

    @Test
    void receiverAsyncCancelClosesThroughProtocolTransition() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.InMemoryReceiverPersisterAsync persister = new InMemoryPersisters.InMemoryReceiverPersisterAsync();
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                Initialized initialized = initial.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                try (CancelTransition cancel = initialized.cancel()) {
                    assertFalse(persister.isClosed());
                    ReceiverPendingFallback pending = cancel.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    // See CancelTest's class doc comment: a never-interacted receiver has no
                    // fallback tx, so this saveAsync() call is itself what closes the session.
                    assertNull(pending, "a receiver that never received the sender's payload has no fallback");
                }
            }
        }
        assertTrue(persister.isClosed(), "the persister must be closed by the cancel() transition itself");
        try (ReplayResult replay =
                Payjoin.replayReceiverEventLogAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            assertInstanceOf(ReceiveSession.Closed.class, replay.state());
        }
    }

    @Test
    void senderAsyncCancelClosesThroughProtocolTransition() throws Exception {
        InMemoryPersisters.InMemorySenderPersisterAsync persister = new InMemoryPersisters.InMemorySenderPersisterAsync();
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                WithReplyKey withReplyKey = initial.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                try (SenderCancelTransition cancel = withReplyKey.cancel()) {
                    SenderPendingFallback pending = cancel.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    try {
                        assertFalse(persister.isClosed());
                        try (BroadcastedTransition closeTransition = pending.closeSession()) {
                            closeTransition.saveAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                        }
                    } finally {
                        pending.close();
                    }
                }
            }
        }
        assertTrue(persister.isClosed());
        try (SenderReplayResult replay =
                Payjoin.replaySenderEventLogAsync(persister).get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            assertInstanceOf(SendSession.Closed.class, replay.state());
        }
    }

    @Test
    void receiverAsyncSaveAcceptsExplicitExecutor() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.InMemoryReceiverPersisterAsync persister = new InMemoryPersisters.InMemoryReceiverPersisterAsync();
        AtomicInteger executions = new AtomicInteger();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Executor countingExecutor = command -> {
                executions.incrementAndGet();
                executor.execute(command);
            };
            try (ReceiverBuilder builder = new ReceiverBuilder(
                    "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
                try (InitialReceiveTransition initial = builder.build()) {
                    Initialized initialized =
                            initial.saveAsync(persister, countingExecutor).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    initialized.close();
                }
            }
        } finally {
            executor.shutdown();
        }
        assertTrue(executions.get() > 0,
                "the Executor overload should be used somewhere in dispatching the async continuation");
    }

    @Test
    void receiverAsyncSaveStaysPendingUntilReleased() throws Exception {
        OhttpKeys ohttpKeys = OhttpKeys.decode(TestFixtures.OHTTP_KEYS_DATA);
        InMemoryPersisters.GatedReceiverPersisterAsync gate =
                new InMemoryPersisters.GatedReceiverPersisterAsync(InMemoryPersisters.Operation.SAVE);
        try (ReceiverBuilder builder = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)) {
            try (InitialReceiveTransition initial = builder.build()) {
                CompletableFuture<Initialized> future = initial.saveAsync(gate);
                gate.awaitEntered(TIMEOUT_SECONDS * 1000);
                assertFalse(future.isDone(), "save() must not complete before the persister's future does");

                gate.release();
                Initialized initialized = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                initialized.close();
            }
        }
    }

    @Test
    void senderAsyncCloseStaysPendingUntilReleased() throws Exception {
        InMemoryPersisters.InMemorySenderPersisterAsync setup = new InMemoryPersisters.InMemorySenderPersisterAsync();
        WithReplyKey withReplyKey;
        try (PjUri uri = v2PjUri(); SenderBuilder builder = new SenderBuilder(Payjoin.originalPsbt(), uri)) {
            try (InitialSendTransition initial = builder.buildRecommended(1_000L)) {
                withReplyKey = initial.saveAsync(setup).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
        }

        InMemoryPersisters.GatedSenderPersisterAsync closeGate =
                new InMemoryPersisters.GatedSenderPersisterAsync(InMemoryPersisters.Operation.CLOSE);
        try (SenderCancelTransition cancel = withReplyKey.cancel()) {
            SenderPendingFallback pending = cancel.saveAsync(setup).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            try (BroadcastedTransition closeTransition = pending.closeSession()) {
                try {
                    CompletableFuture<Void> future = closeTransition.saveAsync(closeGate);
                    closeGate.awaitEntered(TIMEOUT_SECONDS * 1000);
                    assertFalse(future.isDone(), "closeSession() must not complete before the persister's future does");
                    assertFalse(closeGate.isClosed());

                    closeGate.release();
                    future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                } finally {
                    pending.close();
                }
            }
        }
        assertTrue(closeGate.isClosed());
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
