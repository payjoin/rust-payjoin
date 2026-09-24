package org.payjoindevkit;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

/** Minimal in-memory persisters shared by the tests in this package. Mirrors Kotlin's {@code InMemoryPersisters.kt}. */
final class InMemoryPersisters {
    private InMemoryPersisters() {
    }

    /** Which persister operation a {@link ControlledReceiverPersister}/{@link ControlledSenderPersister}
     * or {@link GatedReceiverPersisterAsync}/{@link GatedSenderPersisterAsync} singles out. */
    enum Operation {
        SAVE, LOAD, CLOSE
    }

    private abstract static class MemoryEventLog {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private volatile boolean closed;

        // public: overrides a public interface method (JsonReceiverSessionPersister/JsonSenderSessionPersister)
        public void save(String event) {
            events.add(event);
        }

        public List<String> load() {
            return List.copyOf(events);
        }

        public void closeSession() {
            closed = true;
        }

        boolean isClosed() {
            return closed;
        }
    }

    static final class InMemoryReceiverPersister extends MemoryEventLog implements JsonReceiverSessionPersister {
    }

    static final class InMemorySenderPersister extends MemoryEventLog implements JsonSenderSessionPersister {
    }

    /**
     * A persister whose {@code save}/{@code load}/{@code closeSession} fails on exactly one named
     * operation, everything else behaving like a normal in-memory log. Mirrors Kotlin PR #1875's
     * {@code ControlledPersister.kt} - it proves a storage failure on a specific operation
     * propagates through the generated FFI boundary as a real {@link ForeignException} instead of
     * being swallowed. A standalone class (not a {@link MemoryEventLog} subclass): overriding
     * {@code save}/{@code load}/{@code closeSession} to add a checked {@code throws
     * ForeignException} is only legal if the method they override doesn't already forbid it, which
     * {@code MemoryEventLog}'s do.
     */
    static final class ControlledReceiverPersister implements JsonReceiverSessionPersister {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private final Operation failure;
        private volatile boolean closed;

        ControlledReceiverPersister(Operation failure) {
            this.failure = failure;
        }

        @Override
        public void save(String event) throws ForeignException {
            if (failure == Operation.SAVE) {
                throw new ForeignException.InternalException("storage save failed");
            }
            events.add(event);
        }

        @Override
        public List<String> load() throws ForeignException {
            if (failure == Operation.LOAD) {
                throw new ForeignException.InternalException("storage load failed");
            }
            return List.copyOf(events);
        }

        @Override
        public void closeSession() throws ForeignException {
            if (failure == Operation.CLOSE) {
                throw new ForeignException.InternalException("storage close failed");
            }
            closed = true;
        }

        boolean isClosed() {
            return closed;
        }
    }

    /** Sender-side counterpart of {@link ControlledReceiverPersister} - see that class for why it
     * doesn't extend {@link MemoryEventLog}. */
    static final class ControlledSenderPersister implements JsonSenderSessionPersister {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private final Operation failure;
        private volatile boolean closed;

        ControlledSenderPersister(Operation failure) {
            this.failure = failure;
        }

        @Override
        public void save(String event) throws ForeignException {
            if (failure == Operation.SAVE) {
                throw new ForeignException.InternalException("storage save failed");
            }
            events.add(event);
        }

        @Override
        public List<String> load() throws ForeignException {
            if (failure == Operation.LOAD) {
                throw new ForeignException.InternalException("storage load failed");
            }
            return List.copyOf(events);
        }

        @Override
        public void closeSession() throws ForeignException {
            if (failure == Operation.CLOSE) {
                throw new ForeignException.InternalException("storage close failed");
            }
            closed = true;
        }

        boolean isClosed() {
            return closed;
        }
    }

    /** A plain async in-memory persister - the {@code *Async} counterpart of
     * {@link InMemoryReceiverPersister}, every operation completing immediately. */
    static final class InMemoryReceiverPersisterAsync implements JsonReceiverSessionPersisterAsync {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private volatile boolean closed;

        @Override
        public CompletableFuture<Void> save(String event) {
            events.add(event);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<String>> load() {
            return CompletableFuture.completedFuture(List.copyOf(events));
        }

        @Override
        public CompletableFuture<Void> closeSession() {
            closed = true;
            return CompletableFuture.completedFuture(null);
        }

        boolean isClosed() {
            return closed;
        }
    }

    /** Sender-side counterpart of {@link InMemoryReceiverPersisterAsync}. */
    static final class InMemorySenderPersisterAsync implements JsonSenderSessionPersisterAsync {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private volatile boolean closed;

        @Override
        public CompletableFuture<Void> save(String event) {
            events.add(event);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<String>> load() {
            return CompletableFuture.completedFuture(List.copyOf(events));
        }

        @Override
        public CompletableFuture<Void> closeSession() {
            closed = true;
            return CompletableFuture.completedFuture(null);
        }

        boolean isClosed() {
            return closed;
        }
    }

    /**
     * An async persister whose one named operation doesn't complete until the test releases it -
     * proves the generated async path genuinely awaits the Java-side {@link CompletableFuture}
     * rather than treating callback dispatch as fire-and-forget. Mirrors Kotlin PR #1875's
     * {@code gated(operation, block)} helper in {@code ControlledPersister.kt}, adapted to
     * {@code CompletableFuture} since Java has no {@code CompletableDeferred}/{@code
     * supervisorScope}: {@link #awaitEntered} blocks (with a timeout) until the gated operation has
     * actually been invoked, and {@link #release} lets it finish.
     */
    static final class GatedReceiverPersisterAsync implements JsonReceiverSessionPersisterAsync {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private final Operation gated;
        private final CompletableFuture<Void> entered = new CompletableFuture<>();
        private final CompletableFuture<Void> gate = new CompletableFuture<>();
        private volatile boolean closed;

        GatedReceiverPersisterAsync(Operation gated) {
            this.gated = gated;
        }

        void awaitEntered(long timeoutMillis) throws Exception {
            entered.get(timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
        }

        void release() {
            gate.complete(null);
        }

        boolean isClosed() {
            return closed;
        }

        @Override
        public CompletableFuture<Void> save(String event) {
            if (gated == Operation.SAVE) {
                entered.complete(null);
                return gate.thenRun(() -> events.add(event));
            }
            events.add(event);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<String>> load() {
            if (gated == Operation.LOAD) {
                entered.complete(null);
                return gate.thenApply(ignored -> List.copyOf(events));
            }
            return CompletableFuture.completedFuture(List.copyOf(events));
        }

        @Override
        public CompletableFuture<Void> closeSession() {
            if (gated == Operation.CLOSE) {
                entered.complete(null);
                return gate.thenRun(() -> closed = true);
            }
            closed = true;
            return CompletableFuture.completedFuture(null);
        }
    }

    /** Sender-side counterpart of {@link GatedReceiverPersisterAsync}. */
    static final class GatedSenderPersisterAsync implements JsonSenderSessionPersisterAsync {
        private final List<String> events = new CopyOnWriteArrayList<>();
        private final Operation gated;
        private final CompletableFuture<Void> entered = new CompletableFuture<>();
        private final CompletableFuture<Void> gate = new CompletableFuture<>();
        private volatile boolean closed;

        GatedSenderPersisterAsync(Operation gated) {
            this.gated = gated;
        }

        void awaitEntered(long timeoutMillis) throws Exception {
            entered.get(timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
        }

        void release() {
            gate.complete(null);
        }

        boolean isClosed() {
            return closed;
        }

        @Override
        public CompletableFuture<Void> save(String event) {
            if (gated == Operation.SAVE) {
                entered.complete(null);
                return gate.thenRun(() -> events.add(event));
            }
            events.add(event);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<String>> load() {
            if (gated == Operation.LOAD) {
                entered.complete(null);
                return gate.thenApply(ignored -> List.copyOf(events));
            }
            return CompletableFuture.completedFuture(List.copyOf(events));
        }

        @Override
        public CompletableFuture<Void> closeSession() {
            if (gated == Operation.CLOSE) {
                entered.complete(null);
                return gate.thenRun(() -> closed = true);
            }
            closed = true;
            return CompletableFuture.completedFuture(null);
        }
    }
}
