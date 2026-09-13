package org.payjoindevkit

internal abstract class MemoryEventLog {
    private val events = java.util.concurrent.CopyOnWriteArrayList<String>()
    @Volatile var closed: Boolean = false
        private set

    fun save(event: String) {
        events.add(event)
    }

    fun load(): List<String> = events.toList()

    fun closeSession() {
        closed = true
    }
}

internal abstract class MemoryEventLogAsync {
    private val events = java.util.concurrent.CopyOnWriteArrayList<String>()
    @Volatile var closed: Boolean = false
        private set

    suspend fun save(event: String) {
        events.add(event)
    }

    suspend fun load(): List<String> = events.toList()

    suspend fun closeSession() {
        closed = true
    }
}

internal class InMemoryReceiverPersister : MemoryEventLog(), JsonReceiverSessionPersister

internal class InMemorySenderPersister : MemoryEventLog(), JsonSenderSessionPersister

internal class InMemoryReceiverPersisterAsync : MemoryEventLogAsync(), JsonReceiverSessionPersisterAsync

internal class InMemorySenderPersisterAsync : MemoryEventLogAsync(), JsonSenderSessionPersisterAsync
