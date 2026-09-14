package org.payjoindevkit

import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.assertFalse
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.supervisorScope

internal class ControlledPersister : JsonReceiverSessionPersister, JsonSenderSessionPersister {
    val events = CopyOnWriteArrayList<String>()
    val calls = CopyOnWriteArrayList<String>()
    @Volatile var failure: String? = null
    @Volatile var closed = false

    private fun before(operation: String) {
        calls.add(operation)
        if (failure == operation) throw ForeignException.InternalException("storage $operation failed")
    }

    override fun save(event: String) {
        before("save")
        events.add(event)
    }

    override fun load(): List<String> {
        before("load")
        return events.toList()
    }

    override fun closeSession() {
        before("close")
        closed = true
    }
}

internal class ControlledAsyncPersister : JsonReceiverSessionPersisterAsync, JsonSenderSessionPersisterAsync {
    val events = CopyOnWriteArrayList<String>()
    val calls = CopyOnWriteArrayList<String>()
    @Volatile var failure: String? = null
    @Volatile var closed = false
    @Volatile private var gatedOperation: String? = null
    @Volatile private var entered = CompletableDeferred<Unit>()
    @Volatile private var release = CompletableDeferred<Unit>()

    private suspend fun before(operation: String) {
        calls.add(operation)
        if (gatedOperation == operation) {
            entered.complete(Unit)
            release.await()
        }
        if (failure == operation) throw ForeignException.InternalException("storage $operation failed")
    }

    override suspend fun save(event: String) {
        before("save")
        events.add(event)
    }

    override suspend fun load(): List<String> {
        before("load")
        return events.toList()
    }

    override suspend fun closeSession() {
        before("close")
        closed = true
    }

    // Wait until Rust enters the callback, then prove the FFI call remains pending
    // before releasing it. Callers bound the whole operation with withTimeout.
    suspend fun <T> gated(operation: String, block: suspend () -> T): T = supervisorScope {
        entered = CompletableDeferred()
        release = CompletableDeferred()
        gatedOperation = operation
        val call = async { block() }
        try {
            entered.await()
            assertFalse(call.isCompleted, "FFI call returned before $operation callback resumed")
            release.complete(Unit)
            call.await()
        } finally {
            release.complete(Unit)
            gatedOperation = null
        }
    }
}
