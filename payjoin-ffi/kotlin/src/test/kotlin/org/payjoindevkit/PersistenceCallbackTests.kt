package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class PersistenceCallbackTests {
    @Test
    fun receiverSaveFailurePropagates() {
        val p = ControlledPersister().apply { failure = "save" }
        receiverBuilder().use { builder ->
            builder.build().use { transition ->
                assertFailsWith<ForeignException.InternalException> {
                    transition.save(p)
                }.also {
                    assertContains(it.toString(), "storage ${p.failure} failed")
                }
            }
        }
        assertEquals(listOf("save"), p.calls)
        assertTrue(p.events.isEmpty())
        assertFalse(p.closed)
    }

    @Test
    fun senderSaveFailurePropagates() {
        val p = ControlledPersister().apply { failure = "save" }
        senderBuilder().use { builder ->
            builder.buildRecommended(1000u).use { transition ->
                assertFailsWith<ForeignException.InternalException> {
                    transition.save(p)
                }.also {
                    assertContains(it.toString(), "storage ${p.failure} failed")
                }
            }
        }
        assertEquals(listOf("save"), p.calls)
        assertTrue(p.events.isEmpty())
        assertFalse(p.closed)
    }

    @Test
    fun receiverLoadFailurePropagates() {
        val p = ControlledPersister().apply { failure = "load" }
        assertFailsWith<ReceiverReplayException> {
            replayReceiverEventLog(p)
        }.also {
            assertContains(it.toString(), "storage ${p.failure} failed")
        }
        assertEquals(listOf("load"), p.calls)
    }

    @Test
    fun senderLoadFailurePropagates() {
        val p = ControlledPersister().apply { failure = "load" }
        assertFailsWith<SenderReplayException> {
            replaySenderEventLog(p)
        }.also {
            assertContains(it.toString(), "storage ${p.failure} failed")
        }
        assertEquals(listOf("load"), p.calls)
    }

    @Test
    fun receiverCloseFailurePropagates() {
        val p = ControlledPersister()
        receiverBuilder().use { builder ->
            builder.build().use { it.save(p) }.use { receiver ->
                p.failure = "close"
                receiver.cancel().use { transition ->
                    assertFailsWith<ReceiverPersistedException.Storage> {
                        transition.save(p)
                    }.also {
                        assertContains(it.toString(), "storage ${p.failure} failed")
                    }
                }
            }
        }
        assertEquals("close", p.calls.last())
        assertFalse(p.closed)
    }

    @Test
    fun senderCloseFailurePropagates() {
        val p = ControlledPersister()
        senderBuilder().use { builder ->
            builder.buildRecommended(1000u).use { it.save(p) }.use { sender ->
                sender.cancel().use { it.save(p) }.use { pending ->
                    p.failure = "close"
                    pending.closeSession().use { transition ->
                        assertFailsWith<SenderPersistedException.Storage> {
                            transition.save(p)
                        }.also {
                            assertContains(it.toString(), "storage ${p.failure} failed")
                        }
                    }
                }
            }
        }
        assertEquals("close", p.calls.last())
        assertFalse(p.closed)
    }

    @Test
    fun receiverAsyncSaveFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister().apply { failure = "save" }
            receiverBuilder().use { builder ->
                builder.build().use { transition ->
                    p.gated("save") {
                        assertFailsWith<ForeignException.InternalException> {
                            transition.saveAsync(p)
                        }.also {
                            assertContains(it.toString(), "storage ${p.failure} failed")
                        }
                    }
                }
            }
            assertTrue(p.events.isEmpty())
            assertFalse(p.closed)
        }
    }

    @Test
    fun senderAsyncSaveFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister().apply { failure = "save" }
            senderBuilder().use { builder ->
                builder.buildRecommended(1000u).use { transition ->
                    p.gated("save") {
                        assertFailsWith<ForeignException.InternalException> {
                            transition.saveAsync(p)
                        }.also {
                            assertContains(it.toString(), "storage ${p.failure} failed")
                        }
                    }
                }
            }
            assertTrue(p.events.isEmpty())
            assertFalse(p.closed)
        }
    }

    @Test
    fun receiverAsyncLoadFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister().apply { failure = "load" }
            p.gated("load") {
                assertFailsWith<ReceiverReplayException> {
                    replayReceiverEventLogAsync(p)
                }.also {
                    assertContains(it.toString(), "storage ${p.failure} failed")
                }
                Unit
            }
        }
    }

    @Test
    fun senderAsyncLoadFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister().apply { failure = "load" }
            p.gated("load") {
                assertFailsWith<SenderReplayException> {
                    replaySenderEventLogAsync(p)
                }.also {
                    assertContains(it.toString(), "storage ${p.failure} failed")
                }
                Unit
            }
        }
    }

    @Test
    fun receiverAsyncCloseFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            receiverBuilder().use { builder ->
                builder.build().use { it.saveAsync(p) }.use { receiver ->
                    p.failure = "close"
                    receiver.cancel().use { transition ->
                        p.gated("close") {
                            assertFailsWith<ReceiverPersistedException.Storage> {
                                transition.saveAsync(p)
                            }.also {
                                assertContains(it.toString(), "storage ${p.failure} failed")
                            }
                        }
                    }
                }
            }
            assertFalse(p.closed)
        }
    }

    @Test
    fun senderAsyncCloseFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            senderBuilder().use { builder ->
                builder.buildRecommended(1000u).use { it.saveAsync(p) }.use { sender ->
                    sender.cancel().use { it.saveAsync(p) }.use { pending ->
                        p.failure = "close"
                        pending.closeSession().use { transition ->
                            p.gated("close") {
                                assertFailsWith<SenderPersistedException.Storage> {
                                    transition.saveAsync(p)
                                }.also {
                                    assertContains(it.toString(), "storage ${p.failure} failed")
                                }
                            }
                        }
                    }
                }
            }
            assertFalse(p.closed)
        }
    }

    @Test
    fun receiverSaveLoadCloseResumeSuccessfully(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            receiverBuilder().use { builder ->
                builder.build().use { transition ->
                    p.gated("save") { transition.saveAsync(p) }
                }.use { receiver ->
                    val replay = p.gated("load") { replayReceiverEventLogAsync(p) }
                    replay.use { assertIs<ReceiveSession.Initialized>(it.state()) }
                    assertFalse(p.closed)
                    receiver.cancel().use { transition ->
                        assertNull(p.gated("close") { transition.saveAsync(p) })
                    }
                    assertTrue(p.closed)
                    replayReceiverEventLogAsync(p).use { assertIs<ReceiveSession.Closed>(it.state()) }
                }
            }
        }
    }

    @Test
    fun senderSaveLoadCloseResumeSuccessfully(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            senderBuilder().use { builder ->
                builder.buildRecommended(1000u).use { transition ->
                    p.gated("save") { transition.saveAsync(p) }
                }.use { sender ->
                    val replay = p.gated("load") { replaySenderEventLogAsync(p) }
                    replay.use { assertIs<SendSession.WithReplyKey>(it.state()) }
                    sender.cancel().use { it.saveAsync(p) }.use { pending ->
                        assertFalse(p.closed)
                        pending.closeSession().use { transition ->
                            p.gated("close") { transition.saveAsync(p) }
                        }
                    }
                    assertTrue(p.closed)
                    replaySenderEventLogAsync(p).use { assertIs<SendSession.Closed>(it.state()) }
                }
            }
        }
    }

    @Test
    fun receiverTransitionSaveFailurePropagates() {
        val p = ControlledPersister()
        receiverBuilder().use { builder ->
            builder.build().use { it.save(p) }.use { receiver ->
                p.failure = "save"
                val before = p.events.size
                receiver.cancel().use { transition ->
                    val ex = assertFailsWith<ReceiverPersistedException.Storage> { transition.save(p) }
                    assertContains(ex.toString(), "storage save failed")
                }
                assertEquals(before, p.events.size)
                assertFalse(p.closed)
            }
        }
    }

    @Test
    fun senderTransitionSaveFailurePropagates() {
        val p = ControlledPersister()
        senderBuilder().use { builder ->
            builder.buildRecommended(1000u).use { it.save(p) }.use { sender ->
                p.failure = "save"
                val before = p.events.size
                sender.cancel().use { transition ->
                    val ex = assertFailsWith<SenderPersistedException.Storage> { transition.save(p) }
                    assertContains(ex.toString(), "storage save failed")
                }
                assertEquals(before, p.events.size)
                assertFalse(p.closed)
            }
        }
    }

    @Test
    fun receiverAsyncTransitionSaveFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            receiverBuilder().use { builder ->
                builder.build().use { it.saveAsync(p) }.use { receiver ->
                    p.failure = "save"
                    val before = p.events.size
                    receiver.cancel().use { transition ->
                        p.gated("save") {
                            val ex = assertFailsWith<ReceiverPersistedException.Storage> { transition.saveAsync(p) }
                            assertContains(ex.toString(), "storage save failed")
                        }
                    }
                    assertEquals(before, p.events.size)
                    assertFalse(p.closed)
                }
            }
        }
    }

    @Test
    fun senderAsyncTransitionSaveFailureAfterSuspensionPropagates(): Unit = runBlocking {
        withTimeout(15_000) {
            val p = ControlledAsyncPersister()
            senderBuilder().use { builder ->
                builder.buildRecommended(1000u).use { it.saveAsync(p) }.use { sender ->
                    p.failure = "save"
                    val before = p.events.size
                    sender.cancel().use { transition ->
                        p.gated("save") {
                            val ex = assertFailsWith<SenderPersistedException.Storage> { transition.saveAsync(p) }
                            assertContains(ex.toString(), "storage save failed")
                        }
                    }
                    assertEquals(before, p.events.size)
                    assertFalse(p.closed)
                }
            }
        }
    }
}

private fun receiverBuilder(): ReceiverBuilder = OhttpKeys.decode(ohttpKeysData).use {
    ReceiverBuilder("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", "https://example.com", it)
}

private fun senderBuilder(): SenderBuilder = receiverBuilder().use { builder ->
    builder.build().use { it.save(ControlledPersister()) }.use { receiver ->
        receiver.pjUri().use { SenderBuilder(originalPsbt(), it) }
    }
}
