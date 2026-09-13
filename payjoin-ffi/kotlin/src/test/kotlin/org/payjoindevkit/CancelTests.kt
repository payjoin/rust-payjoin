package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class CancelTests {
    @Test
    fun receiverCancel() {
        val persister = InMemoryReceiverPersister()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val initialized = ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            ohttpKeys,
        ).build().save(persister)
        val fallbackTx = initialized.cancel().save(persister)
        assertNull(fallbackTx)
        assertIs<ReceiveSession.Closed>(replayReceiverEventLog(persister).state())
        assertTrue(persister.closed)
    }

    @Test
    fun receiverCancelAsync() = runTest {
        val persister = InMemoryReceiverPersisterAsync()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val initialized = ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            ohttpKeys,
        ).build().saveAsync(persister)
        val fallbackTx = initialized.cancel().saveAsync(persister)
        assertNull(fallbackTx)
        assertIs<ReceiveSession.Closed>(replayReceiverEventLogAsync(persister).state())
        assertTrue(persister.closed)
    }

    @Test
    fun senderCancel() {
        val receiverPersister = InMemoryReceiverPersister()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val receiver = ReceiverBuilder(
            "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
            "https://example.com",
            ohttpKeys,
        ).build().save(receiverPersister)
        val uri = receiver.pjUri()
        val persister = InMemorySenderPersister()
        val withReplyKey = SenderBuilder(originalPsbt(), uri).buildRecommended(1000u).save(persister)
        val pendingFallback = withReplyKey.cancel().save(persister)
        assertTrue(pendingFallback.fallbackTx().isNotEmpty())
        assertIs<SendSession.SenderPendingFallback>(replaySenderEventLog(persister).state())
        assertFalse(persister.closed)
        pendingFallback.closeSession().save(persister)
        assertIs<SendSession.Closed>(replaySenderEventLog(persister).state())
        assertTrue(persister.closed)
    }

    @Test
    fun senderCancelAsync() = runTest {
        val receiverPersister = InMemoryReceiverPersisterAsync()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val receiver = ReceiverBuilder(
            "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
            "https://example.com",
            ohttpKeys,
        ).build().saveAsync(receiverPersister)
        val uri = receiver.pjUri()
        val persister = InMemorySenderPersisterAsync()
        val withReplyKey = SenderBuilder(originalPsbt(), uri).buildRecommended(1000u).saveAsync(persister)
        val pendingFallback = withReplyKey.cancel().saveAsync(persister)
        assertTrue(pendingFallback.fallbackTx().isNotEmpty())
        assertIs<SendSession.SenderPendingFallback>(replaySenderEventLogAsync(persister).state())
        assertFalse(persister.closed)
        pendingFallback.closeSession().saveAsync(persister)
        assertIs<SendSession.Closed>(replaySenderEventLogAsync(persister).state())
        assertTrue(persister.closed)
    }
}
