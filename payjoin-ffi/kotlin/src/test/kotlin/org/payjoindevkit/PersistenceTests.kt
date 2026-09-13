package org.payjoindevkit

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class PersistenceTests {
    @Test
    fun receiverPersistence() {
        val persister = InMemoryReceiverPersister()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        ReceiverBuilder("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)
            .build()
            .save(persister)
        val state = replayReceiverEventLog(persister).state()
        assertIs<ReceiveSession.Initialized>(state)
        assertFalse(persister.closed)
        persister.closeSession()
        assertTrue(persister.closed)
    }

    @Test
    fun senderPersistence() {
        val receiverPersister = InMemoryReceiverPersister()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val receiver = ReceiverBuilder(
            "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
            "https://example.com",
            ohttpKeys,
        ).build().save(receiverPersister)
        val uri = receiver.pjUri()
        val senderPersister = InMemorySenderPersister()
        SenderBuilder(originalPsbt(), uri).buildRecommended(1000u).save(senderPersister)
        val state = replaySenderEventLog(senderPersister).state()
        assertIs<SendSession.WithReplyKey>(state)
        assertFalse(senderPersister.closed)
        senderPersister.closeSession()
        assertTrue(senderPersister.closed)
        receiverPersister.closeSession()
        assertTrue(receiverPersister.closed)
    }

    @Test
    fun receiverPersistenceAsync() = runTest {
        val persister = InMemoryReceiverPersisterAsync()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        ReceiverBuilder("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com", ohttpKeys)
            .build()
            .saveAsync(persister)
        val state = replayReceiverEventLogAsync(persister).state()
        assertIs<ReceiveSession.Initialized>(state)
        assertFalse(persister.closed)
        persister.closeSession()
        assertTrue(persister.closed)
    }

    @Test
    fun senderPersistenceAsync() = runTest {
        val receiverPersister = InMemoryReceiverPersisterAsync()
        val ohttpKeys = OhttpKeys.decode(ohttpKeysData)
        val receiver = ReceiverBuilder(
            "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK",
            "https://example.com",
            ohttpKeys,
        ).build().saveAsync(receiverPersister)
        val uri = receiver.pjUri()
        val senderPersister = InMemorySenderPersisterAsync()
        SenderBuilder(originalPsbt(), uri).buildRecommended(1000u).saveAsync(senderPersister)
        val state = replaySenderEventLogAsync(senderPersister).state()
        assertIs<SendSession.WithReplyKey>(state)
        assertFalse(senderPersister.closed)
        senderPersister.closeSession()
        assertTrue(senderPersister.closed)
        receiverPersister.closeSession()
        assertTrue(receiverPersister.closed)
    }
}
