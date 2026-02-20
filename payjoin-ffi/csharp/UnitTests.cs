using Xunit;
using uniffi.payjoin;

namespace Payjoin.Tests;

public class UriTests
{
    [Fact]
    public void UrlEncodedPayjoinParameter()
    {
        var uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        var result = Url.Parse(uri);
        Assert.NotNull(result);
    }

    [Fact]
    public void ValidUrl()
    {
        var uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        var result = Url.Parse(uri);
        Assert.NotNull(result);
    }

    [Fact]
    public void MissingAmountShouldBeOk()
    {
        var uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        var result = Url.Parse(uri);
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "https://example.com")]
    [InlineData("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion")]
    [InlineData("BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4", "https://example.com")]
    [InlineData("bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", "https://example.com")]
    public void ValidUrisWithDifferentAddressesAndEndpoints(string address, string pj)
    {
        var uri = $"{address}?amount=1&pj={pj}";
        var result = Url.Parse(uri);
        Assert.NotNull(result);
    }
}

public class InMemoryReceiverPersister : JsonReceiverSessionPersister
{
    private List<string> _events = new();

    public void Save(string @event)
    {
        _events.Add(@event);
    }

    public string[] Load()
    {
        return _events.ToArray();
    }

    public void Close()
    {
        // no-op for tests
    }
}

public class InMemorySenderPersister : JsonSenderSessionPersister
{
    private List<string> _events = new();

    public void Save(string @event)
    {
        _events.Add(@event);
    }

    public string[] Load()
    {
        return _events.ToArray();
    }

    public void Close()
    {
        // no-op for tests
    }
}

public class InMemoryReceiverPersisterAsync : JsonReceiverSessionPersisterAsync
{
    private readonly List<string> _events = new();

    public Task Save(string @event)
    {
        _events.Add(@event);
        return Task.CompletedTask;
    }

    public Task<string[]> Load()
    {
        return Task.FromResult(_events.ToArray());
    }

    public Task Close()
    {
        return Task.CompletedTask;
    }
}

public class InMemorySenderPersisterAsync : JsonSenderSessionPersisterAsync
{
    private readonly List<string> _events = new();

    public Task Save(string @event)
    {
        _events.Add(@event);
        return Task.CompletedTask;
    }

    public Task<string[]> Load()
    {
        return Task.FromResult(_events.ToArray());
    }

    public Task Close()
    {
        return Task.CompletedTask;
    }
}

public class PersistenceTests
{
    private static readonly byte[] OhttpKeysData = new byte[]
    {
        0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
        0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
        0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
        0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
        0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
        0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
        0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x03,
    };

    [Fact]
    public void ReceiverPersistence()
    {
        var persister = new InMemoryReceiverPersister();
        var address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var builder = new ReceiverBuilder(address, "https://example.com", ohttpKeys);
        var transition = builder.Build();
        var initialized = transition.Save(persister);

        var result = PayjoinMethods.ReplayReceiverEventLog(persister);
        var state = result.State();

        Assert.IsType<ReceiveSession.Initialized>(state);
    }

    [Fact]
    public void SenderPersistence()
    {
        var receiverPersister = new InMemoryReceiverPersister();
        var address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var receiver = new ReceiverBuilder(address, "https://example.com", ohttpKeys)
            .Build()
            .Save(receiverPersister);
        var uri = receiver.PjUri();

        var senderPersister = new InMemorySenderPersister();
        var psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
        
        var withReplyKey = new SenderBuilder(psbt, uri)
            .BuildRecommended(1000)
            .Save(senderPersister);

        var replayed = PayjoinMethods.ReplaySenderEventLog(senderPersister);
        var state = replayed.State();

        Assert.IsType<SendSession.WithReplyKey>(state);
    }

    [Fact]
    public async Task ReceiverPersistenceAsync()
    {
        var persister = new InMemoryReceiverPersisterAsync();
        var address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var builder = new ReceiverBuilder(address, "https://example.com", ohttpKeys);
        var transition = builder.Build();
        var initialized = await transition.SaveAsync(persister);

        var result = await PayjoinMethods.ReplayReceiverEventLogAsync(persister);
        var state = result.State();

        Assert.IsType<ReceiveSession.Initialized>(state);
    }

    [Fact]
    public async Task SenderPersistenceAsync()
    {
        var receiverPersister = new InMemoryReceiverPersisterAsync();
        var address = "2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var receiver = await new ReceiverBuilder(address, "https://example.com", ohttpKeys)
            .Build()
            .SaveAsync(receiverPersister);
        var uri = receiver.PjUri();

        var senderPersister = new InMemorySenderPersisterAsync();
        var psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        var withReplyKey = await new SenderBuilder(psbt, uri)
            .BuildRecommended(1000)
            .SaveAsync(senderPersister);

        var replayed = await PayjoinMethods.ReplaySenderEventLogAsync(senderPersister);
        var state = replayed.State();

        Assert.IsType<SendSession.WithReplyKey>(state);
    }
}

public class ValidationTests
{
    private static readonly byte[] OhttpKeysData = new byte[]
    {
        0x01, 0x00, 0x16, 0x04, 0xba, 0x48, 0xc4, 0x9c, 0x3d, 0x4a,
        0x92, 0xa3, 0xad, 0x00, 0xec, 0xc6, 0x3a, 0x02, 0x4d, 0xa1,
        0x0c, 0xed, 0x02, 0x18, 0x0c, 0x73, 0xec, 0x12, 0xd8, 0xa7,
        0xad, 0x2c, 0xc9, 0x1b, 0xb4, 0x83, 0x82, 0x4f, 0xe2, 0xbe,
        0xe8, 0xd2, 0x8b, 0xfe, 0x2e, 0xb2, 0xfc, 0x64, 0x53, 0xbc,
        0x4d, 0x31, 0xcd, 0x85, 0x1e, 0x8a, 0x65, 0x40, 0xe8, 0x6c,
        0x53, 0x82, 0xaf, 0x58, 0x8d, 0x37, 0x09, 0x57, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x03,
    };

    [Fact]
    public void ReceiverBuilderRejectsBadAddress()
    {
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);
        
        Assert.Throws<ReceiverBuilderException.InvalidAddress>(() =>
        {
            new ReceiverBuilder("not-an-address", "https://example.com", ohttpKeys);
        });
    }

    [Fact]
    public void InputPairRejectsInvalidOutpoint()
    {
        Assert.Throws<InputPairException.InvalidOutPoint>(() =>
        {
            var txin = new PlainTxIn(
                new PlainOutPoint("deadbeef", 0),
                new byte[] {},
                0,
                new byte[][] {}
            );
            var psbtIn = new PlainPsbtInput(null, null, null);
            new InputPair(txin, psbtIn, null);
        });
    }
}
