using Xunit;
using Payjoin;

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
        var psbt = PayjoinMethods.OriginalPsbt();
        
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
        var psbt = PayjoinMethods.OriginalPsbt();

        var withReplyKey = await new SenderBuilder(psbt, uri)
            .BuildRecommended(1000)
            .SaveAsync(senderPersister);

        var replayed = await PayjoinMethods.ReplaySenderEventLogAsync(senderPersister);
        var state = replayed.State();

        Assert.IsType<SendSession.WithReplyKey>(state);
    }
}

public class CancelTests
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
    public void ReceiverCancelFromInitialized()
    {
        var persister = new InMemoryReceiverPersister();
        var address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var initialized = new ReceiverBuilder(address, "https://example.com", ohttpKeys)
            .Build()
            .Save(persister);
        var cancelTransition = initialized.Cancel();
        var fallbackTx = cancelTransition.Save(persister);
        Assert.Null(fallbackTx);

        var result = PayjoinMethods.ReplayReceiverEventLog(persister);
        var state = result.State();
        Assert.IsType<ReceiveSession.Closed>(state);
    }

    [Fact]
    public async Task ReceiverCancelFromInitializedAsync()
    {
        var persister = new InMemoryReceiverPersisterAsync();
        var address = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);

        var initialized = await new ReceiverBuilder(address, "https://example.com", ohttpKeys)
            .Build()
            .SaveAsync(persister);
        var cancelTransition = initialized.Cancel();
        var fallbackTx = await cancelTransition.SaveAsync(persister);
        Assert.Null(fallbackTx);

        var result = await PayjoinMethods.ReplayReceiverEventLogAsync(persister);
        var state = result.State();
        Assert.IsType<ReceiveSession.Closed>(state);
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

    private static PjUri CreateV2PjUri()
    {
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);
        var persister = new InMemoryReceiverPersister();
        using var builder = new ReceiverBuilder("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK", "https://example.com", ohttpKeys);
        using var transition = builder.Build();
        using var receiver = transition.Save(persister);
        return receiver.PjUri();
    }

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

    [Fact]
    public void SenderBuilderRejectsBadPsbt()
    {
        using var parsed = Uri.Parse("bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com/pj");
        using var uri = parsed.CheckPjSupported();

        var ex = Assert.Throws<SenderInputException.Psbt>(() =>
        {
            new SenderBuilder("not-a-psbt", uri);
        });

        Assert.IsType<PsbtParseException.InvalidPsbt>(ex.v1);
    }

    [Fact]
    public void ReceiverBuilderRejectsAmountOverflow()
    {
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);
        using var builder = new ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            ohttpKeys);

        Assert.Throws<FfiValidationException.AmountOutOfRange>(() =>
        {
            builder.WithAmount(21_000_000UL * 100_000_000UL + 1);
        });
    }

    [Fact]
    public void ReceiverBuilderRejectsExpirationOverflow()
    {
        var ohttpKeys = OhttpKeys.Decode(OhttpKeysData);
        using var builder = new ReceiverBuilder(
            "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4",
            "https://example.com",
            ohttpKeys);

        Assert.Throws<FfiValidationException.ExpirationOutOfRange>(() =>
        {
            builder.WithExpiration((ulong)uint.MaxValue + 1);
        });
    }

    [Fact]
    public void SenderBuilderWithAdditionalFeeRejectsFeeContributionOverflow()
    {
        using var uri = CreateV2PjUri();
        var psbt = PayjoinMethods.OriginalPsbt();
        using var builder = new SenderBuilder(psbt, uri);

        var ex = Assert.Throws<SenderInputException.FfiValidation>(() =>
        {
            builder.BuildWithAdditionalFee(21_000_000UL * 100_000_000UL + 1, null, 1000, false);
        });

        Assert.IsType<FfiValidationException.AmountOutOfRange>(ex.v1);
    }

    [Fact]
    public void SenderBuilderWithAdditionalFeeRejectsFeeRateOverflow()
    {
        using var uri = CreateV2PjUri();
        var psbt = PayjoinMethods.OriginalPsbt();
        using var builder = new SenderBuilder(psbt, uri);

        var ex = Assert.Throws<SenderInputException.FfiValidation>(() =>
        {
            builder.BuildWithAdditionalFee(1, null, ulong.MaxValue, false);
        });

        Assert.IsType<FfiValidationException.FeeRateOutOfRange>(ex.v1);
    }

    [Fact]
    public void SenderBuilderNonIncentivizingRejectsFeeRateOverflow()
    {
        using var uri = CreateV2PjUri();
        var psbt = PayjoinMethods.OriginalPsbt();
        using var builder = new SenderBuilder(psbt, uri);

        var ex = Assert.Throws<SenderInputException.FfiValidation>(() =>
        {
            builder.BuildNonIncentivizing(ulong.MaxValue);
        });

        Assert.IsType<FfiValidationException.FeeRateOutOfRange>(ex.v1);
    }
}
