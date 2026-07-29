namespace Payjoin.Samples;

public static class SendSample
{
    /// <summary>
    /// Build a sender session from a BIP 21 URI scanned from the receiver and
    /// the wallet's signed original PSBT.
    /// </summary>
    public static WithReplyKey BuildSender(
        string bip21,
        string originalPsbtBase64,
        JsonSenderSessionPersister persister)
    {
        var uri = Payjoin.Uri.Parse(bip21);
        var pjUri = uri.CheckPjSupported(); // throws if the URI carries no payjoin parameters

        var sender = new SenderBuilder(originalPsbtBase64, pjUri)
            .BuildRecommended(minFeeRateSatPerKwu: 250) // 250 sat/kWU = 1 sat/vB floor
            .Save(persister);

        // The sender session then posts the original PSBT and polls for the
        // receiver's proposal through the request/response flow.
        return sender;
    }
}
