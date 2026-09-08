namespace Payjoin.Tests;

internal static class TestVectors
{
    private static string Read(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", name));

    internal static readonly string OriginalPsbt = Read("original-psbt.base64");
    private static readonly string OhttpKeysHex = Read("ohttp-keys.hex").Trim();

    internal static byte[] OhttpKeys => Convert.FromHexString(OhttpKeysHex);
}
