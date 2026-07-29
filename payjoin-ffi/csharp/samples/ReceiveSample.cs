// Compiled samples for the README's receive flow. These build as part of
// Payjoin.Tests, so they cannot go stale against the API.

using System.Collections.Generic;
using System.Threading.Tasks;
using Payjoin.Http;

namespace Payjoin.Samples;

public static class ReceiveSample
{
    /// <summary>
    /// Start a receiver session and produce the BIP 21 URI to show the sender.
    /// </summary>
    public static async Task<string> StartSessionAsync()
    {
        // Fetch the directory's OHTTP keys through an OHTTP relay, which keeps
        // the directory from learning your IP address.
        using var keysClient = new OhttpKeysClient(new System.Uri("https://pj.bobspacebkk.com"));
        var ohttpKeys = await keysClient.GetOhttpKeysAsync(new System.Uri("https://payjo.in"));

        var persister = new InMemoryPersister();
        var receiver = new ReceiverBuilder(
                "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4", // your receiving address
                "https://payjo.in",                           // payjoin directory
                ohttpKeys)
            .Build()
            .Save(persister);

        return receiver.PjUri().AsString();
    }
}

/// <summary>
/// Sessions persist each step to an event log so your app can crash or restart
/// and resume where it left off. Implement the persister over your own storage;
/// this is a minimal in-memory version. Every Save has a SaveAsync counterpart,
/// with async persister interfaces for database-backed storage.
/// </summary>
public class InMemoryPersister : JsonReceiverSessionPersister
{
    private readonly List<string> _events = new();
    public void Save(string @event) => _events.Add(@event);
    public string[] Load() => _events.ToArray();
    public void Close() { }
}
