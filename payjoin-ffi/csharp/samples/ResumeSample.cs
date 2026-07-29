namespace Payjoin.Samples;

public static class ResumeSample
{
    /// <summary>
    /// Replay a persisted event log to recover the current state of a session
    /// after a crash or restart.
    /// </summary>
    public static ReceiveSession Replay(JsonReceiverSessionPersister persister)
    {
        using var replayed = PayjoinMethods.ReplayReceiverEventLog(persister);
        return replayed.State(); // e.g. ReceiveSession.Initialized
    }
}
