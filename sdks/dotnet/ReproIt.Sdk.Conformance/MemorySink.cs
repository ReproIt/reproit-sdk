using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

/// <summary>Stores candidate bytes for conformance tests only.</summary>
internal sealed class MemorySink : ICandidateSink
{
    internal List<byte[]> Candidates { get; } = [];

    public int QueuedBytes => 0;

    public bool AllowsProcessingMode(string mode) => mode is "managed" or "private";

    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate)
    {
        _ = captureId;
        Candidates.Add(candidate.ToArray());
        return true;
    }
}
