using System.Diagnostics;

namespace ReproIt.Sdk;

internal enum FailureAdmission
{
    Admitted,
    SuppressedExact,
    SuppressedHighCardinality,
}

internal static class SdkProcessResources
{
    private const int MaxFailureStormIdentities = 256;
    private const int MaxQueuedCandidates = 16;
    private static readonly HashSet<string> ActiveOperations = [];
    private static readonly Dictionary<string, StormEntry> StormAdmitted = [];
    private static readonly object StateLock = new();
    private static int activeBytes;
    private static int queuedBytes;
    private static int queuedCandidates;
    private static long stormLastRefill = Stopwatch.GetTimestamp();
    private static double stormTokens = 4;

    internal static bool ReserveOperation(string operationId, int bytes)
    {
        lock (StateLock)
        {
            if (ActiveOperations.Contains(operationId) ||
                ActiveOperations.Count >= Sdk.MaxActiveOperations ||
                activeBytes + queuedBytes + bytes > Sdk.MaxGlobalBytes)
            {
                return false;
            }
            ActiveOperations.Add(operationId);
            activeBytes += bytes;
            return true;
        }
    }

    internal static bool GrowOperation(string operationId, int bytes)
    {
        lock (StateLock)
        {
            if (!ActiveOperations.Contains(operationId) ||
                activeBytes + queuedBytes + bytes > Sdk.MaxGlobalBytes)
            {
                return false;
            }
            activeBytes += bytes;
            return true;
        }
    }

    internal static void ReleaseOperation(string operationId, int bytes)
    {
        lock (StateLock)
        {
            if (ActiveOperations.Remove(operationId))
            {
                activeBytes = Math.Max(0, activeBytes - bytes);
            }
        }
    }

    internal static bool ReserveCandidate(int bytes)
    {
        lock (StateLock)
        {
            if (queuedCandidates >= MaxQueuedCandidates ||
                activeBytes + queuedBytes + bytes > Sdk.MaxGlobalBytes)
            {
                return false;
            }
            queuedCandidates += 1;
            queuedBytes += bytes;
            return true;
        }
    }

    internal static void ReleaseCandidate(int bytes)
    {
        lock (StateLock)
        {
            queuedCandidates = Math.Max(0, queuedCandidates - 1);
            queuedBytes = Math.Max(0, queuedBytes - bytes);
        }
    }

    internal static FailureAdmission AdmitFailure(string key)
    {
        lock (StateLock)
        {
            long now = Stopwatch.GetTimestamp();
            double elapsed = Stopwatch.GetElapsedTime(stormLastRefill, now).TotalSeconds;
            stormTokens = Math.Min(4, stormTokens + Math.Max(0, elapsed) * 2);
            stormLastRefill = now;
            foreach (string known in StormAdmitted
                .Where(entry =>
                    Stopwatch.GetElapsedTime(entry.Value.Admitted, now).TotalSeconds >= 60)
                .Select(entry => entry.Key)
                .ToArray())
            {
                StormAdmitted.Remove(known);
            }
            if (StormAdmitted.TryGetValue(key, out StormEntry? existing))
            {
                existing.Observed = now;
                return FailureAdmission.SuppressedExact;
            }
            if (stormTokens < 1)
            {
                return FailureAdmission.SuppressedHighCardinality;
            }
            if (StormAdmitted.Count >= MaxFailureStormIdentities)
            {
                string oldest = StormAdmitted
                    .OrderBy(entry => entry.Value.Observed)
                    .ThenBy(entry => entry.Key, StringComparer.Ordinal)
                    .First().Key;
                StormAdmitted.Remove(oldest);
            }
            stormTokens -= 1;
            StormAdmitted.Add(key, new StormEntry(now));
            return FailureAdmission.Admitted;
        }
    }

    internal static void ResetForTests()
    {
        lock (StateLock)
        {
            ActiveOperations.Clear();
            StormAdmitted.Clear();
            activeBytes = 0;
            queuedBytes = 0;
            queuedCandidates = 0;
            stormLastRefill = Stopwatch.GetTimestamp();
            stormTokens = 4;
        }
    }

    private sealed class StormEntry(long now)
    {
        internal long Admitted { get; } = now;
        internal long Observed { get; set; } = now;
    }
}
