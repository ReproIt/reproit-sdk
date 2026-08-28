using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal enum ObservationAction
{
    Capture,
    Replay,
}

internal enum ObservationOutcome
{
    Error,
    Response,
}

internal enum ObservationSessionState
{
    Request,
    Capture,
    Replay,
    ReplayEof,
    Finished,
}

internal sealed record InstalledObservationAdapter(
    string AdapterId,
    string AdapterVersion,
    AutomaticObservationClass Class,
    string ImplementationDigest);

internal static class InstalledObservationAdapters
{
    private static readonly object RegistryLock = new();
    private static readonly SortedDictionary<AutomaticObservationClass, InstalledObservationAdapter>
        Registry = [];

    internal static void Install(InstalledObservationAdapter adapter)
    {
        lock (RegistryLock)
        {
            if (string.IsNullOrEmpty(adapter.AdapterId) ||
                string.IsNullOrEmpty(adapter.AdapterVersion) ||
                string.IsNullOrEmpty(adapter.ImplementationDigest) ||
                Registry.Count >= SdkEngineBridge.MaxObservationAdapters ||
                Registry.ContainsKey(adapter.Class))
            {
                throw AutomaticProject.CaptureError();
            }
            Registry.Add(adapter.Class, adapter);
        }
    }

    internal static void Remove(InstalledObservationAdapter adapter)
    {
        lock (RegistryLock)
        {
            if (Registry.TryGetValue(adapter.Class, out InstalledObservationAdapter? installed) &&
                installed == adapter)
            {
                Registry.Remove(adapter.Class);
            }
        }
    }

    internal static JsonArray Snapshot()
    {
        lock (RegistryLock)
        {
            JsonArray result = [];
            foreach (AutomaticObservationClass observationClass in
                SdkEngineBridge.RequiredObservationClasses)
            {
                if (!Registry.TryGetValue(observationClass, out InstalledObservationAdapter? adapter))
                {
                    continue;
                }
                result.Add(new JsonObject
                {
                    ["adapter_id"] = adapter.AdapterId,
                    ["adapter_version"] = adapter.AdapterVersion,
                    ["class"] = AutomaticOperation.ObservationClass(adapter.Class),
                    ["implementation_digest"] = adapter.ImplementationDigest,
                });
            }
            return result;
        }
    }
}

internal sealed class ObservationSession
{
    private readonly SdkEngineBridge bridge;
    private readonly SdkEngineObservationHandle handle;
    private readonly object stateLock = new();
    private ulong requestBytes;
    private ulong responseBytes;
    private readonly ulong sessionPosition;
    private ObservationSessionState state = ObservationSessionState.Request;

    internal ObservationSession(SdkEngineBridge bridge, SdkEngineObservationStart start)
    {
        this.bridge = bridge;
        handle = start.Handle;
        sessionPosition = start.SessionPosition;
    }

    internal void WriteRequest(byte[] chunk) =>
        Write("request", chunk, ObservationSessionState.Request);

    internal void WriteResponse(byte[] chunk) =>
        Write("response", chunk, ObservationSessionState.Capture);

    internal ObservationAction Dispatch()
    {
        lock (stateLock)
        {
            if (state != ObservationSessionState.Request || requestBytes == 0)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                string action = bridge.DispatchObservation(handle);
                state = action == "capture"
                    ? ObservationSessionState.Capture
                    : ObservationSessionState.Replay;
                return action == "capture" ? ObservationAction.Capture : ObservationAction.Replay;
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal SdkEngineObservationChunk ReadResponse()
    {
        lock (stateLock)
        {
            if (state != ObservationSessionState.Replay)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                SdkEngineObservationChunk chunk = bridge.ReadObservation(handle);
                if (chunk.Eof)
                {
                    state = ObservationSessionState.ReplayEof;
                }
                return chunk;
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal void Finish(ObservationOutcome outcome)
    {
        lock (stateLock)
        {
            bool valid = state == ObservationSessionState.Capture && responseBytes > 0;
            valid = valid || state == ObservationSessionState.ReplayEof;
            if (!valid)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                bridge.FinishObservation(
                    handle,
                    outcome == ObservationOutcome.Response ? "response" : "error",
                    sessionPosition);
                state = ObservationSessionState.Finished;
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal void Abandon()
    {
        lock (stateLock)
        {
            AbandonLocked();
        }
    }

    private void Write(string stream, byte[] chunk, ObservationSessionState required)
    {
        lock (stateLock)
        {
            if (state != required || chunk.Length is 0 or > SdkEngineBridge.MaxObservationChunkBytes)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                bridge.WriteObservation(handle, stream, chunk);
                if (stream == "request")
                {
                    requestBytes += checked((ulong)chunk.Length);
                }
                else
                {
                    responseBytes += checked((ulong)chunk.Length);
                }
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    private void AbandonLocked()
    {
        if (state == ObservationSessionState.Finished)
        {
            return;
        }
        try
        {
            bridge.AbandonObservation(handle);
        }
        catch (Exception)
        {
            // Capture cleanup must not change application behavior.
        }
        state = ObservationSessionState.Finished;
    }
}
