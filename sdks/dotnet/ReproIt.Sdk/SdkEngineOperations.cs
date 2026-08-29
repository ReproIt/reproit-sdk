using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal readonly record struct SdkEngineHandle(ulong Value);
internal readonly record struct SdkEngineOperationHandle(ulong Value);
internal readonly record struct SdkEngineSinkHandle(ulong Value);
internal readonly record struct SdkEngineObservationHandle(ulong Value);
internal readonly record struct SdkEngineDependencyHandle(ulong Value);

internal sealed record SdkEngineSubjectObject(string Digest, string Path, ulong Size);
internal sealed record SdkEngineObservationAdapter(
    string AdapterId,
    string AdapterVersion,
    string Class,
    string ImplementationDigest);

internal sealed record SdkEngineOpenOptions(
    string BuildRepositoryId,
    string ProjectToml,
    string Sdk,
    string SourceRevision,
    JsonObject SubjectManifest,
    IReadOnlyList<SdkEngineSubjectObject> SubjectObjects);

internal readonly record struct SdkEngineOperationStart(
    SdkEngineOperationHandle Handle,
    string OperationId);
internal readonly record struct SdkEngineObservationStart(
    SdkEngineObservationHandle Handle,
    ulong SessionPosition);
internal readonly record struct SdkEngineObservationChunk(byte[] Chunk, bool Eof);
internal readonly record struct SdkEngineDependencyStart(
    SdkEngineDependencyHandle Handle,
    string Action);

internal static class SdkEngineOperations
{
    internal const string ContractOperation = "contract";
    internal const string FinishDependencyOperation = "dependency-finish";
    internal const string OpenDependencyOperation = "dependency-open";
    internal const string CloseEngineOperation = "engine-close";
    internal const string OpenEngineOperation = "engine-open";
    internal const string AbandonObservationOperation = "observation-abandon";
    internal const string DispatchObservationOperation = "observation-dispatch";
    internal const string FinishObservationOperation = "observation-finish";
    internal const string OpenObservationOperation = "observation-open";
    internal const string ReadObservationOperation = "observation-read";
    internal const string WriteObservationOperation = "observation-write";
    internal const string AbandonOperationName = "operation-abandon";
    internal const string BeginOperationName = "operation-begin";
    internal const string CloseWorldOperation = "operation-close-world";
    internal const string FailOperationName = "operation-fail";
    internal const string InputOperation = "operation-input";
    internal const string SucceedOperationName = "operation-succeed";
    internal const string UnownedOperation = "operation-unowned";
    internal const string WaitForSinkOperation = "sink-wait";

    internal static readonly string[] OperationNames =
    [
        ContractOperation,
        FinishDependencyOperation,
        OpenDependencyOperation,
        CloseEngineOperation,
        OpenEngineOperation,
        AbandonObservationOperation,
        DispatchObservationOperation,
        FinishObservationOperation,
        OpenObservationOperation,
        ReadObservationOperation,
        WriteObservationOperation,
        AbandonOperationName,
        BeginOperationName,
        CloseWorldOperation,
        FailOperationName,
        InputOperation,
        SucceedOperationName,
        UnownedOperation,
        WaitForSinkOperation,
    ];

    internal static SdkEngineHandle OpenEngine(
        this SdkEngineBridge bridge,
        SdkEngineOpenOptions options)
    {
        JsonArray objects = [];
        foreach (SdkEngineSubjectObject subjectObject in options.SubjectObjects)
        {
            objects.Add(new JsonObject
            {
                ["digest"] = subjectObject.Digest,
                ["path"] = subjectObject.Path,
                ["size"] = subjectObject.Size,
            });
        }
        JsonElement result = bridge.Call(new JsonObject
        {
            ["build_repository_id"] = options.BuildRepositoryId,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = OpenEngineOperation,
            ["observation_adapters"] = InstalledObservationAdapters.Snapshot(),
            ["project_toml"] = options.ProjectToml,
            ["sdk"] = options.Sdk,
            ["source_revision"] = options.SourceRevision,
            ["subject_manifest"] = options.SubjectManifest.DeepClone(),
            ["subject_objects"] = objects,
        });
        return new SdkEngineHandle(PositiveHandle(result, "engine_handle"));
    }

    internal static void CloseEngine(this SdkEngineBridge bridge, SdkEngineHandle handle) =>
        EmptyResult(bridge.Call(new JsonObject
        {
            ["engine_handle"] = handle.Value,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = CloseEngineOperation,
        }));

    internal static SdkEngineOperationStart BeginOperation(
        this SdkEngineBridge bridge,
        SdkEngineHandle handle,
        JsonObject begin,
        JsonObject? fuzzContext = null)
    {
        JsonObject request = new()
        {
            ["begin"] = begin.DeepClone(),
            ["engine_handle"] = handle.Value,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = BeginOperationName,
        };
        if (fuzzContext is not null)
        {
            request["fuzz_context"] = fuzzContext.DeepClone();
        }
        JsonElement result = bridge.Call(request);
        ulong operationHandle = PositiveHandle(
            result, "operation_handle", "operation_id");
        JsonElement operationIdValue = result.GetProperty("operation_id");
        string? operationId = operationIdValue.ValueKind == JsonValueKind.String
            ? operationIdValue.GetString()
            : null;
        if (string.IsNullOrEmpty(operationId) || operationId.Length > 256)
        {
            throw ResponseError();
        }
        return new SdkEngineOperationStart(
            new SdkEngineOperationHandle(operationHandle), operationId);
    }

    internal static void RecordInput(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        JsonObject input) => EmptyResult(bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["input"] = input.DeepClone(),
            ["operation"] = InputOperation,
            ["operation_handle"] = handle.Value,
        }));

    internal static SdkEngineDependencyStart OpenDependency(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        string? causalParentId,
        JsonObject request)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["causal_parent_id"] = causalParentId,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = OpenDependencyOperation,
            ["operation_handle"] = handle.Value,
            ["request"] = request.DeepClone(),
        });
        ulong dependencyHandle = PositiveHandle(result, "dependency_handle", "action");
        JsonElement actionValue = result.GetProperty("action");
        string? action = actionValue.ValueKind == JsonValueKind.String
            ? actionValue.GetString()
            : null;
        if (action is not ("capture" or "replay"))
        {
            throw ResponseError();
        }
        return new SdkEngineDependencyStart(
            new SdkEngineDependencyHandle(dependencyHandle), action);
    }

    internal static string FinishDependency(
        this SdkEngineBridge bridge,
        SdkEngineDependencyHandle handle,
        JsonObject? response)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["dependency_handle"] = handle.Value,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = FinishDependencyOperation,
            ["response"] = response?.DeepClone(),
        });
        if (!ExactProperties(result, "outcome"))
        {
            throw ResponseError();
        }
        JsonElement outcomeValue = result.GetProperty("outcome");
        string? outcome = outcomeValue.ValueKind == JsonValueKind.String
            ? outcomeValue.GetString()
            : null;
        return outcome is "error" or "response" ? outcome : throw ResponseError();
    }

    internal static SdkEngineObservationStart OpenObservation(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        string observationClass,
        string? causalParentId)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["causal_parent_id"] = causalParentId,
            ["class"] = observationClass,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = OpenObservationOperation,
            ["operation_handle"] = handle.Value,
        });
        ulong observationHandle = PositiveHandle(
            result, "observation_handle", "session_position");
        if (!result.GetProperty("session_position").TryGetUInt64(out ulong sessionPosition))
        {
            throw ResponseError();
        }
        return new SdkEngineObservationStart(
            new SdkEngineObservationHandle(observationHandle), sessionPosition);
    }

    internal static void WriteObservation(
        this SdkEngineBridge bridge,
        SdkEngineObservationHandle handle,
        string stream,
        byte[] chunk)
    {
        if (chunk.Length is 0 or > SdkEngineBridge.MaxObservationChunkBytes)
        {
            throw CallError();
        }
        EmptyResult(bridge.Call(new JsonObject
        {
            ["chunk"] = EncodeBase64Url(chunk),
            ["format"] = SdkEngineBridge.CallFormat,
            ["observation_handle"] = handle.Value,
            ["operation"] = WriteObservationOperation,
            ["stream"] = stream,
        }));
    }

    internal static string DispatchObservation(
        this SdkEngineBridge bridge,
        SdkEngineObservationHandle handle)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["observation_handle"] = handle.Value,
            ["operation"] = DispatchObservationOperation,
        });
        string? action = ExactProperties(result, "action")
            ? result.GetProperty("action").GetString()
            : null;
        if (action is not ("capture" or "replay"))
        {
            throw ResponseError();
        }
        return action;
    }

    internal static SdkEngineObservationChunk ReadObservation(
        this SdkEngineBridge bridge,
        SdkEngineObservationHandle handle)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["observation_handle"] = handle.Value,
            ["operation"] = ReadObservationOperation,
        });
        if (!ExactProperties(result, "chunk", "eof") ||
            result.GetProperty("chunk").ValueKind != JsonValueKind.String ||
            result.GetProperty("eof").ValueKind is not
                (JsonValueKind.True or JsonValueKind.False))
        {
            throw ResponseError();
        }
        byte[] chunk;
        try
        {
            chunk = DecodeBase64Url(result.GetProperty("chunk").GetString()!);
        }
        catch (FormatException)
        {
            throw ResponseError();
        }
        if (chunk.Length > SdkEngineBridge.MaxObservationReadBytes)
        {
            throw ResponseError();
        }
        return new SdkEngineObservationChunk(chunk, result.GetProperty("eof").GetBoolean());
    }

    internal static void FinishObservation(
        this SdkEngineBridge bridge,
        SdkEngineObservationHandle handle,
        string outcome,
        ulong sessionPosition) => EmptyResult(bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["observation_handle"] = handle.Value,
            ["operation"] = FinishObservationOperation,
            ["outcome"] = outcome,
            ["session_position"] = sessionPosition,
        }));

    internal static void AbandonObservation(
        this SdkEngineBridge bridge,
        SdkEngineObservationHandle handle) => EmptyResult(bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["observation_handle"] = handle.Value,
            ["operation"] = AbandonObservationOperation,
        }));

    internal static void MarkOperationUnowned(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        string observationClass,
        string? causalParentId,
        byte[] evidence) => Observation(
            bridge, handle, observationClass, causalParentId, evidence);

    internal static void CloseOperationWorld(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        string completion) => EmptyResult(bridge.Call(new JsonObject
        {
            ["completion"] = completion,
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = CloseWorldOperation,
            ["operation_handle"] = handle.Value,
        }));

    internal static void SucceedOperation(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle) => OperationTerminal(
            bridge, SucceedOperationName, handle);

    internal static void AbandonOperation(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle) => OperationTerminal(
            bridge, AbandonOperationName, handle);

    internal static SdkEngineSinkHandle FailOperation(
        this SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        JsonObject failure,
        string projectToken)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["failure"] = failure.DeepClone(),
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = FailOperationName,
            ["operation_handle"] = handle.Value,
            ["project_token"] = projectToken,
        });
        return new SdkEngineSinkHandle(PositiveHandle(result, "sink_handle"));
    }

    internal static bool WaitForSink(
        this SdkEngineBridge bridge,
        SdkEngineSinkHandle handle,
        ulong timeoutMilliseconds)
    {
        JsonElement result = bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = WaitForSinkOperation,
            ["sink_handle"] = handle.Value,
            ["timeout_ms"] = timeoutMilliseconds,
        });
        if (!ExactProperties(result, "idle") ||
            result.GetProperty("idle").ValueKind is not
                (JsonValueKind.True or JsonValueKind.False))
        {
            throw ResponseError();
        }
        return result.GetProperty("idle").GetBoolean();
    }

    private static void Observation(
        SdkEngineBridge bridge,
        SdkEngineOperationHandle handle,
        string observationClass,
        string? causalParentId,
        byte[] evidence)
    {
        if (evidence.Length > SdkEngineBridge.MaxEvidenceBytes)
        {
            throw new SdkEngineBridgeException(
                "The Repro It SDK engine rejected the operation.");
        }
        EmptyResult(bridge.Call(new JsonObject
        {
            ["causal_parent_id"] = causalParentId,
            ["class"] = observationClass,
            ["evidence"] = EncodeBase64Url(evidence),
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = UnownedOperation,
            ["operation_handle"] = handle.Value,
        }));
    }

    private static void OperationTerminal(
        SdkEngineBridge bridge,
        string operation,
        SdkEngineOperationHandle handle) => EmptyResult(bridge.Call(new JsonObject
        {
            ["format"] = SdkEngineBridge.CallFormat,
            ["operation"] = operation,
            ["operation_handle"] = handle.Value,
        }));

    private static ulong PositiveHandle(JsonElement result, params string[] properties)
    {
        if (!ExactProperties(result, properties) ||
            !result.GetProperty(properties[0]).TryGetUInt64(out ulong handle) || handle == 0)
        {
            throw ResponseError();
        }
        return handle;
    }

    private static void EmptyResult(JsonElement result)
    {
        if (result.ValueKind != JsonValueKind.Object || result.EnumerateObject().Any())
        {
            throw ResponseError();
        }
    }

    private static bool ExactProperties(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        string[] actual = value.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return actual.SequenceEqual(expected.Order(StringComparer.Ordinal));
    }

    private static SdkEngineBridgeException ResponseError() => new(
        "The Repro It SDK engine returned an invalid response.");

    private static SdkEngineBridgeException CallError() => new(
        "The Repro It SDK engine rejected the operation.");

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 0 => "", 2 => "==", 3 => "=", _ => "!" };
        return Convert.FromBase64String(padded);
    }
}
