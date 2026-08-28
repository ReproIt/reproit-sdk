using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal interface INativeSdkEngine
{
    uint AbiVersion();

    nint Call(byte[] input, byte[] output);

    void Close()
    {
    }
}

internal sealed class SdkEngineBridge : IDisposable
{
    internal const string AbiContractDigest =
        "sha256:72e11b757a7a8e7d76b445001801acc349bc051b041d2e77ed784e731a60eb78";
    internal const uint AbiVersion = 1;
    internal const int MaxEvidenceBytes = 785_408;
    internal const int MaxObservationAdapters = 7;
    internal const int MaxObservationChunkBytes = 32_768;
    internal const int MaxObservationReadBytes = 8_192;
    internal const int MaxObservationSessions = 1_024;
    internal const int MaxObservationSessionsPerOperation = 64;
    internal const int MaxSemanticDependencyRecordBytes = 65_536;
    internal const int MaxSinkWaiters = 16;
    internal const ulong SinkWaitMilliseconds = 1_800_000;
    internal const int OutputCapacity = 16_384;
    internal const int MaxCallBytes = 1_048_576;
    internal const string ContractRequest =
        "{\"format\":\"reproit.sdk-engine-call.v1\",\"operation\":\"contract\"}";
    internal const string CallFormat = "reproit.sdk-engine-call.v1";
    internal const string AbiVersionSymbol = "reproit_sdk_engine_abi_version";
    internal const string CallSymbol = "reproit_sdk_engine_call";

    private const string ResponseFormat = "reproit.sdk-engine-response.v1";
    internal static IReadOnlyList<AutomaticObservationClass> RequiredObservationClasses { get; } =
        Array.AsReadOnly(new[]
        {
            AutomaticObservationClass.Clock,
            AutomaticObservationClass.Database,
            AutomaticObservationClass.Environment,
            AutomaticObservationClass.Filesystem,
            AutomaticObservationClass.OutboundHttp,
            AutomaticObservationClass.Queue,
            AutomaticObservationClass.Randomness,
        });
    private bool closed;
    private readonly INativeSdkEngine native;
    private readonly object stateLock = new();

    private SdkEngineBridge(INativeSdkEngine nativeEngine)
    {
        native = nativeEngine;
    }

    internal static SdkEngineBridge OpenPackaged() => Open(() =>
        new PInvokeSdkEngine(SdkEnginePackage.LibraryPath()));

    internal static SdkEngineBridge Open(Func<INativeSdkEngine> load)
    {
        try
        {
            INativeSdkEngine native = load();
            if (native.AbiVersion() != AbiVersion)
            {
                throw AbiError();
            }
            return new SdkEngineBridge(native);
        }
        catch (SdkEngineBridgeException)
        {
            throw;
        }
        catch (Exception)
        {
            throw Unavailable();
        }
    }

    internal uint Contract()
    {
        JsonElement result = CallBytes(Encoding.UTF8.GetBytes(ContractRequest));
        JsonNode? actual = JsonNode.Parse(result.GetRawText());
        if (!JsonNode.DeepEquals(actual, ExpectedContract()))
        {
            throw ResponseError();
        }
        return AbiVersion;
    }

    internal static JsonObject ExpectedContract()
    {
        JsonArray operations = [];
        foreach (string operation in SdkEngineOperations.OperationNames)
        {
            operations.Add(operation);
        }
        JsonArray requiredObservationClasses = [];
        foreach (AutomaticObservationClass observationClass in RequiredObservationClasses)
        {
            requiredObservationClasses.Add(AutomaticOperation.ObservationClass(observationClass));
        }
        return new JsonObject
        {
            ["abi_version"] = AbiVersion,
            ["dependency_contract"] = new JsonObject
            {
                ["finish_fields"] = new JsonArray("dependency_handle", "response"),
                ["finish_result_fields"] = new JsonArray("outcome"),
                ["open_fields"] = new JsonArray(
                    "causal_parent_id", "operation_handle", "request"),
                ["open_result_fields"] = new JsonArray("action", "dependency_handle"),
                ["replay_read_operation"] = "observation-read",
                ["request_fields"] = new JsonArray(
                    "encoding", "metadata", "method", "observation_class", "operation",
                    "payload", "protocol", "target"),
                ["response_fields"] = new JsonArray(
                    "error_code", "error_number", "metadata", "outcome", "payload", "status",
                    "status_code"),
            },
            ["error_behavior"] = new JsonObject
            {
                ["json_error"] = new JsonObject
                {
                    ["error_code_source"] = "reproit-core-v1",
                    ["includes_message"] = false,
                    ["includes_request"] = false,
                    ["maximum_bytes"] = 256,
                    ["result"] = new JsonObject(),
                },
                ["native_failures"] = new JsonArray
                {
                    NativeFailure(-4, "response-length-overflow"),
                    NativeFailure(-3, "output-capacity-exceeded"),
                    NativeFailure(-2, "engine-panic"),
                    NativeFailure(-1, "invalid-call-boundary"),
                },
                ["success"] = "response-byte-count",
            },
            ["format"] = "reproit.sdk-engine-abi.v1",
            ["libraries"] = new JsonArray
            {
                Library(SdkEnginePackage.LinuxLibrary, "linux-arm64"),
                Library(SdkEnginePackage.LinuxLibrary, "linux-x86_64"),
                Library(SdkEnginePackage.MacOSLibrary, "macos-arm64"),
                Library(SdkEnginePackage.WindowsLibrary, "windows-x86_64"),
            },
            ["limits"] = new JsonObject
            {
                ["engines"] = 64,
                ["evidence_bytes"] = MaxEvidenceBytes,
                ["observation_adapters"] = MaxObservationAdapters,
                ["observation_chunk_bytes"] = MaxObservationChunkBytes,
                ["observation_response_read_bytes"] = MaxObservationReadBytes,
                ["observation_sessions"] = MaxObservationSessions,
                ["observation_sessions_per_operation"] = MaxObservationSessionsPerOperation,
                ["operations"] = 512,
                ["semantic_dependency_record_bytes"] = MaxSemanticDependencyRecordBytes,
                ["sink_wait_ms"] = SinkWaitMilliseconds,
                ["sinks"] = MaxSinkWaiters,
            },
            ["operations"] = operations,
            ["observation_actions"] = new JsonArray("capture", "replay"),
            ["observation_contract"] = new JsonObject
            {
                ["adapter_implementation_binding"] = new JsonArray(
                    "subject-module-digest"),
                ["adapter_registration_fields"] = new JsonArray(
                    "adapter_id", "adapter_version", "class", "implementation_digest"),
                ["finish_fields"] = new JsonArray(
                    "observation_handle", "outcome", "session_position"),
                ["open_fields"] = new JsonArray(
                    "causal_parent_id", "class", "operation_handle"),
                ["open_result_fields"] = new JsonArray(
                    "observation_handle", "session_position"),
                ["read_result_fields"] = new JsonArray("chunk", "eof"),
                ["write_fields"] = new JsonArray("chunk", "observation_handle", "stream"),
            },
            ["request"] = new JsonObject
            {
                ["format"] = CallFormat,
                ["maximum_bytes"] = MaxCallBytes,
            },
            ["required_observation_classes"] = requiredObservationClasses,
            ["response"] = new JsonObject
            {
                ["format"] = ResponseFormat,
                ["output_capacity_bytes"] = OutputCapacity,
            },
            ["symbols"] = new JsonObject
            {
                ["abi_version"] = AbiVersionSymbol,
                ["call"] = CallSymbol,
            },
        };
    }

    private static JsonObject Library(string name, string platform) => new()
    {
        ["name"] = name,
        ["platform"] = platform,
    };

    private static JsonObject NativeFailure(int code, string condition) => new()
    {
        ["code"] = code,
        ["condition"] = condition,
        ["output_written"] = false,
    };

    public void Dispose()
    {
        lock (stateLock)
        {
            if (closed)
            {
                return;
            }
            closed = true;
            try
            {
                native.Close();
            }
            catch (Exception)
            {
                // Native unload failure must not change application behavior.
            }
        }
    }

    internal JsonElement Call(JsonObject request)
    {
        byte[] input;
        try
        {
            input = Encoding.UTF8.GetBytes(request.ToJsonString());
        }
        catch (Exception error) when (error is InvalidOperationException or JsonException)
        {
            throw CallError();
        }
        if (input.Length > MaxCallBytes)
        {
            throw CallError();
        }
        return CallBytes(input);
    }

    private JsonElement CallBytes(byte[] input)
    {
        if (input.Length > MaxCallBytes)
        {
            throw CallError();
        }
        byte[] output = new byte[OutputCapacity];
        nint written;
        lock (stateLock)
        {
            if (closed)
            {
                throw Unavailable();
            }
            try
            {
                written = native.Call(input, output);
            }
            catch (Exception error) when (error is DllNotFoundException or
                EntryPointNotFoundException or BadImageFormatException)
            {
                throw Unavailable();
            }
        }
        if (written < 0 || written > OutputCapacity)
        {
            throw ResponseError();
        }
        return ParseResponse(output.AsMemory(0, checked((int)written)));
    }

    private static JsonElement ParseResponse(ReadOnlyMemory<byte> value)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(value);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !ExactProperties(root, "error_code", "format", "ok", "result") ||
                root.GetProperty("format").GetString() != ResponseFormat)
            {
                throw ResponseError();
            }
            JsonElement ok = root.GetProperty("ok");
            if (ok.ValueKind == JsonValueKind.False)
            {
                return ParseError(root);
            }
            if (ok.ValueKind != JsonValueKind.True ||
                root.GetProperty("error_code").ValueKind != JsonValueKind.Null)
            {
                throw ResponseError();
            }
            JsonElement result = root.GetProperty("result");
            if (result.ValueKind != JsonValueKind.Object)
            {
                throw ResponseError();
            }
            return result.Clone();
        }
        catch (SdkEngineBridgeException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or
            KeyNotFoundException)
        {
            throw ResponseError();
        }
    }

    private static JsonElement ParseError(JsonElement root)
    {
        JsonElement errorCode = root.GetProperty("error_code");
        JsonElement result = root.GetProperty("result");
        string? code = errorCode.ValueKind == JsonValueKind.String ? errorCode.GetString() : null;
        if (root.GetProperty("ok").ValueKind != JsonValueKind.False ||
            string.IsNullOrEmpty(code) || code.Length > 128 ||
            result.ValueKind != JsonValueKind.Object || result.EnumerateObject().Any())
        {
            throw ResponseError();
        }
        throw CallError();
    }

    private static bool ExactProperties(JsonElement value, params string[] expected)
    {
        string[] actual = value.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return actual.SequenceEqual(expected.Order(StringComparer.Ordinal));
    }

    private static SdkEngineBridgeException Unavailable() => new(
        "The Repro It SDK engine is unavailable.");

    private static SdkEngineBridgeException AbiError() => new(
        "The Repro It SDK engine ABI is not compatible.");

    private static SdkEngineBridgeException CallError() => new(
        "The Repro It SDK engine rejected the operation.");

    private static SdkEngineBridgeException ResponseError() => new(
        "The Repro It SDK engine returned an invalid response.");
}

internal sealed class SdkEngineBridgeException(string message) : Exception(message);

internal sealed class PInvokeSdkEngine : INativeSdkEngine
{
    private readonly AbiVersionDelegate abiVersion;
    private readonly CallDelegate call;
    private nint library;

    internal PInvokeSdkEngine(string libraryPath)
    {
        library = NativeLibrary.Load(libraryPath);
        try
        {
            abiVersion = Marshal.GetDelegateForFunctionPointer<AbiVersionDelegate>(
                NativeLibrary.GetExport(library, SdkEngineBridge.AbiVersionSymbol));
            call = Marshal.GetDelegateForFunctionPointer<CallDelegate>(
                NativeLibrary.GetExport(library, SdkEngineBridge.CallSymbol));
        }
        catch
        {
            NativeLibrary.Free(library);
            library = 0;
            throw;
        }
    }

    public uint AbiVersion() => abiVersion();

    public nint Call(byte[] input, byte[] output) => call(
        input, checked((nuint)input.Length), output, checked((nuint)output.Length));

    public void Close()
    {
        if (library != 0)
        {
            NativeLibrary.Free(library);
            library = 0;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint AbiVersionDelegate();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nint CallDelegate(
        [In]
        byte[] input,
        nuint inputLength,
        [Out]
        byte[] output,
        nuint outputCapacity);
}
