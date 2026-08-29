using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class SdkEngineBridgeConformance
{
    internal static void Run()
    {
        AcceptsVersionOneAndTheContract();
        RejectsChangedRequiredObservationClasses();
        RealEngineContractWhenSupplied();
        RejectsMissingLibraryWithoutDetails();
        RejectsMalformedResponse();
        RejectsResponseAboveBound();
        DoesNotEchoSecretResponseBytes();
        CallsTypedOperations();
        BoundsObservationChunksAndAcceptsReplayEof();
        BoundsOperationErrors();
        RejectsOversizedOperationBeforeNativeCall();
        RejectsMalformedTypedResult();
        VerifiesExactPackagedArtifact();
        RejectsPackageMismatchAndLinks();
        RejectsPackageManifestExtras();
        MatchesCanonicalAbiContract();
    }

    private static void RealEngineContractWhenSupplied()
    {
        string? libraryPath = Environment.GetEnvironmentVariable(
            "REPROIT_TEST_SDK_ENGINE_LIBRARY");
        if (string.IsNullOrEmpty(libraryPath))
        {
            return;
        }
        using SdkEngineBridge bridge = SdkEngineBridge.Open(
            () => new PInvokeSdkEngine(libraryPath));
        Require(
            bridge.Contract() == SdkEngineBridge.AbiVersion,
            "The real SDK engine contract does not match the .NET bridge.");
    }

    private static void AcceptsVersionOneAndTheContract()
    {
        FakeNative native = new(SdkEngineBridge.AbiVersion, (input, output) =>
        {
            Require(
                Encoding.UTF8.GetString(input) == SdkEngineBridge.ContractRequest,
                "The .NET SDK engine bridge changed the contract request.");
            Require(
                output.Length == SdkEngineBridge.OutputCapacity,
                "The .NET SDK engine bridge changed the response bound.");
            return Write(output, Success(SdkEngineBridge.ExpectedContract().ToJsonString()));
        });
        SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        Require(
            bridge.Contract() == SdkEngineBridge.AbiVersion,
            "The .NET SDK engine bridge rejected ABI version 1.");
    }

    private static void RejectsMissingLibraryWithoutDetails()
    {
        SdkEngineBridgeException error = ExpectError(() =>
            SdkEngineBridge.Open(() => throw new DllNotFoundException("private loader detail")));
        Require(
            error.Message == "The Repro It SDK engine is unavailable." &&
            !error.Message.Contains("private", StringComparison.Ordinal),
            "The .NET SDK engine bridge exposed a loader detail.");
    }

    private static void RejectsChangedRequiredObservationClasses()
    {
        foreach (string change in new[] { "missing", "reordered", "added", "removed" })
        {
            JsonObject contract = (JsonObject)SdkEngineBridge.ExpectedContract().DeepClone();
            JsonArray classes = contract["required_observation_classes"]!.AsArray();
            switch (change)
            {
                case "missing":
                    contract.Remove("required_observation_classes");
                    break;
                case "reordered":
                    JsonNode first = classes[0]!.DeepClone();
                    classes[0] = classes[1]!.DeepClone();
                    classes[1] = first;
                    break;
                case "added":
                    classes.Add("extra");
                    break;
                case "removed":
                    classes.RemoveAt(classes.Count - 1);
                    break;
            }
            _ = ExpectError(() => ContractErrorResponse(contract));
        }
    }

    private static void ContractErrorResponse(JsonObject contract)
    {
        FakeNative native = new(SdkEngineBridge.AbiVersion, (_, output) =>
            Write(output, Success(contract.ToJsonString())));
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        _ = bridge.Contract();
    }

    private static void RejectsMalformedResponse()
    {
        SdkEngineBridgeException error = ContractError("{\"ok\":true", null);
        Require(
            error.Message == "The Repro It SDK engine returned an invalid response.",
            "The .NET SDK engine bridge accepted malformed JSON.");
    }

    private static void RejectsResponseAboveBound()
    {
        SdkEngineBridgeException error = ContractError(
            "", SdkEngineBridge.OutputCapacity + 1);
        Require(
            error.Message == "The Repro It SDK engine returned an invalid response.",
            "The .NET SDK engine bridge accepted an oversized response.");
    }

    private static void DoesNotEchoSecretResponseBytes()
    {
        const string Secret = "secret-value-that-must-not-escape";
        SdkEngineBridgeException error = ContractError(Secret, null);
        Require(
            !error.Message.Contains(Secret, StringComparison.Ordinal),
            "The .NET SDK engine bridge exposed response bytes in an error.");
    }

    private static void CallsTypedOperations()
    {
        string[] expectedOperations =
        [
            "engine-open", "operation-begin", "operation-input", "observation-open",
            "observation-write", "observation-dispatch", "observation-write",
            "observation-finish", "observation-open", "observation-abandon",
            "operation-unowned", "operation-close-world", "operation-succeed",
            "operation-abandon", "operation-fail", "sink-wait", "engine-close",
        ];
        List<string> operations = [];
        FakeNative native = new(SdkEngineBridge.AbiVersion, (input, output) =>
        {
            using JsonDocument document = JsonDocument.Parse(input);
            JsonElement request = document.RootElement;
            string operation = request.GetProperty("operation").GetString()!;
            operations.Add(operation);
            Require(
                request.GetProperty("format").GetString() == SdkEngineBridge.CallFormat,
                "The typed .NET SDK engine request has the wrong format.");
            string result = operation switch
            {
                "engine-open" => EngineOpenResult(request),
                "operation-begin" =>
                    "{\"operation_handle\":12,\"operation_id\":\"op_test\"}",
                "observation-open" =>
                    "{\"observation_handle\":14,\"session_position\":0}",
                "observation-dispatch" => "{\"action\":\"capture\"}",
                "operation-unowned" => ObservationResult(request, "op_parent", ""),
                "operation-fail" => FailureResult(request),
                "sink-wait" => SinkWaitResult(request),
                _ => "{}",
            };
            return Write(output, Success(result));
        });
        SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        SdkEngineHandle engineHandle = bridge.OpenEngine(new SdkEngineOpenOptions(
            "repository",
            "project",
            "dotnet",
            "revision",
            [],
            [new SdkEngineSubjectObject("sha256:digest", "/subject", 7)]));
        Require(engineHandle.Value == 11, "The typed engine-open response was not accepted.");
        SdkEngineOperationStart start = bridge.BeginOperation(engineHandle, []);
        Require(
            start.Handle.Value == 12 && start.OperationId == "op_test",
            "The typed operation-begin response was not accepted.");
        bridge.RecordInput(start.Handle, []);
        SdkEngineObservationStart observation = bridge.OpenObservation(
            start.Handle, "outbound-http", null);
        Require(
            observation.Handle.Value == 14 && observation.SessionPosition == 0,
            "The typed observation-open response was not accepted.");
        bridge.WriteObservation(observation.Handle, "request", [0xfb, 0xff]);
        Require(
            bridge.DispatchObservation(observation.Handle) == "capture",
            "The typed observation-dispatch response was not accepted.");
        bridge.WriteObservation(observation.Handle, "response", Encoding.UTF8.GetBytes("response"));
        bridge.FinishObservation(
            observation.Handle, "response", observation.SessionPosition);
        SdkEngineObservationStart abandoned = bridge.OpenObservation(
            start.Handle, "database", null);
        bridge.AbandonObservation(abandoned.Handle);
        bridge.MarkOperationUnowned(start.Handle, "database", "op_parent", []);
        bridge.CloseOperationWorld(start.Handle, "complete");
        bridge.SucceedOperation(start.Handle);
        bridge.AbandonOperation(start.Handle);
        SdkEngineSinkHandle sink = bridge.FailOperation(start.Handle, [], "project-token");
        Require(sink.Value == 13, "The typed operation-fail response was not accepted.");
        Require(bridge.WaitForSink(sink, 250), "The typed sink-wait response was not accepted.");
        bridge.CloseEngine(engineHandle);
        Require(
            operations.SequenceEqual(expectedOperations),
            "The typed .NET SDK engine operation order changed.");
    }

    private static string EngineOpenResult(JsonElement request)
    {
        Require(
            request.GetProperty("sdk").GetString() == "dotnet" &&
            !request.GetProperty("observation_adapters").EnumerateArray().Any(),
            "The engine-open request lost its SDK.");
        return "{\"engine_handle\":11}";
    }

    private static string ObservationResult(
        JsonElement request,
        string? expectedParent,
        string expectedEvidence)
    {
        JsonElement parent = request.GetProperty("causal_parent_id");
        bool validParent = expectedParent is null
            ? parent.ValueKind == JsonValueKind.Null
            : parent.GetString() == expectedParent;
        Require(
            validParent && request.GetProperty("evidence").GetString() == expectedEvidence,
            "The observation request changed its evidence or causal parent.");
        return "{}";
    }

    private static string FailureResult(JsonElement request)
    {
        Require(
            request.GetProperty("project_token").GetString() == "project-token",
            "The failure request lost its project token.");
        return "{\"sink_handle\":13}";
    }

    private static string SinkWaitResult(JsonElement request)
    {
        Require(
            request.GetProperty("timeout_ms").GetUInt64() == 250,
            "The sink wait request changed its timeout.");
        return "{\"idle\":true}";
    }

    private static void BoundsOperationErrors()
    {
        const string Secret = "project-token-that-must-not-escape";
        SdkEngineBridge bridge = OperationBridge((_, output) => Write(
            output,
            "{\"error_code\":\"schema_invalid\",\"format\":\"" +
            "reproit.sdk-engine-response.v1\",\"ok\":false,\"result\":{}}"));
        SdkEngineBridgeException error = ExpectError(() =>
            bridge.FailOperation(new SdkEngineOperationHandle(1), [], Secret));
        Require(
            error.Message == "The Repro It SDK engine rejected the operation." &&
            !error.Message.Contains(Secret, StringComparison.Ordinal) &&
            !error.Message.Contains("schema_invalid", StringComparison.Ordinal),
            "The .NET SDK engine operation error exposed engine or request data.");
    }

    private static void BoundsObservationChunksAndAcceptsReplayEof()
    {
        int calls = 0;
        SdkEngineBridge bridge = OperationBridge((input, output) =>
        {
            calls += 1;
            using JsonDocument document = JsonDocument.Parse(input);
            string? operation = document.RootElement.GetProperty("operation").GetString();
            string result = operation == SdkEngineOperations.ReadObservationOperation
                ? "{\"chunk\":\"cmVwbGF5\",\"eof\":true}"
                : "{}";
            return Write(output, Success(result));
        });
        SdkEngineObservationHandle handle = new(1);
        bridge.WriteObservation(
            handle, "request", new byte[SdkEngineBridge.MaxObservationChunkBytes]);
        int before = calls;
        _ = ExpectError(() => bridge.WriteObservation(
            handle, "request", new byte[SdkEngineBridge.MaxObservationChunkBytes + 1]));
        Require(calls == before, "The .NET bridge sent an observation chunk above the limit.");
        SdkEngineObservationChunk read = bridge.ReadObservation(handle);
        Require(
            Encoding.UTF8.GetString(read.Chunk) == "replay" && read.Eof,
            "The .NET bridge rejected a bounded replay EOF.");
        string oversized = Convert.ToBase64String(
            new byte[SdkEngineBridge.MaxObservationReadBytes + 1])
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        SdkEngineBridge oversizedBridge = OperationBridge((_, output) => Write(
            output,
            Success($"{{\"chunk\":\"{oversized}\",\"eof\":true}}")));
        _ = ExpectError(() => oversizedBridge.ReadObservation(handle));
    }

    private static void RejectsOversizedOperationBeforeNativeCall()
    {
        bool called = false;
        SdkEngineBridge bridge = OperationBridge((_, _) =>
        {
            called = true;
            return 0;
        });
        SdkEngineBridgeException error = ExpectError(() => bridge.OpenEngine(
            new SdkEngineOpenOptions(
                "",
                new string('x', SdkEngineBridge.MaxCallBytes),
                "dotnet",
                "",
                [],
                [])));
        Require(
            error.Message == "The Repro It SDK engine rejected the operation." && !called,
            "The .NET SDK engine bridge sent an oversized operation to native code.");
    }

    private static void RejectsMalformedTypedResult()
    {
        SdkEngineBridge bridge = OperationBridge((_, output) =>
            Write(output, Success("{\"engine_handle\":0}")));
        SdkEngineBridgeException error = ExpectError(() => bridge.OpenEngine(
            new SdkEngineOpenOptions("", "", "dotnet", "", [], [])));
        Require(
            error.Message == "The Repro It SDK engine returned an invalid response.",
            "The .NET SDK engine bridge accepted an invalid typed handle.");
    }

    private static SdkEngineBridge OperationBridge(Func<byte[], byte[], nint> call) =>
        SdkEngineBridge.Open(() => new FakeNative(SdkEngineBridge.AbiVersion, call));

    private static string Success(string result) =>
        "{\"error_code\":null,\"format\":\"reproit.sdk-engine-response.v1\"," +
        "\"ok\":true,\"result\":" + result + "}";

    private static void VerifiesExactPackagedArtifact()
    {
        using TestDirectory directory = new();
        string library = WritePackage(directory.Path, Encoding.UTF8.GetBytes("exact engine bytes"));
        Require(
            SdkEnginePackage.LibraryPathAt(directory.Path, "linux-x86_64") == library,
            "The .NET SDK engine package rejected its exact artifact.");
    }

    private static void RejectsPackageMismatchAndLinks()
    {
        using TestDirectory directory = new();
        string library = WritePackage(directory.Path, Encoding.UTF8.GetBytes("exact engine bytes"));
        File.WriteAllBytes(library, Encoding.UTF8.GetBytes("changed engine bytes"));
        ExpectError(() => SdkEnginePackage.LibraryPathAt(directory.Path, "linux-x86_64"));

        using TestDirectory linkedDirectory = new();
        library = WritePackage(linkedDirectory.Path, Encoding.UTF8.GetBytes("exact engine bytes"));
        string realLibrary = library + ".real";
        File.Move(library, realLibrary);
        try
        {
            File.CreateSymbolicLink(library, realLibrary);
        }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException)
        {
            return;
        }
        ExpectError(() => SdkEnginePackage.LibraryPathAt(
            linkedDirectory.Path, "linux-x86_64"));
    }

    private static void RejectsPackageManifestExtras()
    {
        using TestDirectory directory = new();
        string library = WritePackage(directory.Path, Encoding.UTF8.GetBytes("exact engine bytes"));
        string manifest = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(library)!, SdkEnginePackage.ArtifactManifestName);
        string value = File.ReadAllText(manifest).Replace(
            "\"target\":", "\"extra\":true,\"target\":", StringComparison.Ordinal);
        File.WriteAllText(manifest, value);
        ExpectError(() => SdkEnginePackage.LibraryPathAt(directory.Path, "linux-x86_64"));
    }

    private static void MatchesCanonicalAbiContract()
    {
        string path = CanonicalAbiPath();
        byte[] value = File.ReadAllBytes(path);
        Require(
            $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}" ==
                SdkEngineBridge.AbiContractDigest,
            "The .NET SDK engine ABI digest differs from the canonical contract.");
        using JsonDocument document = JsonDocument.Parse(value);
        JsonElement abi = document.RootElement;
        JsonNode? canonical = JsonNode.Parse(value);
        Require(
            JsonNode.DeepEquals(canonical, SdkEngineBridge.ExpectedContract()),
            "The .NET SDK engine bridge does not validate the complete canonical ABI.");
        Dictionary<string, string> libraries = abi.GetProperty("libraries")
            .EnumerateArray()
            .ToDictionary(
                library => library.GetProperty("platform").GetString()!,
                library => library.GetProperty("name").GetString()!,
                StringComparer.Ordinal);
        Dictionary<string, string> expectedLibraries = new(StringComparer.Ordinal)
        {
            ["linux-arm64"] = SdkEnginePackage.LinuxLibrary,
            ["linux-x86_64"] = SdkEnginePackage.LinuxLibrary,
            ["macos-arm64"] = SdkEnginePackage.MacOSLibrary,
            ["windows-x86_64"] = SdkEnginePackage.WindowsLibrary,
        };
        string[] operations = abi.GetProperty("operations")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToArray();
        string[] requiredObservationClasses = abi.GetProperty("required_observation_classes")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToArray();
        Require(
            abi.GetProperty("abi_version").GetUInt32() == SdkEngineBridge.AbiVersion &&
            abi.GetProperty("limits").GetProperty("evidence_bytes").GetInt32() ==
                SdkEngineBridge.MaxEvidenceBytes &&
            abi.GetProperty("limits").GetProperty("sinks").GetInt32() ==
                SdkEngineBridge.MaxSinkWaiters &&
            abi.GetProperty("limits").GetProperty("sink_wait_ms").GetUInt64() ==
                SdkEngineBridge.SinkWaitMilliseconds &&
            abi.GetProperty("request").GetProperty("format").GetString() ==
                SdkEngineBridge.CallFormat &&
            abi.GetProperty("request").GetProperty("maximum_bytes").GetInt32() ==
                SdkEngineBridge.MaxCallBytes &&
            abi.GetProperty("response").GetProperty("format").GetString() ==
                "reproit.sdk-engine-response.v1" &&
            abi.GetProperty("response").GetProperty("output_capacity_bytes").GetInt32() ==
                SdkEngineBridge.OutputCapacity &&
            abi.GetProperty("symbols").GetProperty("abi_version").GetString() ==
                SdkEngineBridge.AbiVersionSymbol &&
            abi.GetProperty("symbols").GetProperty("call").GetString() ==
                SdkEngineBridge.CallSymbol &&
            abi.GetProperty("symbols").GetProperty("capture_probe").GetString() ==
                SdkEngineBridge.CaptureProbeSymbol &&
            requiredObservationClasses.SequenceEqual(
                SdkEngineBridge.RequiredObservationClasses.Select(
                    AutomaticOperation.ObservationClass)) &&
            operations.SequenceEqual(SdkEngineOperations.OperationNames) &&
            libraries.OrderBy(entry => entry.Key).SequenceEqual(
                expectedLibraries.OrderBy(entry => entry.Key)),
            "The .NET SDK engine bridge differs from the canonical ABI contract.");
    }

    private static string CanonicalAbiPath()
    {
        string? configured = Environment.GetEnvironmentVariable("REPROIT_SDK_ENGINE_ABI");
        if (!string.IsNullOrEmpty(configured))
        {
            return configured;
        }
        DirectoryInfo? directory = new(Environment.CurrentDirectory);
        while (directory is not null)
        {
            string candidate = System.IO.Path.Combine(
                directory.FullName,
                "crates",
                "reproit-sdk-engine",
                "sdk-engine-abi.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            directory = directory.Parent;
        }
        throw new InvalidOperationException("The canonical SDK engine ABI is unavailable.");
    }

    private static string WritePackage(string root, byte[] library)
    {
        string targetDirectory = System.IO.Path.Combine(
            root, SdkEnginePackage.PackageDirectory, "linux-x86_64");
        Directory.CreateDirectory(targetDirectory);
        string libraryPath = System.IO.Path.Combine(
            targetDirectory, SdkEnginePackage.LinuxLibrary);
        File.WriteAllBytes(libraryPath, library);
        string digest = "sha256:" +
            Convert.ToHexString(SHA256.HashData(library)).ToLowerInvariant();
        JsonObject manifest = new()
        {
            ["abi_contract_digest"] = SdkEngineBridge.AbiContractDigest,
            ["artifacts"] = new JsonArray
            {
                new JsonObject
                {
                    ["digest"] = digest,
                    ["file"] = SdkEnginePackage.LinuxLibrary,
                    ["role"] = "engine",
                    ["size"] = library.Length,
                },
            },
            ["format"] = SdkEnginePackage.ArtifactManifestFormat,
            ["target"] = "linux-x86_64",
        };
        File.WriteAllText(
            System.IO.Path.Combine(targetDirectory, SdkEnginePackage.ArtifactManifestName),
            manifest.ToJsonString());
        return libraryPath;
    }

    private static SdkEngineBridgeException ContractError(string response, int? returned)
    {
        FakeNative native = new(SdkEngineBridge.AbiVersion, (_, output) =>
        {
            nint written = Write(output, response);
            return returned ?? written;
        });
        SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        return ExpectError(() => bridge.Contract());
    }

    private static nint Write(byte[] output, string value)
    {
        byte[] encoded = Encoding.UTF8.GetBytes(value);
        encoded.AsSpan(0, Math.Min(encoded.Length, output.Length)).CopyTo(output);
        return encoded.Length;
    }

    private static SdkEngineBridgeException ExpectError(Action operation)
    {
        try
        {
            operation();
        }
        catch (SdkEngineBridgeException error)
        {
            return error;
        }
        throw new InvalidOperationException("The .NET SDK engine bridge accepted invalid input.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeNative(
        uint version,
        Func<byte[], byte[], nint> call) : INativeSdkEngine
    {
        public uint AbiVersion() => version;

        public nint Call(byte[] input, byte[] output) => call(input, output);
    }

    private sealed class TestDirectory : IDisposable
    {
        internal TestDirectory()
        {
            Path = System.IO.Path.Combine(
                Environment.CurrentDirectory,
                ".sdk-engine-conformance",
                System.IO.Path.GetRandomFileName());
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
