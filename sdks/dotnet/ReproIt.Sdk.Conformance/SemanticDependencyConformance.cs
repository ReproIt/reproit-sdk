using System.Text;
using System.Text.Json.Nodes;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class SemanticDependencyConformance
{
    internal static void Run()
    {
        BridgeUsesExactCallShape();
        CapturePreservesLiveSuccessAndError();
        CaptureFailuresPreserveLiveResult();
        ReplayReadsChunksAfterEngineValidation();
        ReplayUsesEngineValidatedOutcome();
        ReplayNeverFallsBackToLive();
    }

    private static void BridgeUsesExactCallShape()
    {
        List<JsonObject> calls = [];
        FakeNative native = new(call =>
        {
            calls.Add((JsonObject)call.DeepClone());
            string operation = call["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "dependency-open" => new()
                {
                    ["action"] = "capture",
                    ["dependency_handle"] = 41,
                },
                "dependency-finish" => new() { ["outcome"] = "response" },
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        JsonObject request = new()
        {
            ["encoding"] = "bytes",
            ["metadata"] = new JsonArray
            {
                new JsonObject { ["name"] = "eC10YWc", ["value"] = "Zmlyc3Q" },
                new JsonObject { ["name"] = "eC10YWc", ["value"] = "c2Vjb25k" },
            },
            ["method"] = null,
            ["observation_class"] = "database",
            ["operation"] = "database-execute",
            ["payload"] = "cGF5bG9hZA",
            ["protocol"] = "test-protocol",
            ["target"] = "dGFyZ2V0",
        };
        SdkEngineDependencyStart started = bridge.OpenDependency(
            new SdkEngineOperationHandle(7), "op_parent", request);
        string outcome = bridge.FinishDependency(started.Handle, new JsonObject
        {
            ["error_code"] = null,
            ["error_number"] = null,
            ["metadata"] = new JsonArray(),
            ["outcome"] = "response",
            ["payload"] = "",
            ["status"] = null,
            ["status_code"] = null,
        });
        Require(
            started.Action == "capture" && started.Handle.Value == 41 && outcome == "response",
            "The .NET dependency bridge rejected a valid result.");
        JsonObject open = calls[0];
        JsonObject sentRequest = open["request"]!.AsObject();
        JsonArray metadata = sentRequest["metadata"]!.AsArray();
        Require(
            HasExactly(open,
                "causal_parent_id", "format", "operation", "operation_handle", "request") &&
            HasExactly(sentRequest,
                "encoding", "metadata", "method", "observation_class", "operation", "payload",
                "protocol", "target") &&
            open["causal_parent_id"]!.GetValue<string>() == "op_parent" &&
            metadata[0]!["value"]!.GetValue<string>() == "Zmlyc3Q" &&
            metadata[1]!["value"]!.GetValue<string>() == "c2Vjb25k" &&
            HasExactly(calls[1], "dependency_handle", "format", "operation", "response"),
            "The .NET dependency bridge changed its exact shape or metadata order.");
    }

    private static void CapturePreservesLiveSuccessAndError()
    {
        foreach (ObservationOutcome outcome in new[]
            { ObservationOutcome.Response, ObservationOutcome.Error })
        {
            List<string> calls = [];
            FakeNative native = DependencyNative("capture", null, call =>
            {
                string operation = call["operation"]!.GetValue<string>();
                if (operation is "dependency-open" or "dependency-finish")
                {
                    calls.Add(operation);
                }
                return operation == "dependency-finish"
                    ? Success(new JsonObject
                    {
                        ["outcome"] = outcome == ObservationOutcome.Response
                            ? "response"
                            : "error",
                    })
                    : null;
            });
            using OperationFixture fixture = new(native);
            SemanticDependencyResponse response = TestResponse(outcome);
            InvalidOperationException? sentinel = outcome == ObservationOutcome.Error
                ? new InvalidOperationException("sentinel dependency error")
                : null;
            int liveCalls = 0;
            try
            {
                SemanticDependencyResponse actual = SemanticDependencyTranslator.Translate(
                    fixture.Operation,
                    TestRequest(),
                    null,
                    () =>
                    {
                        liveCalls += 1;
                        return new SemanticDependencyLiveResult(response, sentinel);
                    });
                Require(
                    sentinel is null && ReferenceEquals(actual, response),
                    "Capture changed the exact live success result.");
            }
            catch (InvalidOperationException error)
            {
                Require(
                    ReferenceEquals(error, sentinel),
                    "Capture changed the exact live exception.");
            }
            Require(
                liveCalls == 1 && calls.SequenceEqual(
                    new[] { "dependency-open", "dependency-finish" }),
                "Capture changed the live call count or engine sequence.");
        }
    }

    private static void CaptureFailuresPreserveLiveResult()
    {
        (string Name, string? Failure, bool OversizedRequest, bool OversizedResponse)[] cases =
        [
            ("request conversion", null, true, false),
            ("dependency open", "dependency-open", false, false),
            ("response conversion", null, false, true),
            ("dependency finish", "dependency-finish", false, false),
        ];
        foreach ((string name, string? failure, bool oversizedRequest,
            bool oversizedResponse) in cases)
        {
            foreach (bool withError in new[] { false, true })
            {
                FakeNative native = DependencyNative("capture", null, call =>
                    call["operation"]!.GetValue<string>() == failure ? Rejected() : null);
                using OperationFixture fixture = new(native);
                SemanticDependencyRequest request = TestRequest();
                if (oversizedRequest)
                {
                    request = request with
                    {
                        Metadata = [new SemanticDependencyMetadata(
                            new byte[SdkEngineBridge.MaxCallBytes + 1], [])],
                    };
                }
                SemanticDependencyResponse response = TestResponse(ObservationOutcome.Response);
                if (oversizedResponse)
                {
                    response = response with
                    {
                        Metadata = [new SemanticDependencyMetadata(
                            new byte[SdkEngineBridge.MaxCallBytes + 1], [])],
                    };
                }
                InvalidOperationException? sentinel = withError
                    ? new InvalidOperationException("sentinel dependency error")
                    : null;
                int liveCalls = 0;
                try
                {
                    SemanticDependencyResponse actual = SemanticDependencyTranslator.Translate(
                        fixture.Operation,
                        request,
                        null,
                        () =>
                        {
                            liveCalls += 1;
                            return new SemanticDependencyLiveResult(response, sentinel);
                        });
                    Require(
                        sentinel is null && ReferenceEquals(actual, response),
                        $"The {name} failure changed a live success result.");
                }
                catch (InvalidOperationException error)
                {
                    Require(
                        ReferenceEquals(error, sentinel),
                        $"The {name} failure changed the live exception.");
                }
                Require(liveCalls == 1, $"The {name} failure ran the live call twice.");
            }
        }
    }

    private static void ReplayReadsChunksAfterEngineValidation()
    {
        byte[] record = PublishedResponse("semantic_dependency_response_outbound_http");
        int split = record.Length / 2;
        FakeNative native = DependencyNative(
            "replay", [record[..split], record[split..]], null);
        using OperationFixture fixture = new(native);
        bool liveCalled = false;
        SemanticDependencyResponse response = SemanticDependencyTranslator.Translate(
            fixture.Operation,
            TestRequest(),
            null,
            () =>
            {
                liveCalled = true;
                return new SemanticDependencyLiveResult(
                    TestResponse(ObservationOutcome.Response), null);
            });
        Require(
            !liveCalled && response.Outcome == ObservationOutcome.Response &&
            response.StatusCode == 200 &&
            Encoding.UTF8.GetString(response.Payload!) == "{\"available\":true}",
            "Replay did not reconstruct the engine-validated response.");
    }

    private static void ReplayNeverFallsBackToLive()
    {
        (string Name, byte[][] Reads, bool FinishFailure)[] cases =
        [
            ("empty read", [[]], false),
            ("record over bound",
                [new byte[SdkEngineBridge.MaxSemanticDependencyRecordBytes], [1]], false),
            ("finish rejection", [Encoding.UTF8.GetBytes("{}")], true),
        ];
        foreach ((string name, byte[][] reads, bool finishFailure) in cases)
        {
            FakeNative native = DependencyNative("replay", reads, call =>
                finishFailure && call["operation"]!.GetValue<string>() == "dependency-finish"
                    ? Rejected()
                    : null);
            using OperationFixture fixture = new(native);
            bool liveCalled = false;
            _ = ExpectCaptureError(() => SemanticDependencyTranslator.Translate(
                fixture.Operation,
                TestRequest(),
                null,
                () =>
                {
                    liveCalled = true;
                    return new SemanticDependencyLiveResult(
                        TestResponse(ObservationOutcome.Response), null);
                }));
            Require(!liveCalled, $"Strict replay fell back to live for {name}.");
        }
    }

    private static void ReplayUsesEngineValidatedOutcome()
    {
        JsonObject record = JsonNode.Parse(
            PublishedResponse("semantic_dependency_response_outbound_http"))!.AsObject();
        record["outcome"] = "error";
        FakeNative native = DependencyNative(
            "replay", [Encoding.UTF8.GetBytes(record.ToJsonString())], null);
        using OperationFixture fixture = new(native);
        SemanticDependencyResponse response = SemanticDependencyTranslator.Translate(
            fixture.Operation,
            TestRequest(),
            null,
            () => throw new InvalidOperationException("Replay called the live dependency."));
        Require(
            response.Outcome == ObservationOutcome.Response,
            "The language bridge duplicated the engine outcome validation.");
    }

    private static FakeNative DependencyNative(
        string action,
        byte[][]? reads,
        Func<JsonObject, byte[]?>? intercept)
    {
        int readIndex = 0;
        return new FakeNative(call =>
        {
            byte[]? intercepted = intercept?.Invoke(call);
            if (intercepted is not null)
            {
                return intercepted;
            }
            string operation = call["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 71 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 72,
                    ["operation_id"] = "op_semantic",
                },
                "dependency-open" => new()
                {
                    ["action"] = action,
                    ["dependency_handle"] = 73,
                },
                "observation-read" => ReadResult(reads!, ref readIndex),
                "dependency-finish" => new() { ["outcome"] = "response" },
                _ => [],
            };
            return Success(result);
        });
    }

    private static JsonObject ReadResult(byte[][] reads, ref int index)
    {
        byte[] chunk = reads[index];
        index += 1;
        return new JsonObject
        {
            ["chunk"] = EncodeBase64Url(chunk),
            ["eof"] = index == reads.Length,
        };
    }

    private static SemanticDependencyRequest TestRequest()
    {
        return new SemanticDependencyRequest(
            "http-1.1-message",
            [
                new SemanticDependencyMetadata(
                    Encoding.UTF8.GetBytes("x-tag"), Encoding.UTF8.GetBytes("first")),
                new SemanticDependencyMetadata(
                    Encoding.UTF8.GetBytes("x-tag"), Encoding.UTF8.GetBytes("second")),
            ],
            "POST",
            AutomaticObservationClass.OutboundHttp,
            "outbound-http-request",
            Encoding.UTF8.GetBytes("{\"quantity\":1}"),
            "http-1.1",
            "https://inventory.example/v1/items/42");
    }

    private static SemanticDependencyResponse TestResponse(ObservationOutcome outcome)
    {
        return outcome == ObservationOutcome.Error
            ? new SemanticDependencyResponse(
                "other", null, [], outcome, null, null, null)
            : new SemanticDependencyResponse(
                null,
                null,
                [new SemanticDependencyMetadata(
                    Encoding.UTF8.GetBytes("content-type"),
                    Encoding.UTF8.GetBytes("application/json"))],
                outcome,
                Encoding.UTF8.GetBytes("{\"available\":true}"),
                null,
                200);
    }

    private static byte[] PublishedResponse(string name)
    {
        string path = Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS") ??
            throw new InvalidOperationException("REPROIT_PROTOCOL_VECTORS is required.");
        JsonObject vectors = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        return CanonicalJson.Bytes(vectors["positive"]![name]!["value"]!);
    }

    private static bool HasExactly(JsonObject value, params string[] names) =>
        value.Count == names.Length && names.All(value.ContainsKey);

    private static byte[] Success(JsonObject result) => Encoding.UTF8.GetBytes(
        new JsonObject
        {
            ["error_code"] = null,
            ["format"] = "reproit.sdk-engine-response.v1",
            ["ok"] = true,
            ["result"] = result,
        }.ToJsonString());

    private static byte[] Rejected() => Encoding.UTF8.GetBytes(new JsonObject
    {
        ["error_code"] = "SCHEMA_INVALID",
        ["format"] = "reproit.sdk-engine-response.v1",
        ["ok"] = false,
        ["result"] = new JsonObject(),
    }.ToJsonString());

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static AutomaticCaptureException ExpectCaptureError(Action action)
    {
        try
        {
            action();
        }
        catch (AutomaticCaptureException error)
        {
            return error;
        }
        throw new InvalidOperationException("Strict replay accepted an invalid response.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class OperationFixture : IDisposable
    {
        private readonly SdkEngineBridge bridge;
        private readonly AutomaticProject project;
        private readonly DotnetSubjectPackage subject;

        internal OperationFixture(FakeNative native)
        {
            bridge = SdkEngineBridge.Open(() => native);
            subject = TestSubject();
            project = AutomaticProject.OpenWith(new AutomaticProjectOptions
            {
                BuildRepositoryId = "repository",
                ProjectToml = "project",
                SourceRevision = "revision",
            }, bridge, subject);
            Operation = project.StartOperation(new AutomaticOperationStart(
                "generic", "1.0.0", [], AutomaticOperationKind.RequestResponse, "operation"));
        }

        internal AutomaticOperation Operation { get; }

        public void Dispose()
        {
            Operation.Dispose();
            project.Dispose();
            subject.Dispose();
            bridge.Dispose();
        }
    }

    private static DotnetSubjectPackage TestSubject()
    {
        string spool = Directory.CreateTempSubdirectory("reproit-dotnet-semantic-test-").FullName;
        string digest = "sha256:" + new string('a', 64);
        return new DotnetSubjectPackage(
            new JsonObject { ["format"] = "reproit.subject-closure.v1" },
            [new PackagedSubjectObject(digest, Path.Combine(spool, "subject"), 1)],
            spool,
            digest);
    }

    private sealed class FakeNative(Func<JsonObject, byte[]> response) : INativeSdkEngine
    {
        public uint AbiVersion() => SdkEngineBridge.AbiVersion;

        public nint Call(byte[] input, byte[] output)
        {
            byte[] value = response(JsonNode.Parse(input)!.AsObject());
            value.CopyTo(output, 0);
            return value.Length;
        }

        public void Close()
        {
        }
    }
}
