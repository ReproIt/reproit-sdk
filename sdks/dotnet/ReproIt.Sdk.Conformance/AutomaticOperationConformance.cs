using System.Text;
using System.Text.Json.Nodes;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class AutomaticOperationConformance
{
    internal static void Run()
    {
        KeepsWorldCoordinatorMethodsInternal();
        ActivationScopesRestoreAsync().GetAwaiter().GetResult();
        UsesSharedEngineLifecycle();
        ObservationSessionRejectsInvalidTransitions();
        UsesEngineForSuccessCancellationAndCleanup();
        DoesNotExposeTokenProviderErrors();
        RejectCleanupUsesAbandon();
        CloseStopsSinkPollingBeforeNativeUnload();
    }

    private static void KeepsWorldCoordinatorMethodsInternal()
    {
        foreach (string name in new[]
        {
            "Observe", "MarkUnowned", "CloseWorld", "Activate", "ActiveOperation",
        })
        {
            Require(
                typeof(AutomaticOperation).GetMethod(name) is null,
                "The automatic .NET operation exposes an internal World coordinator method.");
        }
    }

    private static async Task ActivationScopesRestoreAsync()
    {
        int operationIndex = 0;
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 81 },
                "operation-begin" => BeginContextOperation(ref operationIndex),
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        using AutomaticProject project = AutomaticProject.OpenWith(
            Options(null), bridge, subject);
        using AutomaticOperation outer = project.StartOperation(Start());
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "The .NET operation did not activate its automatic context.");
        using AutomaticOperationActivation outerActivation = outer.Activate();
        await Task.Yield();
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "The .NET activation did not flow across async execution.");

        using (AutomaticOperation inner = project.StartOperation(Start()))
        using (AutomaticOperationActivation innerActivation = inner.Activate())
        {
            Require(
                ReferenceEquals(AutomaticOperationContext.ActiveOperation(), inner),
                "The nested .NET activation did not select the inner operation.");
            inner.Dispose();
            Require(
                ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
                "The nested .NET activation did not restore its active parent.");
        }

        using AutomaticOperation first = project.StartOperation(Start());
        using AutomaticOperation second = project.StartOperation(Start());
        bool[] concurrent = await Task.WhenAll(
            Task.Run(() => ActiveAfterYieldAsync(first)),
            Task.Run(() => ActiveAfterYieldAsync(second)));
        Require(
            concurrent.All(value => value),
            "Concurrent .NET activations shared active state.");
        first.Cancel();
        second.Cancel();
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "Completed concurrent .NET operations did not restore their active parent.");

        using AutomaticOperation exceptional = project.StartOperation(Start());
        Require(
            await RestoresAfterExceptionAsync(exceptional),
            "A .NET exception did not preserve the automatic operation.");
        exceptional.Cancel();
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "A completed exceptional .NET operation did not restore its active parent.");

        using AutomaticOperation canceled = project.StartOperation(Start());
        using CancellationTokenSource cancellation = new();
        Task<bool> canceledTask = Task.Run(
            () => RestoresAfterCancellationAsync(canceled, cancellation.Token));
        cancellation.Cancel();
        Require(
            await canceledTask,
            "A .NET cancellation did not preserve the automatic operation.");
        canceled.Cancel();
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "A completed canceled .NET operation did not restore its active parent.");

        using (AutomaticOperation disposed = project.StartOperation(Start()))
        using (AutomaticOperationActivation disposedActivation = disposed.Activate())
        {
            disposed.Dispose();
            Require(
                disposedActivation.Operation is null &&
                ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
                "A disposed .NET operation remained active.");
        }
        Require(
            ReferenceEquals(AutomaticOperationContext.ActiveOperation(), outer),
            "The .NET activation scope did not preserve the outer operation.");
    }

    private static JsonObject BeginContextOperation(ref int operationIndex)
    {
        operationIndex += 1;
        return new JsonObject
        {
            ["operation_handle"] = 81 + operationIndex,
            ["operation_id"] = $"op_context_{operationIndex}",
        };
    }

    private static async Task<bool> ActiveAfterYieldAsync(AutomaticOperation operation)
    {
        using AutomaticOperationActivation activation = operation.Activate();
        await Task.Yield();
        return ReferenceEquals(AutomaticOperationContext.ActiveOperation(), operation);
    }

    private static async Task<bool> RestoresAfterExceptionAsync(
        AutomaticOperation operation)
    {
        try
        {
            using AutomaticOperationActivation activation = operation.Activate();
            await Task.Yield();
            throw new InvalidOperationException("test exception");
        }
        catch (InvalidOperationException)
        {
            return ReferenceEquals(AutomaticOperationContext.ActiveOperation(), operation);
        }
    }

    private static async Task<bool> RestoresAfterCancellationAsync(
        AutomaticOperation operation,
        CancellationToken cancellation)
    {
        try
        {
            using AutomaticOperationActivation activation = operation.Activate();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellation);
        }
        catch (OperationCanceledException)
        {
            return ReferenceEquals(AutomaticOperationContext.ActiveOperation(), operation);
        }
        return false;
    }

    private static void UsesSharedEngineLifecycle()
    {
        using ManualResetEventSlim sinkWait = new();
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 21 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 22,
                    ["operation_id"] = "op_automatic",
                },
                "observation-open" => new()
                {
                    ["observation_handle"] = 24,
                    ["session_position"] = 0,
                },
                "observation-dispatch" => new() { ["action"] = "capture" },
                "operation-fail" => new() { ["sink_handle"] = 23 },
                "sink-wait" => SinkWaitResult(sinkWait),
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        using AutomaticProject project = AutomaticProject.OpenWith(
            Options(() => new ManagedProjectToken("project-token")), bridge, subject);
        using AutomaticOperation operation = project.StartOperation(new AutomaticOperationStart(
            "generic-http",
            "1.0.0",
            ["op_parent"],
            AutomaticOperationKind.RequestResponse,
            "orders.place"));
        Require(
            operation.OperationId == "op_automatic",
            "The automatic .NET project did not start a shared-engine operation.");
        operation.RecordInput(new AutomaticInputChunk(
            AutomaticInputChannel.Input, "application/json", Encoding.UTF8.GetBytes("request")));
        ObservationSession session = operation.OpenObservationSession(
            AutomaticObservationClass.Database, null);
        session.WriteRequest(Encoding.UTF8.GetBytes("database query"));
        Require(
            session.Dispatch() == ObservationAction.Capture,
            "The automatic observation session did not select capture.");
        session.WriteResponse(Encoding.UTF8.GetBytes("database result"));
        session.Finish(ObservationOutcome.Response);
        operation.Fail(AutomaticTriggerCompletion.Return, new JsonObject
        {
            ["category"] = "explicit",
            ["operation_kind"] = "request-response",
        });
        Require(
            sinkWait.Wait(TimeSpan.FromSeconds(5)),
            "The automatic .NET operation did not finish shared-engine cleanup.");
        string[] expected =
        [
            "engine-open",
            "operation-begin",
            "operation-input",
            "observation-open",
            "observation-write",
            "observation-dispatch",
            "observation-write",
            "observation-finish",
            "operation-close-world",
            "operation-fail",
            "sink-wait",
        ];
        JsonObject[] requests = native.Requests;
        Require(
            requests.Select(value => value["operation"]!.GetValue<string>())
                .SequenceEqual(expected),
            "The automatic .NET operation did not use the shared-engine lifecycle.");
        JsonObject begin = requests[1]["begin"]!.AsObject();
        Require(
            begin["operation_kind"]!.GetValue<string>() == "request-response" &&
            begin["causal_parent_ids"]![0]!.GetValue<string>() == "op_parent",
            "The automatic .NET operation lost its kind or causal parent.");
        JsonObject input = requests[2]["input"]!.AsObject();
        Require(
            input["input_index"]!.GetValue<int>() == 0 &&
            input["value"]!.GetValue<string>() == "cmVxdWVzdA",
            "The automatic .NET operation changed its ordered input chunk.");
    }

    private static void UsesEngineForSuccessCancellationAndCleanup()
    {
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 31 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 32,
                    ["operation_id"] = "op_cleanup",
                },
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        AutomaticProject project = AutomaticProject.OpenWith(Options(null), bridge, subject);
        project.StartOperation(Start()).Succeed();
        project.StartOperation(Start()).Cancel();
        project.StartOperation(Start()).Dispose();
        project.Dispose();
        string[] expected =
        [
            "engine-open",
            "operation-begin",
            "operation-succeed",
            "operation-begin",
            "operation-abandon",
            "operation-begin",
            "operation-abandon",
            "engine-close",
        ];
        Require(
            native.Requests.Select(value => value["operation"]!.GetValue<string>())
                .SequenceEqual(expected),
            "The automatic .NET operation terminal cleanup changed.");
    }

    private static void ObservationSessionRejectsInvalidTransitions()
    {
        int calls = 0;
        FakeNative native = new(request =>
        {
            calls += 1;
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "observation-dispatch" => new() { ["action"] = "replay" },
                "observation-read" => new() { ["chunk"] = "", ["eof"] = true },
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        ObservationSession session = new(
            bridge,
            new SdkEngineObservationStart(new SdkEngineObservationHandle(1), 0));
        int before = calls;
        _ = ExpectCaptureError(() => session.WriteResponse(Encoding.UTF8.GetBytes("invalid")));
        Require(calls == before, "The .NET session sent an invalid response transition.");
        session.WriteRequest(Encoding.UTF8.GetBytes("request"));
        Require(
            session.Dispatch() == ObservationAction.Replay,
            "The .NET session rejected replay dispatch.");
        SdkEngineObservationChunk chunk = session.ReadResponse();
        Require(chunk.Chunk.Length == 0 && chunk.Eof, "The .NET session rejected replay EOF.");
        before = calls;
        _ = ExpectCaptureError(() => session.ReadResponse());
        Require(calls == before, "The .NET session sent a read after replay EOF.");
        session.Finish(ObservationOutcome.Response);
    }

    private static void DoesNotExposeTokenProviderErrors()
    {
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 41 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 42,
                    ["operation_id"] = "op_error",
                },
                _ => [],
            };
            return Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        const string Secret = "private-token-provider-detail";
        using AutomaticProject project = AutomaticProject.OpenWith(
            Options(() => throw new InvalidOperationException(Secret)), bridge, subject);
        using AutomaticOperation operation = project.StartOperation(Start());
        AutomaticCaptureException error = ExpectCaptureError(() => operation.Fail(
            AutomaticTriggerCompletion.Return, []));
        Require(
            error.Message == "Repro It could not capture the operation." &&
            !error.Message.Contains(Secret, StringComparison.Ordinal),
            "The automatic .NET operation exposed a token-provider error.");
    }

    private static void CloseStopsSinkPollingBeforeNativeUnload()
    {
        using ManualResetEventSlim waitStarted = new();
        using ManualResetEventSlim releaseWait = new();
        using ManualResetEventSlim nativeClosed = new();
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 51 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 52,
                    ["operation_id"] = "op_wait_close",
                },
                "operation-fail" => new() { ["sink_handle"] = 53 },
                "sink-wait" => BlockingSinkPoll(request, waitStarted, releaseWait),
                _ => [],
            };
            return Success(result);
        }, nativeClosed.Set);
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        AutomaticProject project = AutomaticProject.OpenWith(
            Options(() => new ManagedProjectToken("project-token")), bridge, subject);
        using AutomaticOperation operation = project.StartOperation(Start());
        operation.Fail(AutomaticTriggerCompletion.Return, []);
        Require(
            waitStarted.Wait(TimeSpan.FromSeconds(5)),
            "The automatic .NET sink poll did not start.");
        Task close = Task.Run(project.Dispose);
        Require(
            !nativeClosed.Wait(TimeSpan.FromMilliseconds(50)),
            "The .NET native SDK engine unloaded during an active call.");
        releaseWait.Set();
        Require(
            close.Wait(TimeSpan.FromSeconds(5)),
            "The .NET project close waited beyond the current bounded native call.");
        Require(nativeClosed.IsSet, "The .NET project did not unload the native SDK engine.");
    }

    private static void RejectCleanupUsesAbandon()
    {
        FakeNative native = new(request =>
        {
            string operation = request["operation"]!.GetValue<string>();
            JsonObject result = operation switch
            {
                "engine-open" => new() { ["engine_handle"] = 61 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 62,
                    ["operation_id"] = "op_reject_cleanup",
                },
                _ => [],
            };
            return operation is "operation-succeed" or "operation-fail"
                ? Rejected()
                : Success(result);
        });
        using SdkEngineBridge bridge = SdkEngineBridge.Open(() => native);
        using DotnetSubjectPackage subject = TestSubject();
        using AutomaticProject project = AutomaticProject.OpenWith(
            Options(() => new ManagedProjectToken("project-token")), bridge, subject);
        project.StartOperation(Start()).Succeed();
        using AutomaticOperation failure = project.StartOperation(Start());
        _ = ExpectCaptureError(() =>
            failure.Fail(AutomaticTriggerCompletion.Return, []));
        string joined = string.Join(",", native.Requests.Select(
            value => value["operation"]!.GetValue<string>()));
        Require(
            joined.Contains("operation-succeed,operation-abandon", StringComparison.Ordinal) &&
            joined.Contains("operation-fail,operation-abandon", StringComparison.Ordinal),
            "The automatic .NET operation retained state after terminal rejection.");
    }

    private static JsonObject BlockingSinkPoll(
        JsonObject request,
        ManualResetEventSlim waitStarted,
        ManualResetEventSlim releaseWait)
    {
        Require(
            request["timeout_ms"]!.GetValue<ulong>() == 0,
            "The .NET sink poll used a blocking native timeout.");
        waitStarted.Set();
        releaseWait.Wait();
        return new JsonObject { ["idle"] = false };
    }

    private static JsonObject SinkWaitResult(ManualResetEventSlim wait)
    {
        wait.Set();
        return new JsonObject { ["idle"] = true };
    }

    private static AutomaticProjectOptions Options(Func<ManagedProjectToken>? tokenProvider) =>
        new()
        {
            BuildRepositoryId = "repository",
            ProjectToml = "project",
            ProjectTokenProvider = tokenProvider,
            SourceRevision = "revision",
        };

    private static AutomaticOperationStart Start() => new(
        "generic", "1.0.0", [], AutomaticOperationKind.RequestResponse, "operation");

    private static DotnetSubjectPackage TestSubject()
    {
        string spool = Directory.CreateTempSubdirectory("reproit-dotnet-engine-test-").FullName;
        string digest = "sha256:" + new string('a', 64);
        return new DotnetSubjectPackage(
            new JsonObject { ["format"] = "reproit.subject-closure.v1" },
            [new PackagedSubjectObject(digest, Path.Combine(spool, "subject"), 1)],
            spool,
            digest);
    }

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

    private static AutomaticCaptureException ExpectCaptureError(Action operation)
    {
        try
        {
            operation();
        }
        catch (AutomaticCaptureException error)
        {
            return error;
        }
        throw new InvalidOperationException("The automatic .NET operation accepted invalid input.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class FakeNative(
        Func<JsonObject, byte[]> response,
        Action? close = null) : INativeSdkEngine
    {
        private readonly object stateLock = new();
        private readonly List<JsonObject> requests = [];

        internal JsonObject[] Requests
        {
            get
            {
                lock (stateLock)
                {
                    return requests.Select(value => (JsonObject)value.DeepClone()).ToArray();
                }
            }
        }

        public uint AbiVersion() => SdkEngineBridge.AbiVersion;

        public nint Call(byte[] input, byte[] output)
        {
            JsonObject request = JsonNode.Parse(input)!.AsObject();
            lock (stateLock)
            {
                requests.Add((JsonObject)request.DeepClone());
            }
            byte[] value = response(request);
            value.CopyTo(output, 0);
            return value.Length;
        }

        public void Close() => close?.Invoke();
    }
}
