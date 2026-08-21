using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using ReproIt.Sdk;
using ReproIt.Sdk.AspNetCore;
using ReproIt.Sdk.Conformance;

Require(typeof(Sdk).Assembly.GetType("ReproIt.Sdk.MemorySink") is null,
    "The released SDK exposes a memory-only candidate sink.");

// The sdk-portability differential stage prints this host's capture and
// exits so the gate can diff it against the other four SDKs.
if (args is ["processor-capture"])
{
    foreach (string capability in ProcessorCapture.CaptureProcessorCapabilities())
    {
        Console.WriteLine(capability);
    }
    return;
}

JsonNode vectors = JsonNode.Parse(await File.ReadAllTextAsync(
    Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS")
        ?? throw new InvalidOperationException("REPROIT_PROTOCOL_VECTORS is required.")))!;
JsonObject positive = vectors["positive"]!.AsObject();
JsonNode Value(string name) => positive[name]!["value"]!.DeepClone();

JsonNode expected = Value("candidate");
CandidateStart start = new(
    expected["capture_id"]!.GetValue<string>(),
    expected["deployment"]!.DeepClone(),
    expected["operation_id"]!.GetValue<string>(),
    expected["world_id"]!.GetValue<string>());
const int QueueRestartCandidateLimit = 16;

string? queueRestartChild = Environment.GetEnvironmentVariable(
    "REPROIT_QUEUE_RESTART_CHILD");
if (queueRestartChild is not null)
{
    await RunQueueRestartChild(queueRestartChild,
        Environment.GetEnvironmentVariable("REPROIT_QUEUE_RESTART_STATE")
            ?? throw new InvalidOperationException("Queue restart state path is required."));
    return;
}

MemorySink memory = new();
Sdk sdk = new(memory);
Fail(sdk, start);
Require(memory.Candidates.Count == 1 &&
    memory.Candidates[0].AsSpan().SequenceEqual(CanonicalJson.Bytes(expected)),
    "The .NET candidate differs from the language-neutral vector.");
Require(sdk.ActiveOperations == 0, "The failed operation remained active.");

memory = new MemorySink();
sdk = new Sdk(memory);
JsonNode dependency = Value("dependency_close_request")["cursor"]!.DeepClone();
sdk.Begin(start, Value("operation_begin_payload"));
sdk.RecordInput(start.OperationId, Value("operation_input_payload"));
sdk.RecordDependency(start.OperationId, dependency);
sdk.Fail(start.OperationId, Value("failure_payload"));
Require(memory.Candidates.Count == 1,
    "The complete dependency capture did not reach the sink.");
JsonArray dependencyRecords = JsonNode.Parse(memory.Candidates[0])!["records"]!.AsArray();
Require(dependencyRecords.Count == 5 &&
    dependencyRecords[2]!["kind"]!.GetValue<string>() == "dependency",
    "The dependency record order changed.");

CandidateStart refreshed = start with
{
    CaptureId = "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
    OperationId = "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
    WorldId = $"sha256:{new string('a', 64)}",
};
Fail(sdk, refreshed);
Require(memory.Candidates.Count == 1,
    "A refreshed World bypassed Failure suppression.");
Require(sdk.RecallCounters.EligibleFailureObserved == 2 &&
    sdk.RecallCounters.SuppressedExactStorm == 1,
    "The exact-storm recall counters are incorrect.");

memory = new MemorySink();
sdk = new Sdk(memory);
for (int index = 0; index < 1_000; index += 1)
{
    string suffix = index.ToString("x12");
    Fail(sdk, start with
    {
        CaptureId = $"cap_01890f3e-7b1c-7cc0-8a1b-{suffix}",
        OperationId = $"op_01890f3e-7b1c-7cc0-8a1b-{suffix}",
    });
}
Require(memory.Candidates.Count == 1,
    "Exact Failure repetition consumed more than one candidate token.");
Require(sdk.RecallCounters.EligibleFailureObserved == 1_000 &&
    sdk.RecallCounters.SuppressedExactStorm == 999,
    "The repeated-Failure recall counters are incorrect.");

memory = new MemorySink();
sdk = new Sdk(memory);
for (int index = 0; index < 257; index += 1)
{
    JsonNode failure = Value("failure_payload");
    failure["identity"]!["stable_code"] = $"storm-{index}";
    byte[] identityBytes = CanonicalJson.Bytes(failure["identity"]!);
    failure["failure"]!["identity"] =
        $"sha256:{Convert.ToHexString(SHA256.HashData(identityBytes)).ToLowerInvariant()}";
    string suffix = index.ToString("x12");
    CandidateStart current = start with
    {
        CaptureId = $"cap_01890f3e-7b1c-7cc0-8a1b-{suffix}",
        OperationId = $"op_01890f3e-7b1c-7cc0-8a1b-{suffix}",
    };
    sdk.Begin(current, Value("operation_begin_payload"));
    sdk.Fail(current.OperationId, failure);
}
Require(memory.Candidates.Count <= 4,
    "High-cardinality churn bypassed the candidate token bucket.");
Require(sdk.RecallCounters.SuppressedHighCardinalityStorm > 0,
    "The high-cardinality recall counter did not advance.");

memory = new MemorySink();
sdk = new Sdk(memory);
sdk.Begin(start, Value("operation_begin_payload"));
sdk.Succeed(start.OperationId);
sdk.Begin(start, Value("operation_begin_payload"));
sdk.Cancel(start.OperationId);
Require(memory.Candidates.Count == 0, "A successful or cancelled operation reached the sink.");
InvalidOperationException original = new("customer failure");
try
{
    Operations.Run<int>(
        sdk,
        start,
        Value("operation_begin_payload"),
        [Value("operation_input_payload")],
        () => throw original,
        _ => Value("failure_payload"));
    throw new InvalidOperationException("The application exception did not escape.");
}
catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
{
}
Require(memory.Candidates.Count == 1, "The failed operation did not reach the sink.");

foreach (string operationKind in new[] { "stream", "delivered-work" })
{
    memory = new MemorySink();
    sdk = new Sdk(memory);
    JsonNode begin = Value("operation_begin_payload");
    begin["operation_kind"] = operationKind;
    JsonNode failure = Value("failure_payload");
    failure["identity"]!["operation_kind"] = operationKind;
    byte[] identityBytes = CanonicalJson.Bytes(failure["identity"]!);
    failure["failure"]!["identity"] =
        $"sha256:{Convert.ToHexString(SHA256.HashData(identityBytes)).ToLowerInvariant()}";
    JsonNode secondInput = Value("operation_input_payload");
    byte[] secondValue = "second-input"u8.ToArray();
    secondInput["input_index"] = 1;
    secondInput["value"] = Convert.ToBase64String(secondValue)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    secondInput["value_digest"] =
        $"sha256:{Convert.ToHexString(SHA256.HashData(secondValue)).ToLowerInvariant()}";
    Operations.Preparation preparation = new(
        start,
        begin,
        [Value("operation_input_payload"), secondInput],
        [dependency.DeepClone()]);
    original = new InvalidOperationException("customer operation failure");
    try
    {
        if (operationKind == "stream")
        {
            Operations.RunStream<int>(sdk, preparation, () => throw original, _ => failure);
        }
        else
        {
            Operations.RunDeliveredWork<int>(sdk, preparation, () => throw original, _ => failure);
        }
        throw new InvalidOperationException("The application exception did not escape.");
    }
    catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
    {
    }
    Require(memory.Candidates.Count == 1 && sdk.ActiveOperations == 0,
        "The operation boundary lost the candidate or retained capture state.");
    JsonArray records = JsonNode.Parse(memory.Candidates[0])!["records"]!.AsArray();
    string[] kinds = records
        .Select(record => record!["kind"]!.GetValue<string>())
        .ToArray();
    Require(kinds.SequenceEqual(
        new[] { "begin", "input", "input", "dependency", "failure", "terminal" }),
        "The ordered operation record sequence changed.");
}

memory = new MemorySink();
sdk = new Sdk(memory);
original = new InvalidOperationException("customer conversion failure");
try
{
    Operations.Run<int>(
        sdk,
        start,
        Value("operation_begin_payload"),
        [Value("operation_input_payload")],
        () => throw original,
        _ => throw new CaptureException("Failure conversion failed."));
    throw new InvalidOperationException("The application exception did not escape.");
}
catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
{
}
Require(memory.Candidates.Count == 0 && sdk.ActiveOperations == 0 &&
    sdk.RecallCounters.CandidateIncomplete == 1,
    "Failure conversion changed application behavior or retained capture state.");

memory = new MemorySink();
sdk = new Sdk(memory);
JsonNode invalidDependency = dependency.DeepClone();
invalidDependency["cursor_digest"] = "invalid";
original = new InvalidOperationException("customer dependency failure");
try
{
    Operations.RunPrepared<int>(
        sdk,
        new Operations.Preparation(
            start,
            Value("operation_begin_payload"),
            [Value("operation_input_payload")],
            [invalidDependency]),
        () => throw original,
        _ => Value("failure_payload"));
    throw new InvalidOperationException("The application exception did not escape.");
}
catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
{
}
Require(memory.Candidates.Count == 0 && sdk.ActiveOperations == 0 &&
    sdk.RecallCounters.CandidateIncomplete > 0,
    "The invalid dependency changed the result or reached the sink.");

PrivateOnlySink privateOnly = new();
sdk = new Sdk(privateOnly);
JsonNode managedDeployment = start.Deployment.DeepClone();
managedDeployment["processing_mode"] = "managed";
CandidateStart managedStart = start with { Deployment = managedDeployment };
sdk.Begin(managedStart, Value("operation_begin_payload"));
try
{
    sdk.Fail(managedStart.OperationId, Value("failure_payload"));
    throw new InvalidOperationException("The private sink accepted a managed candidate.");
}
catch (CaptureException)
{
}
Require(privateOnly.Deliveries == 0 && sdk.RecallCounters.CandidateRejected == 1,
    "The managed candidate entered the private transport.");

MemorySink managedMemory = new();
Fail(new Sdk(managedMemory), managedStart);
UnixRuntimeSink privateRuntime = new(
    "/tmp/reproit-missing-private-runtime.sock",
    () => "ReproIt workload-token");
Require(!privateRuntime.TrySend(
    managedStart.CaptureId,
    managedMemory.Candidates.Single()),
    "The private Runtime transport accepted a direct managed candidate.");
Require(!privateRuntime.TrySend(
    refreshed.CaptureId,
    CanonicalJson.Bytes(expected)),
    "The private Runtime transport accepted a mismatched capture ID.");
Require(!privateRuntime.TrySend(
    start.CaptureId,
    new byte[Sdk.MaxGlobalBytes + 1]),
    "The private Runtime transport accepted an oversized candidate.");
Require(privateRuntime.QueuedBytes == 0,
    "A rejected candidate changed the private Runtime queue.");

memory = new MemorySink();
sdk = new Sdk(memory);
original = new InvalidOperationException("customer HTTP failure");
ReproItMiddleware middleware = new(
    _ => Task.FromException(original),
    sdk,
    _ => new AspNetCapture(
        start,
        Value("operation_begin_payload"),
        [Value("operation_input_payload")],
        []),
    _ => Value("failure_payload"));
try
{
    await middleware.InvokeAsync(new DefaultHttpContext());
    throw new InvalidOperationException("The HTTP exception did not escape.");
}
catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
{
}
Require(memory.Candidates.Count == 1, "The ASP.NET Core failure did not reach the sink.");

memory = new MemorySink();
sdk = new Sdk(memory);
sdk.Begin(start, Value("operation_begin_payload"));
JsonNode oversized = Value("failure_payload");
oversized["oversized"] = new string('x', Sdk.MaxEventBytes);
try
{
    sdk.Fail(start.OperationId, oversized);
    throw new InvalidOperationException("The oversized Failure was accepted.");
}
catch (CaptureException)
{
}
Require(sdk.ActiveOperations == 0 && memory.Candidates.Count == 0,
    "The oversized operation was retained or delivered.");

memory = new MemorySink();
sdk = new Sdk(memory);
List<string> operationIds = new(Sdk.MaxActiveOperations);
for (int index = 0; index < Sdk.MaxActiveOperations; index += 1)
{
    string operationId = $"op_01890f3e-7b1c-7cc0-8a1b-{index:x12}";
    sdk.Begin(start with { OperationId = operationId }, Value("operation_begin_payload"));
    operationIds.Add(operationId);
}
try
{
    sdk.Begin(
        start with { OperationId = "op_01890f3e-7b1c-7cc0-8a1b-000000000200" },
        Value("operation_begin_payload"));
    throw new InvalidOperationException("The operation beyond the active bound was accepted.");
}
catch (CaptureException)
{
}
Require(sdk.ActiveOperations == Sdk.MaxActiveOperations && memory.Candidates.Count == 0,
    "The active operation bound changed capture state.");
foreach (string operationId in operationIds)
{
    sdk.Cancel(operationId);
}
Require(sdk.ActiveOperations == 0, "The bounded active operations were not released.");

string directory = Path.Combine(Path.GetTempPath(), $"reproit-dotnet-{Environment.ProcessId}");
Directory.CreateDirectory(directory);
string socketPath = Path.Combine(directory, "runtime.sock");
using Socket listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
listener.Bind(new UnixDomainSocketEndPoint(socketPath));
listener.Listen(1);
Task<byte[]> received = ReceiveAsync(listener);
UnixRuntimeSink runtime = new(socketPath, () => "ReproIt workload-token");
Fail(new Sdk(runtime), start);
byte[] request = await received.WaitAsync(TimeSpan.FromSeconds(1));
Require(request.AsSpan().IndexOf("Reproit-Protocol: 1"u8) >= 0,
    "The protocol header is missing.");
Require(request.AsSpan().IndexOf("Authorization: ReproIt workload-token"u8) >= 0,
    "The authorization header is missing.");
Require(HttpBody(request).AsSpan().SequenceEqual(CanonicalJson.Bytes(expected)),
    "The Runtime received different candidate bytes.");
Directory.Delete(directory, true);

string successDirectory = Path.Combine(
    Path.GetTempPath(), $"reproit-dotnet-success-{Environment.ProcessId}");
Directory.CreateDirectory(successDirectory);
string successSocketPath = Path.Combine(successDirectory, "runtime.sock");
using (Socket successListener = new(
    AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
{
    successListener.Bind(new UnixDomainSocketEndPoint(successSocketPath));
    successListener.Listen(1);
    runtime = new UnixRuntimeSink(
        successSocketPath, () => "ReproIt workload-token");
    sdk = new Sdk(runtime);
    string success = Operations.Run(
        sdk,
        start,
        Value("operation_begin_payload"),
        [Value("operation_input_payload")],
        () => "application-result",
        _ => Value("failure_payload"));
    await Task.Delay(20);
    Require(success == "application-result" && sdk.ActiveOperations == 0 &&
        runtime.QueuedBytes == 0 && !successListener.Poll(0, SelectMode.SelectRead),
        "A successful operation contacted the Runtime or retained capture state.");
}
Directory.Delete(successDirectory, true);

runtime = new UnixRuntimeSink(
    "/tmp/reproit-dotnet-outage.sock", () => "ReproIt workload-token");
sdk = new Sdk(runtime);
original = new InvalidOperationException("customer Runtime-outage failure");
try
{
    Operations.Run<int>(
        sdk,
        start,
        Value("operation_begin_payload"),
        [Value("operation_input_payload")],
        () => throw original,
        _ => Value("failure_payload"));
    throw new InvalidOperationException("The application exception did not escape.");
}
catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
{
}
DateTime outageDeadline = DateTime.UtcNow.AddSeconds(1);
while (runtime.QueuedBytes != 0 && DateTime.UtcNow < outageDeadline)
{
    await Task.Delay(1);
}
Require(runtime.QueuedBytes == 0 && sdk.ActiveOperations == 0,
    "Runtime outage changed application behavior or retained SDK resources.");

runtime = new UnixRuntimeSink(
    "/tmp/reproit-dotnet-authorization.sock",
    () => throw new InvalidOperationException("authorization unavailable"));
sdk = new Sdk(runtime);
Fail(sdk, start);
outageDeadline = DateTime.UtcNow.AddSeconds(1);
while (runtime.QueuedBytes != 0 && DateTime.UtcNow < outageDeadline)
{
    await Task.Delay(1);
}
Require(runtime.QueuedBytes == 0 && sdk.ActiveOperations == 0,
    "Runtime authorization failure retained SDK resources.");

using ManualResetEventSlim deliveryStarted = new(false);
using ManualResetEventSlim releaseDelivery = new(false);
runtime = new UnixRuntimeSink("/tmp/reproit-missing-runtime.sock", () =>
{
    deliveryStarted.Set();
    releaseDelivery.Wait(TimeSpan.FromSeconds(1));
    return null;
});
Require(runtime.TrySend(
    "cap_01890f3e-7b1c-7cc0-8a1b-000000000000",
    CandidateBytes("cap_01890f3e-7b1c-7cc0-8a1b-000000000000")),
    "The first candidate was rejected.");
Require(deliveryStarted.Wait(TimeSpan.FromSeconds(1)), "The first delivery did not start.");
for (int index = 1; index < 16; index += 1)
{
    string captureId = $"cap_01890f3e-7b1c-7cc0-8a1b-{index:x12}";
    Require(runtime.TrySend(
        captureId,
        CandidateBytes(captureId)),
        $"Candidate {index} was rejected below the bound.");
}
Require(!runtime.TrySend(
    "cap_01890f3e-7b1c-7cc0-8a1b-000000000010",
    CandidateBytes("cap_01890f3e-7b1c-7cc0-8a1b-000000000010")),
    "The candidate beyond the active and waiting bound was accepted.");
releaseDelivery.Set();
DateTime drainDeadline = DateTime.UtcNow.AddSeconds(1);
while (runtime.QueuedBytes != 0 && DateTime.UtcNow < drainDeadline)
{
    await Task.Delay(1);
}
Require(runtime.QueuedBytes == 0, "The bounded queue did not drain.");

RecordingStagedTransport stagedRuntime = new();
RecordingStagedTransport stagedDeferred = new();
byte[] stagingKey = Enumerable.Repeat((byte)0x63, 32).ToArray();
StagedCandidateSink staged = new(stagedRuntime, stagedDeferred, stagingKey);
Sdk stagedSdk = new(staged);
Fail(stagedSdk, start);
DateTime stagedDeadline = DateTime.UtcNow.AddSeconds(1);
while ((stagedRuntime.Received.Count == 0 || stagedDeferred.Received.Count == 0 ||
    stagedSdk.RecallCounters.CandidateDurablyAccepted == 0) &&
    DateTime.UtcNow < stagedDeadline)
{
    await Task.Delay(1);
}
Require(stagedRuntime.Received.Count == 1 && stagedDeferred.Received.Count == 1 &&
    stagedRuntime.Received[0].AsSpan().SequenceEqual(stagedDeferred.Received[0]),
    "The staged transports did not receive one identical envelope.");
JsonNode envelope = JsonNode.Parse(stagedRuntime.Received[0])!;
byte[] stored = FromBase64Url(envelope["ciphertext"]!.GetValue<string>());
byte[] plaintext = new byte[stored.Length - 28];
using (AesGcm cipher = new(stagingKey, 16))
{
    cipher.Decrypt(
        stored.AsSpan(0, 12),
        stored.AsSpan(12, plaintext.Length),
        stored.AsSpan(12 + plaintext.Length, 16),
        plaintext,
        CanonicalJson.Bytes(envelope["identity"]!));
}
Require(plaintext.AsSpan().SequenceEqual(CanonicalJson.Bytes(expected)) && staged.QueuedBytes == 0,
    "The staged envelope did not contain the exact complete candidate.");

JsonNode incomplete = expected.DeepClone();
incomplete["records"]!.AsArray().RemoveAt(incomplete["records"]!.AsArray().Count - 1);
Require(!staged.TrySend(
        incomplete["capture_id"]!.GetValue<string>(),
        CanonicalJson.Bytes(incomplete)),
    "An incomplete candidate entered staged delivery.");
await Task.Delay(1);
Require(stagedRuntime.Received.Count == 1 && stagedDeferred.Received.Count == 1,
    "An incomplete candidate made a staged network request.");
Require(stagedSdk.RecallCounters.CandidateIncomplete == 1,
    "The incomplete staged candidate was not counted.");

StagedCandidateSink unavailableStaging = new(
    new ThrowingStagedTransport(),
    new ThrowingStagedTransport(),
    stagingKey);
Sdk unavailableStagingSdk = new(unavailableStaging);
Fail(unavailableStagingSdk, start);
stagedDeadline = DateTime.UtcNow.AddSeconds(1);
while (unavailableStaging.QueuedBytes != 0 && DateTime.UtcNow < stagedDeadline)
{
    await Task.Delay(1);
}
Require(unavailableStaging.QueuedBytes == 0 &&
    unavailableStagingSdk.ActiveOperations == 0 &&
    unavailableStagingSdk.RecallCounters.CandidateDeliveryExpired == 1,
    "Staged Runtime failure retained candidate resources.");

ThrowingWorldTransport worldTransport = new();
WorldTokenCache worldCache = new(
    worldTransport,
    start.Deployment["service_id"]!.GetValue<string>());
await Task.Delay(20);
try
{
    _ = worldCache.CandidateStart(
        start.CaptureId, start.Deployment.DeepClone(), start.OperationId);
    throw new InvalidOperationException("The missing World token was accepted.");
}
catch (CaptureException)
{
}
await worldCache.DisposeAsync();
Require(worldTransport.Attempts > 0,
    "The World-token outage path did not call its Runtime transport.");
await QueueProcessRestartRecovery();
Console.WriteLine("dotnet_candidate=PASS");
Console.WriteLine("dotnet_unix_transport=PASS");
Console.WriteLine("dotnet_staged_transport=PASS");

ReproIt.Sdk.Conformance.ManagedConformance.Run();
ReproIt.Sdk.Conformance.ManagedLoopbackConformance.Run();
ReproIt.Sdk.Conformance.ProcessorCaptureConformance.Run();

void Fail(Sdk target, CandidateStart candidateStart)
{
    target.Begin(candidateStart, Value("operation_begin_payload"));
    target.RecordInput(candidateStart.OperationId, Value("operation_input_payload"));
    target.Fail(candidateStart.OperationId, Value("failure_payload"));
}

byte[] CandidateBytes(string captureId)
{
    JsonNode candidate = expected.DeepClone();
    candidate["capture_id"] = captureId;
    return CanonicalJson.Bytes(candidate);
}

async Task QueueProcessRestartRecovery()
{
    string root = Directory.CreateTempSubdirectory("reproit-dotnet-queue-restart-").FullName;
    string statePath = Path.Combine(root, "state.json");
    try
    {
        using Process first = StartQueueRestartChild("seed", statePath);
        DateTime deadline = DateTime.UtcNow.AddSeconds(2);
        while ((!File.Exists(statePath) || new FileInfo(statePath).Length == 0) &&
            DateTime.UtcNow < deadline)
        {
            await Task.Delay(5);
        }
        Require(File.Exists(statePath) && new FileInfo(statePath).Length > 0,
            "The first queue process did not persist its bounded state.");
        first.Kill(entireProcessTree: true);
        await first.WaitForExitAsync();

        using Process recovered = StartQueueRestartChild("recover", statePath);
        await recovered.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Require(recovered.ExitCode == 0, "The restarted queue process failed.");

        await File.WriteAllTextAsync(statePath, "{");
        using Process corrupt = StartQueueRestartChild("recover", statePath);
        await corrupt.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Require(corrupt.ExitCode != 0,
            "The restarted queue process accepted corrupt durable state.");

        WriteQueueRestartState(statePath, new JsonObject
        {
            ["format"] = "reproit.sdk-queue-restart.v1",
            ["one_over_accepted"] = false,
            ["pid"] = first.Id,
            ["queued_bytes"] = QueueRestartCandidateLimit + 1,
            ["queued_candidates"] = QueueRestartCandidateLimit + 1,
        });
        using Process oneOver = StartQueueRestartChild("recover", statePath);
        await oneOver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Require(oneOver.ExitCode != 0,
            "The restarted queue process accepted one-over durable state.");
    }
    finally
    {
        Directory.Delete(root, recursive: true);
    }
}

Process StartQueueRestartChild(string mode, string statePath)
{
    string executable = Environment.ProcessPath
        ?? throw new InvalidOperationException("The current process path is unavailable.");
    ProcessStartInfo startInfo = new(executable)
    {
        RedirectStandardError = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet",
        StringComparison.OrdinalIgnoreCase))
    {
        startInfo.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
    }
    startInfo.Environment["REPROIT_QUEUE_RESTART_CHILD"] = mode;
    startInfo.Environment["REPROIT_QUEUE_RESTART_STATE"] = statePath;
    return Process.Start(startInfo)
        ?? throw new InvalidOperationException("The queue restart child did not start.");
}

async Task RunQueueRestartChild(string mode, string statePath)
{
    byte[] candidate = CanonicalJson.Bytes(expected);
    if (mode == "recover")
    {
        ReadQueueRestartState(statePath, candidate.Length);
    }
    else if (mode != "seed")
    {
        throw new InvalidOperationException("The queue restart child mode is invalid.");
    }
    using ManualResetEventSlim started = new(false);
    using ManualResetEventSlim release = new(false);
    UnixRuntimeSink sink = new("/tmp/reproit-missing-runtime-restart.sock", () =>
    {
        started.Set();
        release.Wait(TimeSpan.FromMinutes(1));
        return null;
    });
    const string firstCaptureId = "cap_01890f3e-7b1c-7cc0-8a1b-000000000000";
    Require(sink.TrySend(firstCaptureId, CandidateBytes(firstCaptureId)),
        "The queue restart child refused the first candidate.");
    Require(started.Wait(TimeSpan.FromSeconds(1)),
        "The queue restart child did not start delivery.");
    for (int index = 1; index < QueueRestartCandidateLimit; index += 1)
    {
        string captureId = $"cap_01890f3e-7b1c-7cc0-8a1b-{index:x12}";
        Require(sink.TrySend(captureId, CandidateBytes(captureId)),
            "The queue restart child stopped below the bound.");
    }
    WriteQueueRestartState(statePath, new JsonObject
    {
        ["format"] = "reproit.sdk-queue-restart.v1",
        ["one_over_accepted"] = sink.TrySend(
            "cap_01890f3e-7b1c-7cc0-8a1b-000000000010",
            CandidateBytes("cap_01890f3e-7b1c-7cc0-8a1b-000000000010")),
        ["pid"] = Environment.ProcessId,
        ["queued_bytes"] = sink.QueuedBytes,
        ["queued_candidates"] = QueueRestartCandidateLimit,
    });
    if (mode == "seed")
    {
        await Task.Delay(Timeout.InfiniteTimeSpan);
    }
}

void WriteQueueRestartState(string path, JsonObject state)
{
    const int maximumBytes = 4096;
    byte[] bytes = CanonicalJson.Bytes(state);
    Require(bytes.Length is > 0 and <= maximumBytes,
        "The queue restart state exceeds its bound.");
    string temporary = path + ".tmp";
    File.Delete(temporary);
    using (FileStream output = new(temporary, FileMode.CreateNew, FileAccess.Write,
        FileShare.None, 4096, FileOptions.WriteThrough))
    {
        output.Write(bytes);
        output.Flush(flushToDisk: true);
    }
    File.Move(temporary, path, overwrite: true);
}

void ReadQueueRestartState(string path, int candidateSize)
{
    const int maximumBytes = 4096;
    FileInfo information = new(path);
    Require(information.Exists && information.LinkTarget is null &&
        information.Length is > 0 and <= maximumBytes,
        "The queue restart state is invalid.");
    JsonObject state = JsonNode.Parse(File.ReadAllBytes(path))?.AsObject()
        ?? throw new InvalidOperationException("The queue restart state is invalid.");
    string[] expectedKeys =
    [
        "format", "one_over_accepted", "pid", "queued_bytes", "queued_candidates"
    ];
    Require(state.Select(entry => entry.Key).Order().SequenceEqual(expectedKeys.Order()) &&
        state["format"]!.GetValue<string>() == "reproit.sdk-queue-restart.v1" &&
        !state["one_over_accepted"]!.GetValue<bool>() &&
        state["queued_candidates"]!.GetValue<int>() == QueueRestartCandidateLimit &&
        state["queued_bytes"]!.GetValue<int>() ==
            QueueRestartCandidateLimit * candidateSize &&
        state["pid"]!.GetValue<int>() > 0 &&
        state["pid"]!.GetValue<int>() != Environment.ProcessId,
        "The queue restart state is invalid.");
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static async Task<byte[]> ReceiveAsync(Socket listener)
{
    using Socket connection = await listener.AcceptAsync();
    byte[] buffer = new byte[300_000];
    int length = 0;
    int bodyStart = -1;
    int bodyLength = -1;
    while (length < buffer.Length)
    {
        int read = await connection.ReceiveAsync(buffer.AsMemory(length));
        if (read == 0)
        {
            break;
        }
        length += read;
        if (bodyStart < 0)
        {
            bodyStart = buffer.AsSpan(0, length).IndexOf("\r\n\r\n"u8);
            if (bodyStart >= 0)
            {
                bodyStart += 4;
                string header = Encoding.ASCII.GetString(buffer, 0, bodyStart);
                string line = header.Split("\r\n")
                    .Single(value => value.StartsWith(
                        "Content-Length:", StringComparison.OrdinalIgnoreCase));
                bodyLength = int.Parse(line.Split(':', 2)[1]);
            }
        }
        if (bodyStart >= 0 && length >= bodyStart + bodyLength)
        {
            break;
        }
    }
    await connection.SendAsync("HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"u8.ToArray());
    return buffer[..length];
}

static byte[] FromBase64Url(string value)
{
    string padded = value.Replace('-', '+').Replace('_', '/');
    padded += new string('=', (4 - padded.Length % 4) % 4);
    return Convert.FromBase64String(padded);
}

static byte[] HttpBody(byte[] request)
{
    int boundary = request.AsSpan().IndexOf("\r\n\r\n"u8);
    if (boundary < 0) return [];
    return request[(boundary + 4)..];
}

sealed class RecordingStagedTransport : IStagedCandidateTransport
{
    internal List<byte[]> Received { get; } = [];

    public Task<StagedDeliveryOutcome> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout)
    {
        _ = captureId;
        _ = timeout;
        Received.Add(envelope.ToArray());
        return Task.FromResult(StagedDeliveryOutcome.CloudProtected);
    }
}

sealed class ThrowingStagedTransport : IStagedCandidateTransport
{
    public Task<StagedDeliveryOutcome> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout) => throw new InvalidOperationException("staging unavailable");
}

sealed class ThrowingWorldTransport : IWorldTokenTransport
{
    internal int Attempts { get; private set; }

    public Task<string?> FetchWorldIdAsync(
        string serviceId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Attempts += 1;
        throw new InvalidOperationException("Runtime unavailable");
    }
}

sealed class PrivateOnlySink : ICandidateSink
{
    internal int Deliveries { get; private set; }
    public int QueuedBytes => 0;
    public bool AllowsProcessingMode(string mode) => mode == "private";
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate)
    {
        _ = captureId;
        _ = candidate;
        Deliveries += 1;
        return true;
    }
}
