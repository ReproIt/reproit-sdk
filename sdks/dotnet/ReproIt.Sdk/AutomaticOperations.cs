using System.Diagnostics;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Identifies one framework-neutral Backend Trigger.</summary>
public enum AutomaticOperationKind
{
    /// <summary>A request produces one response.</summary>
    RequestResponse,
    /// <summary>An ordered input stream produces one terminal result.</summary>
    Stream,
    /// <summary>One delivered task ends with an acknowledgment or task result.</summary>
    DeliveredWork,
}

/// <summary>Identifies the meaning of one ordered input chunk.</summary>
public enum AutomaticInputChannel
{
    /// <summary>The chunk controls Trigger execution.</summary>
    Control,
    /// <summary>The chunk contains application input.</summary>
    Input,
    /// <summary>The chunk contains application-visible metadata.</summary>
    Metadata,
}

/// <summary>Identifies one supported World boundary.</summary>
internal enum AutomaticObservationClass
{
    /// <summary>The observation reads a clock.</summary>
    Clock,
    /// <summary>The observation interacts with a database.</summary>
    Database,
    /// <summary>The observation reads the process environment.</summary>
    Environment,
    /// <summary>The observation reads the filesystem.</summary>
    Filesystem,
    /// <summary>The observation makes an outbound HTTP call.</summary>
    OutboundHttp,
    /// <summary>The observation interacts with a queue.</summary>
    Queue,
    /// <summary>The observation reads randomness.</summary>
    Randomness,
}

/// <summary>Identifies how one Trigger ended.</summary>
public enum AutomaticTriggerCompletion
{
    /// <summary>A delivered task ended with an acknowledgment.</summary>
    Acknowledgment,
    /// <summary>A request-response operation returned.</summary>
    Return,
    /// <summary>An ordered stream reached its terminal item.</summary>
    StreamEnd,
    /// <summary>A delivered task ended without an acknowledgment.</summary>
    TaskEnd,
}

/// <summary>Binds one installed SDK to one reviewed project and subject.</summary>
public sealed class AutomaticProjectOptions
{
    /// <summary>Gets the reviewed repository identity.</summary>
    public required string BuildRepositoryId { get; init; }

    /// <summary>Gets the reviewed project configuration bytes.</summary>
    public required string ProjectToml { get; init; }

    /// <summary>Gets the project token only after a complete Failure.</summary>
    public Func<ManagedProjectToken>? ProjectTokenProvider { get; init; }

    /// <summary>Gets the immutable source revision.</summary>
    public required string SourceRevision { get; init; }

    /// <summary>Gets the optional exact subject entry assembly.</summary>
    public string? SubjectEntryAssembly { get; init; }
}

/// <summary>Describes one framework-neutral operation.</summary>
public sealed record AutomaticOperationStart(
    string AdapterId,
    string AdapterVersion,
    IReadOnlyList<string> CausalParentIds,
    AutomaticOperationKind Kind,
    string Name);

/// <summary>Contains one ordered, application-visible Trigger input.</summary>
public sealed record AutomaticInputChunk(
    AutomaticInputChannel Channel,
    string ContentType,
    byte[] Value);

/// <summary>Reports a local automatic capture failure without customer data.</summary>
public sealed class AutomaticCaptureException() : Exception(
    "Repro It could not capture the operation.");

/// <summary>Owns one shared native capture engine.</summary>
public sealed class AutomaticProject : IDisposable
{
    private readonly AutomaticHttpAdapterLease httpAdapter;
    private readonly AutomaticNativeGuardLease nativeGuard;
    private readonly SdkEngineBridge bridge;
    private readonly object stateLock = new();
    private readonly Func<ManagedProjectToken>? tokenProvider;
    private bool closed;
    private readonly SdkEngineHandle handle;
    private int sinkWaiters;

    private AutomaticProject(
        SdkEngineBridge bridge,
        SdkEngineHandle handle,
        Func<ManagedProjectToken>? tokenProvider,
        AutomaticHttpAdapterLease httpAdapter,
        AutomaticNativeGuardLease nativeGuard)
    {
        this.bridge = bridge;
        this.handle = handle;
        this.tokenProvider = tokenProvider;
        this.httpAdapter = httpAdapter;
        this.nativeGuard = nativeGuard;
    }

    /// <summary>Opens the packaged shared engine for one running .NET subject.</summary>
    public static AutomaticProject Open(AutomaticProjectOptions options)
    {
        SdkEngineBridge? bridge = null;
        try
        {
            bridge = SdkEngineBridge.OpenPackaged();
            _ = bridge.Contract();
            using DotnetSubjectPackage subject =
                ManagedSubject.PackageRunningDotnetSubject(options.SubjectEntryAssembly);
            return OpenWith(options, bridge, subject);
        }
        catch (Exception)
        {
            bridge?.Dispose();
            throw CaptureError();
        }
    }

    internal static AutomaticProject OpenWith(
        AutomaticProjectOptions options,
        SdkEngineBridge bridge,
        DotnetSubjectPackage subject)
    {
        AutomaticHttpAdapterLease? httpAdapter = null;
        AutomaticNativeGuardLease? nativeGuard = null;
        try
        {
            nativeGuard = AutomaticNativeGuard.Acquire(subject.AdapterImplementationDigest);
            httpAdapter = AutomaticHttpAdapter.Acquire(subject.AdapterImplementationDigest);
            List<SdkEngineSubjectObject> objects = subject.Objects
                .Select(value => value.Size > 0
                    ? new SdkEngineSubjectObject(
                        value.Digest, value.Path, checked((ulong)value.Size))
                    : throw CaptureError())
                .ToList();
            SdkEngineHandle handle = bridge.OpenEngine(new SdkEngineOpenOptions(
                options.BuildRepositoryId,
                options.ProjectToml,
                "dotnet",
                options.SourceRevision,
                subject.Manifest,
                objects));
            return new AutomaticProject(
                bridge, handle, options.ProjectTokenProvider, httpAdapter, nativeGuard);
        }
        catch (Exception)
        {
            httpAdapter?.Dispose();
            nativeGuard?.Dispose();
            bridge.Dispose();
            throw CaptureError();
        }
    }

    /// <summary>Starts one request-response, stream, or delivered-work operation.</summary>
    public AutomaticOperation StartOperation(AutomaticOperationStart start)
    {
        FuzzCampaignContext? fuzzContext = DistributedFuzz.Active();
        lock (stateLock)
        {
            if (closed)
            {
                throw CaptureError();
            }
            try
            {
                JsonArray causalParents = [];
                foreach (string parent in start.CausalParentIds)
                {
                    causalParents.Add(parent);
                }
                if (fuzzContext?.ParentOperationId is string parentOperationId &&
                    !start.CausalParentIds.Contains(parentOperationId, StringComparer.Ordinal))
                {
                    causalParents.Add(parentOperationId);
                }
                JsonObject begin = new()
                {
                    ["adapter_id"] = start.AdapterId,
                    ["adapter_version"] = start.AdapterVersion,
                    ["causal_parent_ids"] = causalParents,
                    ["format"] = fuzzContext is null
                        ? "reproit.operation-begin.v1"
                        : "reproit.operation-begin.v2",
                    ["operation_kind"] = OperationKind(start.Kind),
                    ["operation_name"] = start.Name,
                };
                if (fuzzContext is not null)
                {
                    begin["campaign_context"] = fuzzContext.BeginIdentity();
                }
                SdkEngineOperationStart operation = bridge.BeginOperation(
                    handle,
                    begin,
                    fuzzContext?.NativeInput());
                AutomaticOperation result = new(this, bridge, operation, fuzzContext);
                result.ActivateAutomatically();
                return result;
            }
            catch (Exception)
            {
                throw CaptureError();
            }
        }
    }

    internal string ProjectToken()
    {
        try
        {
            return tokenProvider?.Invoke().SdkEngineValue is string value && value.Length > 0
                ? value
                : throw CaptureError();
        }
        catch (Exception)
        {
            throw CaptureError();
        }
    }

    internal void StartSinkWait(SdkEngineSinkHandle sink)
    {
        lock (stateLock)
        {
            if (closed || sinkWaiters >= SdkEngineBridge.MaxSinkWaiters)
            {
                return;
            }
            sinkWaiters += 1;
        }
        _ = Task.Run(async () =>
        {
            long started = Stopwatch.GetTimestamp();
            try
            {
                while (!Volatile.Read(ref closed) &&
                    Stopwatch.GetElapsedTime(started).TotalMilliseconds <
                        SdkEngineBridge.SinkWaitMilliseconds)
                {
                    try
                    {
                        if (bridge.WaitForSink(sink, 0))
                        {
                            return;
                        }
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    await Task.Delay(25).ConfigureAwait(false);
                }
            }
            finally
            {
                lock (stateLock)
                {
                    sinkWaiters -= 1;
                }
            }
        });
    }

    /// <summary>Deletes active shared-engine state.</summary>
    public void Dispose()
    {
        lock (stateLock)
        {
            if (closed)
            {
                return;
            }
            Volatile.Write(ref closed, true);
            try
            {
                bridge.CloseEngine(handle);
            }
            catch (Exception)
            {
                // Shared-engine cleanup must not change application behavior.
            }
            bridge.Dispose();
            httpAdapter.Dispose();
            nativeGuard.Dispose();
        }
    }

    private static string OperationKind(AutomaticOperationKind value) => value switch
    {
        AutomaticOperationKind.RequestResponse => "request-response",
        AutomaticOperationKind.Stream => "stream",
        AutomaticOperationKind.DeliveredWork => "delivered-work",
        _ => throw CaptureError(),
    };

    internal static AutomaticCaptureException CaptureError() => new();
}

/// <summary>Owns one shared-engine operation until a terminal action.</summary>
public sealed class AutomaticOperation : IDisposable
{
    private readonly HashSet<AutomaticOperationActivation> activations = [];
    private const int MaxInputBytes = 65_536;
    private const int MaxInputs = 1_024;
    private readonly SdkEngineBridge bridge;
    private bool finished;
    private readonly SdkEngineOperationHandle handle;
    private ushort inputIndex;
    private readonly object stateLock = new();
    private readonly AutomaticProject project;
    private bool worldComplete;
    private AutomaticOperationActivation? automaticActivation;

    internal AutomaticOperation(
        AutomaticProject project,
        SdkEngineBridge bridge,
        SdkEngineOperationStart operation,
        FuzzCampaignContext? fuzzContext = null)
    {
        this.project = project;
        this.bridge = bridge;
        handle = operation.Handle;
        OperationId = operation.OperationId;
        FuzzContext = fuzzContext?.WithParent(OperationId);
    }

    /// <summary>Gets the stable identity for causal child operations.</summary>
    public string OperationId { get; }

    internal FuzzCampaignContext? FuzzContext { get; }

    internal AutomaticOperationActivation Activate() =>
        AutomaticOperationContext.Activate(this);

    internal void ActivateAutomatically()
    {
        if (automaticActivation is not null)
        {
            throw AutomaticProject.CaptureError();
        }
        automaticActivation = AutomaticOperationContext.Activate(this);
    }

    internal bool IsActive()
    {
        lock (stateLock)
        {
            return !finished && !worldComplete;
        }
    }

    internal void RegisterActivation(AutomaticOperationActivation activation)
    {
        lock (stateLock)
        {
            if (finished || worldComplete)
            {
                throw AutomaticProject.CaptureError();
            }
            activations.Add(activation);
        }
    }

    internal void UnregisterActivation(AutomaticOperationActivation activation)
    {
        lock (stateLock)
        {
            activations.Remove(activation);
        }
    }

    /// <summary>Records one ordered Trigger input chunk.</summary>
    public void RecordInput(AutomaticInputChunk input)
    {
        lock (stateLock)
        {
            if (finished || input.Value.Length > MaxInputBytes || inputIndex >= MaxInputs)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                bridge.RecordInput(handle, new JsonObject
                {
                    ["channel"] = InputChannel(input.Channel),
                    ["content_type"] = input.ContentType,
                    ["format"] = "reproit.operation-input.v1",
                    ["input_index"] = inputIndex,
                    ["value"] = EncodeBase64Url(input.Value),
                    ["value_digest"] = SubjectProtocol.DigestBytes(input.Value),
                });
                inputIndex += 1;
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal ObservationSession OpenObservationSession(
        AutomaticObservationClass observationClass,
        string? causalParentId)
    {
        lock (stateLock)
        {
            if (finished || worldComplete)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                SdkEngineObservationStart start = bridge.OpenObservation(
                    handle, ObservationClass(observationClass), causalParentId);
                return new ObservationSession(bridge, start);
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal SdkEngineDependencyConnection OpenSemanticDependency(
        JsonObject request,
        string? causalParentId)
    {
        lock (stateLock)
        {
            if (finished || worldComplete)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                SdkEngineDependencyStart start = bridge.OpenDependency(
                    handle, causalParentId, request);
                return new SdkEngineDependencyConnection(bridge, start);
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal void MarkUnowned(
        AutomaticObservationClass observationClass,
        string? causalParentId,
        byte[] evidence)
    {
        lock (stateLock)
        {
            if (finished || worldComplete)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                bridge.MarkOperationUnowned(
                    handle, ObservationClass(observationClass), causalParentId, evidence);
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    internal void CloseWorld(AutomaticTriggerCompletion completion)
    {
        lock (stateLock)
        {
            CloseWorldLocked(completion);
        }
    }

    /// <summary>Deletes one successful operation without delivery.</summary>
    public void Succeed()
    {
        lock (stateLock)
        {
            if (finished)
            {
                return;
            }
            try
            {
                bridge.SucceedOperation(handle);
            }
            catch (Exception)
            {
                try
                {
                    bridge.AbandonOperation(handle);
                }
                catch (Exception)
                {
                    // Capture cleanup must not change application behavior.
                }
            }
            FinishLocked();
        }
    }

    /// <summary>Deletes one cancelled operation without delivery.</summary>
    public void Cancel() => Dispose();

    /// <summary>Closes the World and sends one typed Failure to the shared engine.</summary>
    public void Fail(AutomaticTriggerCompletion completion, JsonObject failureIdentity)
    {
        lock (stateLock)
        {
            if (finished)
            {
                throw AutomaticProject.CaptureError();
            }
            try
            {
                if (!worldComplete)
                {
                    CloseWorldLocked(completion);
                }
                SdkEngineSinkHandle sink = bridge.FailOperation(
                    handle, failureIdentity, project.ProjectToken());
                FinishLocked();
                project.StartSinkWait(sink);
            }
            catch (Exception)
            {
                AbandonLocked();
                throw AutomaticProject.CaptureError();
            }
        }
    }

    /// <summary>Deletes one unfinished operation.</summary>
    public void Dispose()
    {
        lock (stateLock)
        {
            AbandonLocked();
        }
    }

    private void CloseWorldLocked(AutomaticTriggerCompletion completion)
    {
        if (finished || worldComplete)
        {
            throw AutomaticProject.CaptureError();
        }
        try
        {
            bridge.CloseOperationWorld(handle, Completion(completion));
            worldComplete = true;
        }
        catch (Exception)
        {
            AbandonLocked();
            throw AutomaticProject.CaptureError();
        }
    }

    private void AbandonLocked()
    {
        if (finished)
        {
            return;
        }
        try
        {
            bridge.AbandonOperation(handle);
        }
        catch (Exception)
        {
            // Capture cleanup must not change application behavior.
        }
        FinishLocked();
    }

    private void FinishLocked()
    {
        finished = true;
        if (automaticActivation is AutomaticOperationActivation activation)
        {
            automaticActivation = null;
            AutomaticOperationContext.Deactivate(activation);
        }
        foreach (AutomaticOperationActivation remainingActivation in activations)
        {
            remainingActivation.ClearOperation(this);
        }
        activations.Clear();
    }

    private static string InputChannel(AutomaticInputChannel value) => value switch
    {
        AutomaticInputChannel.Control => "control",
        AutomaticInputChannel.Input => "input",
        AutomaticInputChannel.Metadata => "metadata",
        _ => throw AutomaticProject.CaptureError(),
    };

    internal static string ObservationClass(AutomaticObservationClass value) => value switch
    {
        AutomaticObservationClass.Clock => "clock",
        AutomaticObservationClass.Database => "database",
        AutomaticObservationClass.Environment => "environment",
        AutomaticObservationClass.Filesystem => "filesystem",
        AutomaticObservationClass.OutboundHttp => "outbound-http",
        AutomaticObservationClass.Queue => "queue",
        AutomaticObservationClass.Randomness => "randomness",
        _ => throw AutomaticProject.CaptureError(),
    };

    private static string Completion(AutomaticTriggerCompletion value) => value switch
    {
        AutomaticTriggerCompletion.Acknowledgment => "acknowledgment",
        AutomaticTriggerCompletion.Return => "return",
        AutomaticTriggerCompletion.StreamEnd => "stream-end",
        AutomaticTriggerCompletion.TaskEnd => "task-end",
        _ => throw AutomaticProject.CaptureError(),
    };

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed class AutomaticOperationActivation : IDisposable
{
    private AutomaticOperation? operation;

    internal AutomaticOperationActivation(
        AutomaticOperation operation,
        AutomaticOperationActivation? parent)
    {
        this.operation = operation;
        Parent = parent;
    }

    internal AutomaticOperation? Operation => Volatile.Read(ref operation);

    internal AutomaticOperationActivation? Parent { get; }

    public void Dispose() => AutomaticOperationContext.Deactivate(this);

    internal void ClearOperation(AutomaticOperation expected)
    {
        _ = Interlocked.CompareExchange(ref operation, null, expected);
    }

    internal AutomaticOperation? ReleaseOperation() =>
        Interlocked.Exchange(ref operation, null);
}

internal static class AutomaticOperationContext
{
    private static readonly AsyncLocal<AutomaticOperationActivation?> Current = new();

    internal static AutomaticOperationActivation Activate(AutomaticOperation operation)
    {
        AutomaticOperationActivation activation = new(operation, Current.Value);
        operation.RegisterActivation(activation);
        Current.Value = activation;
        return activation;
    }

    internal static AutomaticOperation? ActiveOperation()
    {
        AutomaticOperationActivation? activation = Current.Value;
        for (int depth = 0; activation is not null && depth < 64; depth += 1)
        {
            AutomaticOperation? operation = activation.Operation;
            if (operation is not null && operation.IsActive())
            {
                return operation;
            }
            activation = activation.Parent;
        }
        return null;
    }

    internal static void Deactivate(AutomaticOperationActivation activation)
    {
        if (ReferenceEquals(Current.Value, activation))
        {
            Current.Value = activation.Parent;
        }
        activation.ReleaseOperation()?.UnregisterActivation(activation);
    }
}
