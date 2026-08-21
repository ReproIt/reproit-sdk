using System.Text;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Holds one initial World ID and its completion operation.</summary>
public sealed record ManagedWorldCapture(
    string WorldId,
    Func<string, FrozenManagedCaptureClosure> Complete);

/// <summary>Records dependency cursors for one application operation.</summary>
public sealed class OperationCapture
{
    private readonly List<JsonNode> dependencies = [];
    private readonly object stateLock = new();
    private bool valid = true;

    internal OperationCapture(string? operationId)
    {
        OperationId = operationId;
    }

    /// <summary>Gets the package-owned operation ID when capture is active.</summary>
    public string? OperationId { get; }

    internal IReadOnlyList<JsonNode>? Dependencies
    {
        get
        {
            lock (stateLock)
            {
                return valid
                    ? dependencies.Select(value => value.DeepClone()).ToArray()
                    : null;
            }
        }
    }

    /// <summary>Records one bounded dependency cursor.</summary>
    public void RecordDependency(JsonNode dependency)
    {
        lock (stateLock)
        {
            if (!valid)
            {
                return;
            }
            try
            {
                JsonNode copied = dependency.DeepClone();
                if (dependencies.Count >= Sdk.MaxEvents ||
                    CanonicalJson.Bytes(copied).Length > Sdk.MaxEventBytes)
                {
                    valid = false;
                    dependencies.Clear();
                    return;
                }
                dependencies.Add(copied);
            }
            catch (Exception)
            {
                valid = false;
                dependencies.Clear();
            }
        }
    }
}

/// <summary>Captures operations through the official managed SDK entry.</summary>
public sealed class ReproItCapture
{
    private const int MaxCapturedInputBytes = 32 * 1_024;
    private const int MaxContentTypeBytes = 256;
    private const int MaxOperationNameBytes = 128;

    private readonly OfficialManagedProject project;
    private readonly Func<ManagedWorldCapture> worldCapture;

    /// <summary>Validates one reviewed build and prepares application capture.</summary>
    public ReproItCapture(
        JsonObject project,
        string buildRepositoryId,
        string sourceRevision,
        Func<ManagedWorldCapture> worldCapture)
    {
        this.project = new OfficialManagedProject(
            project, buildRepositoryId, sourceRevision);
        this.worldCapture = worldCapture ?? throw new ArgumentNullException(nameof(worldCapture));
    }

    /// <summary>Runs one operation and preserves its exact return or exception.</summary>
    public T Run<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, T> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => RunKind(
            "request-response", operationName, contentType, input,
            operation, classifyFailure);

    /// <summary>Runs one ordered stream operation.</summary>
    public T RunStream<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, T> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => RunKind(
            "stream", operationName, contentType, input,
            operation, classifyFailure);

    /// <summary>Runs one delivered-work operation.</summary>
    public T RunDeliveredWork<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, T> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => RunKind(
            "delivered-work", operationName, contentType, input,
            operation, classifyFailure);

    private T RunKind<T>(
        string operationKind,
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, T> operation,
        Func<Exception, JsonNode?> classifyFailure)
    {
        ActiveOperation? active = StartOperation(
            operationKind, operationName, contentType, input);
        OperationCapture context = active?.Context ?? new OperationCapture(null);
        try
        {
            return operation(context);
        }
        catch (Exception original)
        {
            CaptureFailure(active, original, classifyFailure);
            throw;
        }
    }

    /// <summary>Runs one asynchronous operation and preserves its exact result.</summary>
    public async Task<T> RunAsync<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, Task<T>> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => await RunKindAsync(
            "request-response", operationName, contentType, input,
            operation, classifyFailure).ConfigureAwait(false);

    /// <summary>Runs one asynchronous ordered stream operation.</summary>
    public async Task<T> RunStreamAsync<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, Task<T>> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => await RunKindAsync(
            "stream", operationName, contentType, input,
            operation, classifyFailure).ConfigureAwait(false);

    /// <summary>Runs one asynchronous delivered-work operation.</summary>
    public async Task<T> RunDeliveredWorkAsync<T>(
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, Task<T>> operation,
        Func<Exception, JsonNode?> classifyFailure)
        => await RunKindAsync(
            "delivered-work", operationName, contentType, input,
            operation, classifyFailure).ConfigureAwait(false);

    private async Task<T> RunKindAsync<T>(
        string operationKind,
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input,
        Func<OperationCapture, Task<T>> operation,
        Func<Exception, JsonNode?> classifyFailure)
    {
        ActiveOperation? active = StartOperation(
            operationKind, operationName, contentType, input);
        OperationCapture context = active?.Context ?? new OperationCapture(null);
        try
        {
            return await operation(context).ConfigureAwait(false);
        }
        catch (Exception original)
        {
            CaptureFailure(active, original, classifyFailure);
            throw;
        }
    }

    private ActiveOperation? StartOperation(
        string operationKind,
        string operationName,
        string contentType,
        ReadOnlyMemory<byte> input)
    {
        try
        {
            if ((operationKind != "request-response" &&
                operationKind != "stream" &&
                operationKind != "delivered-work") ||
                operationName.Length == 0 ||
                Encoding.UTF8.GetByteCount(operationName) > MaxOperationNameBytes ||
                contentType.Length == 0 ||
                Encoding.UTF8.GetByteCount(contentType) > MaxContentTypeBytes ||
                input.Length > MaxCapturedInputBytes)
            {
                return null;
            }
            ManagedWorldCapture world = worldCapture();
            OfficialManagedOperation operation = project.StartOperation(world.WorldId);
            return new ActiveOperation(
                operation,
                world,
                operationKind,
                operationName,
                contentType,
                input.ToArray(),
                new OperationCapture(operation.OperationId));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static void CaptureFailure(
        ActiveOperation? active,
        Exception original,
        Func<Exception, JsonNode?> classifyFailure)
    {
        if (active is null)
        {
            return;
        }
        try
        {
            IReadOnlyList<JsonNode>? dependencies = active.Context.Dependencies;
            JsonNode? failure = classifyFailure(original);
            if (dependencies is null || failure is null)
            {
                return;
            }
            FrozenManagedCaptureClosure closure =
                active.World.Complete(active.Operation.OperationId);
            ManagedCandidateSink sink = active.Operation.CandidateSink(
                closure,
                () => new ManagedProjectToken(
                    Environment.GetEnvironmentVariable("REPROIT_MANAGED_PROJECT_TOKEN") ?? ""));
            Sdk sdk = new(sink);
            sdk.Begin(
                active.Start,
                OperationBegin(active.OperationKind, active.OperationName));
            sdk.RecordInput(
                active.Operation.OperationId,
                OperationInput(active.ContentType, active.Input));
            foreach (JsonNode dependency in dependencies)
            {
                sdk.RecordDependency(active.Operation.OperationId, dependency);
            }
            sdk.Fail(active.Operation.OperationId, failure);
        }
        catch (Exception)
        {
            // Capture failure must not change application behavior.
        }
    }

    private static JsonObject OperationBegin(
        string operationKind, string operationName) => new()
    {
        ["adapter_id"] = "sdk",
        ["adapter_version"] = "1.0.0",
        ["causal_parent_ids"] = new JsonArray(),
        ["format"] = "reproit.operation-begin.v1",
        ["operation_kind"] = operationKind,
        ["operation_name"] = operationName,
    };

    private static JsonObject OperationInput(string contentType, byte[] value) => new()
    {
        ["channel"] = "input",
        ["content_type"] = contentType,
        ["format"] = "reproit.operation-input.v1",
        ["input_index"] = 0,
        ["value"] = ManagedProtocol.EncodeBase64Url(value),
        ["value_digest"] = ManagedProtocol.DigestBytes(value),
    };

    private sealed record ActiveOperation(
        OfficialManagedOperation Operation,
        ManagedWorldCapture World,
        string OperationKind,
        string OperationName,
        string ContentType,
        byte[] Input,
        OperationCapture Context)
    {
        public CandidateStart Start => new(
            Operation.CaptureId,
            Operation.Deployment,
            Operation.OperationId,
            Operation.WorldId);
    }
}
