using System.Diagnostics;
using System.Globalization;
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
    private const int MaxProjectBytes = 65_536;
    private const int MaxProjectSearchDepth = 64;

    private OfficialManagedProject? project;
    private readonly Func<ManagedWorldCapture> worldCapture;

    private ReproItCapture()
    {
        project = null;
        worldCapture = AutomaticWorldCapture;
    }

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

    /// <summary>Loads the reviewed project and prepares fail-open capture.</summary>
    public static ReproItCapture Init()
    {
        ReproItCapture capture = new();
        try
        {
            string projectFile = FindProjectFile();
            JsonObject project = ParseProjectConfig(File.ReadAllBytes(projectFile));
            string? repositoryId = project["repository_id"]?.GetValue<string>();
            if (repositoryId is null)
            {
                return capture;
            }
            string projectRoot = Directory.GetParent(
                Path.GetDirectoryName(projectFile)!)!.FullName;
            string sourceRevision = GitSourceRevision(projectRoot);
            capture.project = new OfficialManagedProject(
                project, repositoryId, sourceRevision);
        }
        catch (Exception)
        {
            // Initialization failure disables capture without changing the application.
        }
        return capture;
    }

    /// <summary>Runs one framework-neutral operation and preserves its exact result.</summary>
    public T Operation<T>(
        string operationName,
        ReadOnlyMemory<byte> input,
        Func<T> operation)
        => Run(
            operationName,
            "application/octet-stream",
            input,
            _ => operation(),
            error => ExceptionFailure(operationName, error));

    /// <summary>Runs one asynchronous framework-neutral operation.</summary>
    public async Task<T> OperationAsync<T>(
        string operationName,
        ReadOnlyMemory<byte> input,
        Func<Task<T>> operation)
        => await RunAsync(
            operationName,
            "application/octet-stream",
            input,
            _ => operation(),
            error => ExceptionFailure(operationName, error)).ConfigureAwait(false);

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
            if (project is null)
            {
                return null;
            }
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
            CaptureFailurePayload(active, failure, dependencies);
        }
        catch (Exception)
        {
            // Capture failure must not change application behavior.
        }
    }

    private static void CaptureFailurePayload(
        ActiveOperation active,
        JsonNode failure,
        IReadOnlyList<JsonNode>? dependencies = null)
    {
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
        foreach (JsonNode dependency in dependencies ?? [])
        {
            sdk.RecordDependency(active.Operation.OperationId, dependency);
        }
        sdk.Fail(active.Operation.OperationId, failure);
    }

    private static JsonObject ExceptionFailure(
        string operationName, Exception original)
    {
        string type = original.GetType().FullName ?? original.GetType().Name;
        return FailurePayload("exception", operationName, type, type);
    }

    private static JsonObject FailurePayload(
        string category,
        string operationName,
        string stableCode,
        string type)
    {
        JsonObject identity = new()
        {
            ["category"] = category,
            ["cause_types"] = new JsonArray(),
            ["frames"] = new JsonArray(),
            ["operation_kind"] = "request-response",
            ["operation_name"] = operationName,
            ["runtime_family"] = "dotnet",
            ["schema"] = "reproit.failure.v1",
            ["stable_code"] = stableCode,
            ["type"] = type,
        };
        return new JsonObject
        {
            ["failure"] = new JsonObject
            {
                ["category"] = category,
                ["identity"] = ManagedProtocol.CanonicalDigest(identity),
                ["matcher"] = "exception-exact-v1",
                ["object_id"] = ManagedProtocol.NewObjectId(),
                ["schema"] = "reproit.failure.v1",
            },
            ["format"] = "reproit.failure-payload.v1",
            ["identity"] = identity,
        };
    }

    private static ManagedWorldCapture AutomaticWorldCapture()
    {
        JsonObject world = new()
        {
            ["created_at"] = DateTimeOffset.UtcNow.ToString(
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
            ["format"] = "reproit.world-checkpoint.v1",
            ["points"] = new JsonArray(),
        };
        string worldId = ManagedProtocol.CanonicalDigest(world);
        return new ManagedWorldCapture(
            worldId,
            _ => new FrozenManagedCaptureClosure(
                new ManagedCaptureClosure([], "return", (JsonObject)world.DeepClone())));
    }

    private static bool ValidBoundary(
        string operationName, string contentType, ReadOnlySpan<byte> input) =>
        operationName.Length > 0 &&
        Encoding.UTF8.GetByteCount(operationName) <= MaxOperationNameBytes &&
        contentType.Length > 0 &&
        Encoding.UTF8.GetByteCount(contentType) <= MaxContentTypeBytes &&
        input.Length <= MaxCapturedInputBytes;

    private static string FindProjectFile()
    {
        DirectoryInfo? directory = new(Environment.CurrentDirectory);
        for (int depth = 0; depth < MaxProjectSearchDepth && directory is not null; depth += 1)
        {
            DirectoryInfo configurationDirectory = new(Path.Combine(
                directory.FullName, ".reproit"));
            FileInfo candidate = new(Path.Combine(
                configurationDirectory.FullName, "project.toml"));
            if (configurationDirectory.Exists &&
                configurationDirectory.LinkTarget is null &&
                candidate.Exists && candidate.LinkTarget is null &&
                candidate.Length <= MaxProjectBytes)
            {
                return candidate.FullName;
            }
            directory = directory.Parent;
        }
        throw new InvalidOperationException(
            "Repro It could not load the reviewed project configuration.");
    }

    private static JsonObject ParseProjectConfig(byte[] bytes)
    {
        if (bytes.Length > MaxProjectBytes)
        {
            throw new InvalidOperationException(
                "The Repro It project configuration is invalid.");
        }
        JsonObject project = [];
        foreach (string sourceLine in Encoding.UTF8.GetString(bytes).Split('\n'))
        {
            string line = sourceLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            if (line.StartsWith('['))
            {
                break;
            }
            int separator = line.IndexOf('=');
            if (separator <= 0)
            {
                throw new InvalidOperationException(
                    "The Repro It project configuration is invalid.");
            }
            string key = line[..separator].Trim();
            string raw = line[(separator + 1)..].Trim();
            if (key.Length == 0 || project.ContainsKey(key))
            {
                throw new InvalidOperationException(
                    "The Repro It project configuration is invalid.");
            }
            JsonNode? value = raw.StartsWith('"')
                ? JsonNode.Parse(raw)
                : int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out int number)
                    ? JsonValue.Create(number)
                    : null;
            if (value is null || value is not JsonValue)
            {
                throw new InvalidOperationException(
                    "The Repro It project configuration is invalid.");
            }
            project[key] = value;
        }
        return project;
    }

    private static string GitSourceRevision(string projectRoot)
    {
        using Process process = new()
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                WorkingDirectory = projectRoot,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };
        process.StartInfo.ArgumentList.Add("rev-parse");
        process.StartInfo.ArgumentList.Add("--verify");
        process.StartInfo.ArgumentList.Add("HEAD");
        if (!process.Start() || !process.WaitForExit(2_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
                // The process can exit between the timeout and cleanup.
            }
            throw new InvalidOperationException(
                "Repro It could not identify the deployed source revision.");
        }
        string revision = process.StandardOutput.ReadToEnd().Trim();
        string standardError = process.StandardError.ReadToEnd();
        if (process.ExitCode != 0 || standardError.Length != 0 ||
            revision.Length is not (40 or 64) ||
            revision.Any(character => character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f')))
        {
            throw new InvalidOperationException(
                "Repro It could not identify the deployed source revision.");
        }
        return revision;
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
