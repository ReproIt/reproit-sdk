using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Reports a local capture that is incomplete or exceeds a fixed bound.</summary>
public sealed class CaptureException(string message) : Exception(message);

/// <summary>Supplies the immutable identity needed to start one operation capture.</summary>
public sealed record CandidateStart(
    string CaptureId,
    JsonNode Deployment,
    string OperationId,
    string WorldId
);

/// <summary>Accepts complete failed candidates without blocking an application operation.</summary>
public interface ICandidateSink
{
    /// <summary>Reports whether this sink accepts one processing mode.</summary>
    bool AllowsProcessingMode(string mode);

    /// <summary>Gets the current queued candidate bytes.</summary>
    int QueuedBytes { get; }

    /// <summary>Tries to enqueue one complete candidate.</summary>
    bool TrySend(string captureId, ReadOnlyMemory<byte> candidate);
}

/// <summary>Contains bounded local recall counters without customer values.</summary>
public sealed record SdkRecallCounters(
    ulong CandidateDeliveryExpired,
    ulong CandidateDurablyAccepted,
    ulong CandidateIncomplete,
    ulong CandidateQueueFull,
    ulong CandidateRejected,
    ulong EligibleFailureObserved,
    ulong SuppressedExactStorm,
    ulong SuppressedHighCardinalityStorm)
{
    internal SdkRecallCounters Merge(SdkRecallCounters other) => new(
        Add(CandidateDeliveryExpired, other.CandidateDeliveryExpired),
        Add(CandidateDurablyAccepted, other.CandidateDurablyAccepted),
        Add(CandidateIncomplete, other.CandidateIncomplete),
        Add(CandidateQueueFull, other.CandidateQueueFull),
        Add(CandidateRejected, other.CandidateRejected),
        Add(EligibleFailureObserved, other.EligibleFailureObserved),
        Add(SuppressedExactStorm, other.SuppressedExactStorm),
        Add(SuppressedHighCardinalityStorm, other.SuppressedHighCardinalityStorm));

    private static ulong Add(ulong left, ulong right) =>
        right >= (ulong)long.MaxValue - left ? (ulong)long.MaxValue : left + right;
}

internal interface IRecallCounterSource
{
    SdkRecallCounters RecallCounters { get; }
}

/// <summary>Owns bounded active records and sends complete failed candidates only.</summary>
public sealed class Sdk
{
    /// <summary>The global active and queued byte bound.</summary>
    public const int MaxGlobalBytes = 1_048_576;
    /// <summary>The per-operation byte bound.</summary>
    public const int MaxOperationBytes = 262_144;
    /// <summary>The per-event byte bound.</summary>
    public const int MaxEventBytes = 65_536;
    /// <summary>The event-count bound.</summary>
    public const int MaxEvents = 1_024;
    /// <summary>The concurrent active-operation bound.</summary>
    public const int MaxActiveOperations = 512;

    private readonly Dictionary<string, ActiveOperation> operations = [];
    private readonly object stateLock = new();
    private readonly ICandidateSink sink;
    private readonly bool allowPrivate;
    private readonly MutableRecallCounters recall = new();

    /// <summary>Creates an SDK with one bounded local candidate sink.</summary>
    public Sdk(ICandidateSink sink) : this(sink, allowPrivate: false)
    {
    }

    internal Sdk(ICandidateSink sink, bool allowPrivate)
    {
        this.sink = sink ?? new DiscardCandidateSink();
        this.allowPrivate = allowPrivate;
    }

    /// <summary>Gets the active operation count.</summary>
    public int ActiveOperations
    {
        get
        {
            lock (stateLock)
            {
                return operations.Count;
            }
        }
    }

    /// <summary>Gets a bounded snapshot of local capture outcomes.</summary>
    public SdkRecallCounters RecallCounters
    {
        get
        {
            lock (stateLock)
            {
                return recall.Snapshot().Merge(
                    sink is IRecallCounterSource source
                        ? source.RecallCounters
                        : new SdkRecallCounters(0, 0, 0, 0, 0, 0, 0, 0));
            }
        }
    }

    /// <summary>Starts one operation with its immutable begin record.</summary>
    public void Begin(CandidateStart start, JsonNode value)
    {
        if (!CandidateProtocol.ValidPrefixedUuid7(start.CaptureId, "cap_") ||
            !CandidateProtocol.ValidPrefixedUuid7(start.OperationId, "op_") ||
            !CandidateProtocol.ValidDigest(start.WorldId) ||
            start.Deployment["processing_mode"]?.GetValue<string>() is not string mode ||
            mode != "managed" && !(allowPrivate && mode == "private"))
        {
            throw Incomplete();
        }
        EventRecord record = CreateRecord("begin", 0, value);
        int size = RecordSize(record);
        lock (stateLock)
        {
            if (operations.ContainsKey(start.OperationId))
            {
                throw new CaptureException("The operation already has capture state.");
            }
            if (!SdkProcessResources.ReserveOperation(start.OperationId, size))
            {
                throw Limit();
            }
            CandidateStart snapshot = start with { Deployment = start.Deployment.DeepClone() };
            operations.Add(start.OperationId, new ActiveOperation(size, [record], snapshot));
        }
    }

    /// <summary>Appends one ordered semantic input record.</summary>
    public void RecordInput(string operationId, JsonNode value)
    {
        Append(operationId, "input", value);
    }

    /// <summary>Appends one dependency cursor record.</summary>
    public void RecordDependency(string operationId, JsonNode value)
    {
        Append(operationId, "dependency", value);
    }

    /// <summary>Deletes a successful operation without delivery.</summary>
    public void Succeed(string operationId)
    {
        lock (stateLock)
        {
            Delete(operationId);
        }
    }

    /// <summary>Deletes a cancelled operation without delivery.</summary>
    public void Cancel(string operationId) => Succeed(operationId);

    /// <summary>Deletes incomplete local state and records the outcome.</summary>
    public void AbandonIncomplete(string operationId)
    {
        lock (stateLock)
        {
            if (!operations.ContainsKey(operationId))
            {
                return;
            }
            Delete(operationId);
            recall.IncrementCandidateIncomplete();
        }
    }

    /// <summary>Freezes and enqueues one complete failed candidate.</summary>
    public void Fail(string operationId, JsonNode value)
    {
        lock (stateLock)
        {
            recall.IncrementEligibleFailureObserved();
            if (!operations.TryGetValue(operationId, out ActiveOperation? active))
            {
                recall.IncrementCandidateIncomplete();
                throw Incomplete();
            }
            EventRecord failure;
            try
            {
                failure = CreateRecord("failure", active.Records.Count, value);
            }
            catch
            {
                recall.IncrementCandidateIncomplete();
                throw;
            }
            finally
            {
                Delete(operationId);
            }
            int failureSize = RecordSize(failure);
            if (!WithinOperation(active, failureSize))
            {
                recall.IncrementCandidateIncomplete();
                throw Limit();
            }
            active.Records.Add(failure);
            JsonNode terminalValue = new JsonObject
            {
                ["complete"] = true,
                ["event_count"] = active.Records.Count,
                ["format"] = "reproit.terminal.v1",
            };
            EventRecord terminal = CreateRecord("terminal", active.Records.Count, terminalValue);
            if (active.Bytes + failureSize + RecordSize(terminal) > MaxOperationBytes)
            {
                recall.IncrementCandidateIncomplete();
                throw Limit();
            }
            active.Records.Add(terminal);
            JsonNode? failureReference = value["failure"]?.DeepClone();
            if (failureReference is null)
            {
                recall.IncrementCandidateIncomplete();
                throw Incomplete();
            }
            JsonArray records = [];
            foreach (EventRecord record in active.Records)
            {
                records.Add(record.ToJson());
            }
            JsonNode candidate = new JsonObject
            {
                ["capture_id"] = active.Start.CaptureId,
                ["deployment"] = active.Start.Deployment.DeepClone(),
                ["failure"] = failureReference,
                ["format"] = "reproit.candidate.v1",
                ["operation_id"] = operationId,
                ["processing_mode"] = active.Start.Deployment["processing_mode"]?.DeepClone(),
                ["records"] = records,
                ["world_id"] = active.Start.WorldId,
            };
            try
            {
                CandidateProtocol.Validate(candidate);
            }
            catch (CaptureException)
            {
                recall.IncrementCandidateIncomplete();
                throw;
            }
            if (!AdmitFailure(candidate, value))
            {
                return;
            }
            byte[] encoded = CanonicalJson.Bytes(candidate);
            string mode = candidate["processing_mode"]!.GetValue<string>();
            if (!sink.AllowsProcessingMode(mode))
            {
                recall.IncrementCandidateRejected();
                throw Incomplete();
            }
            if (encoded.Length > MaxOperationBytes ||
                !sink.TrySend(active.Start.CaptureId, encoded))
            {
                recall.IncrementCandidateQueueFull();
                throw Limit();
            }
        }
    }

    private bool AdmitFailure(JsonNode candidate, JsonNode value)
    {
        JsonNode? identity = value["identity"];
        JsonNode? failure = value["failure"];
        JsonNode? deployment = candidate["deployment"];
        JsonNode? subject = deployment?["subject"];
        if (identity is null || failure is null || deployment is null || subject is null)
        {
            throw Incomplete();
        }
        JsonObject stable = new()
        {
            ["failure_identity_digest"] = failure["identity"]?.DeepClone(),
            ["format"] = "reproit.failure-storm-identity.v1",
            ["operation_kind"] = identity["operation_kind"]?.DeepClone(),
            ["operation_name"] = identity["operation_name"]?.DeepClone(),
            ["service_id"] = deployment["service_id"]?.DeepClone(),
            ["source_revision"] = deployment["source_revision"]?.DeepClone(),
            ["subject_artifact_digest"] = subject["artifact_digest"]?.DeepClone(),
        };
        if (stable.Any(part => part.Value is null))
        {
            throw Incomplete();
        }
        string key = Convert.ToHexString(SHA256.HashData(CanonicalJson.Bytes(stable)));
        FailureAdmission admission = SdkProcessResources.AdmitFailure(key);
        if (admission == FailureAdmission.SuppressedExact)
        {
            recall.IncrementSuppressedExactStorm();
            return false;
        }
        if (admission == FailureAdmission.SuppressedHighCardinality)
        {
            recall.IncrementSuppressedHighCardinalityStorm();
            return false;
        }
        return true;
    }

    private sealed class MutableRecallCounters
    {
        private const ulong Maximum = long.MaxValue;
        private ulong candidateIncomplete;
        private ulong candidateQueueFull;
        private ulong candidateRejected;
        private ulong eligibleFailureObserved;
        private ulong suppressedExactStorm;
        private ulong suppressedHighCardinalityStorm;

        public void IncrementCandidateIncomplete() => Increment(ref candidateIncomplete);
        public void IncrementCandidateQueueFull() => Increment(ref candidateQueueFull);
        public void IncrementCandidateRejected() => Increment(ref candidateRejected);
        public void IncrementEligibleFailureObserved() => Increment(ref eligibleFailureObserved);
        public void IncrementSuppressedExactStorm() => Increment(ref suppressedExactStorm);
        public void IncrementSuppressedHighCardinalityStorm() =>
            Increment(ref suppressedHighCardinalityStorm);

        public SdkRecallCounters Snapshot() => new(
            0, 0, candidateIncomplete, candidateQueueFull, candidateRejected,
            eligibleFailureObserved, suppressedExactStorm, suppressedHighCardinalityStorm);

        private static void Increment(ref ulong counter)
        {
            if (counter < Maximum)
            {
                counter += 1;
            }
        }
    }

    private void Append(string operationId, string kind, JsonNode value)
    {
        lock (stateLock)
        {
            if (!operations.TryGetValue(operationId, out ActiveOperation? active))
            {
                recall.IncrementCandidateIncomplete();
                throw Incomplete();
            }
            EventRecord record;
            try
            {
                record = CreateRecord(kind, active.Records.Count, value);
            }
            catch
            {
                Delete(operationId);
                recall.IncrementCandidateIncomplete();
                throw;
            }
            int size = RecordSize(record);
            if (!WithinOperation(active, size) ||
                !SdkProcessResources.GrowOperation(operationId, size))
            {
                Delete(operationId);
                recall.IncrementCandidateIncomplete();
                throw Limit();
            }
            active.Records.Add(record);
            active.Bytes += size;
        }
    }

    private void Delete(string operationId)
    {
        if (operations.Remove(operationId, out ActiveOperation? active))
        {
            SdkProcessResources.ReleaseOperation(operationId, active.Bytes);
        }
    }

    private static bool WithinOperation(ActiveOperation active, int size) =>
        active.Records.Count < MaxEvents && active.Bytes + size <= MaxOperationBytes;

    private static EventRecord CreateRecord(string kind, int sequence, JsonNode value)
    {
        byte[] encoded = CanonicalJson.Bytes(value);
        if (encoded.Length > MaxEventBytes)
        {
            throw Limit();
        }
        return new EventRecord(kind, Convert.ToBase64String(encoded)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_'), sequence);
    }

    private static int RecordSize(EventRecord record) => record.Payload.Length + 32;

    private static CaptureException Limit() => new("The SDK capture limit was reached.");
    private static CaptureException Incomplete() =>
        new("The operation does not have complete capture state.");

    private sealed class ActiveOperation(int bytes, List<EventRecord> records, CandidateStart start)
    {
        public int Bytes { get; set; } = bytes;
        public List<EventRecord> Records { get; } = records;
        public CandidateStart Start { get; } = start;
    }

    private sealed record EventRecord(string Kind, string Payload, int Sequence)
    {
        public JsonNode ToJson() => new JsonObject
        {
            ["kind"] = Kind,
            ["payload"] = Payload,
            ["sequence"] = Sequence,
        };
    }
}

/// <summary>Delivers candidates in the background over an authenticated Unix stream.</summary>
internal sealed class UnixRuntimeSink : ICandidateSink, IWorldTokenTransport
{
    private readonly RuntimeSink sink;

    /// <summary>Creates a bounded Unix Runtime sink.</summary>
    public UnixRuntimeSink(string socketPath, Func<string?> authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        if (!Path.IsPathFullyQualified(socketPath))
        {
            throw new ArgumentException(
                "The Runtime socket path must be absolute.", nameof(socketPath));
        }
        sink = new RuntimeSink(
            "reproit-runtime",
            authorization,
            RuntimeTransportFactory.Unix(socketPath));
    }

    /// <inheritdoc />
    public int QueuedBytes => sink.QueuedBytes;
    /// <inheritdoc />
    public bool AllowsProcessingMode(string mode) => mode == "private";

    /// <inheritdoc />
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate) =>
        sink.TrySend(captureId, candidate);

    /// <inheritdoc />
    public Task<string?> FetchWorldIdAsync(
        string serviceId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        sink.FetchWorldIdAsync(serviceId, timeout, cancellationToken);
}

/// <summary>Delivers candidates to a shared Runtime through authenticated TLS.</summary>
internal sealed class TlsRuntimeSink : ICandidateSink, IWorldTokenTransport
{
    private readonly RuntimeSink sink;

    /// <summary>Creates a bounded TLS Runtime sink.</summary>
    public TlsRuntimeSink(
        string host,
        int port,
        string serverName,
        string caCertificatePath,
        Func<string?> authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        sink = new RuntimeSink(
            serverName,
            authorization,
            RuntimeTransportFactory.Tls(host, port, serverName, caCertificatePath));
    }

    /// <inheritdoc />
    public int QueuedBytes => sink.QueuedBytes;
    /// <inheritdoc />
    public bool AllowsProcessingMode(string mode) => mode == "private";

    /// <inheritdoc />
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate) =>
        sink.TrySend(captureId, candidate);

    /// <inheritdoc />
    public Task<string?> FetchWorldIdAsync(
        string serviceId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        sink.FetchWorldIdAsync(serviceId, timeout, cancellationToken);
}

internal sealed class RuntimeSink : ICandidateSink
{
    private const int MaxQueuedCandidates = 16;
    private const int MaxWorldTokenBytes = 65_536;
    private readonly Func<string?> authorization;
    private readonly Queue<QueuedCandidate> queue = new();
    private readonly object stateLock = new();
    private readonly Func<CancellationToken, Task<Stream>> connect;
    private readonly string contentType;
    private readonly string host;
    private readonly string path;
    private bool processing;
    private int queuedBytes;
    private int queuedCandidates;

    internal RuntimeSink(
        string host,
        Func<string?> authorization,
        Func<CancellationToken, Task<Stream>> connect,
        string path = "/v1/candidates/{capture_id}",
        string contentType = "application/reproit-candidate+json")
    {
        this.connect = connect;
        this.contentType = contentType;
        this.host = host;
        this.path = path;
        this.authorization = authorization;
    }

    /// <inheritdoc />
    public int QueuedBytes
    {
        get
        {
            lock (stateLock)
            {
                return queuedBytes;
            }
        }
    }

    /// <inheritdoc />
    public bool AllowsProcessingMode(string mode) => mode == "private";

    /// <inheritdoc />
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate)
    {
        if (candidate.IsEmpty || candidate.Length > Sdk.MaxGlobalBytes ||
            !CandidateProtocol.ValidPrefixedUuid7(captureId, "cap_") ||
            !CandidateProtocol.UsesMode(candidate.Span, captureId, "private"))
        {
            return false;
        }
        lock (stateLock)
        {
            if (queuedCandidates >= MaxQueuedCandidates ||
                queuedBytes + candidate.Length > Sdk.MaxGlobalBytes)
            {
                return false;
            }
            queue.Enqueue(new QueuedCandidate(
                captureId, candidate.ToArray(), Stopwatch.GetTimestamp()));
            queuedBytes += candidate.Length;
            queuedCandidates += 1;
            if (!processing)
            {
                processing = true;
                // The delivery lifetime starts at enqueue, and a saturated
                // host thread pool can delay a queued work item past the
                // whole budget, so the worker starts on a dedicated thread.
                StartWorker();
            }
            return true;
        }
    }

    internal async Task<string?> FetchWorldIdAsync(
        string serviceId,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        string? token;
        try
        {
            token = authorization();
        }
        catch (Exception)
        {
            return null;
        }
        if (string.IsNullOrEmpty(token) || token.Length > 4_096 ||
            token.Contains('\r') || token.Contains('\n'))
        {
            return null;
        }
        using CancellationTokenSource deadline =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await using Stream connection = await connect(deadline.Token).ConfigureAwait(false);
            string request =
                $"GET /v1/services/{serviceId}/world HTTP/1.1\r\n" +
                $"Host: {host}\r\nReproit-Protocol: 1\r\n" +
                $"Authorization: {token}\r\nConnection: close\r\n\r\n";
            await connection.WriteAsync(
                Encoding.ASCII.GetBytes(request), deadline.Token).ConfigureAwait(false);
            return await ReadWorldIdAsync(connection, deadline.Token).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or SocketException or
            AuthenticationException or OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<string?> ReadWorldIdAsync(
        Stream connection,
        CancellationToken cancellationToken)
    {
        byte[] response = new byte[4_096 + MaxWorldTokenBytes];
        int length = 0;
        int boundary = -1;
        while (length < response.Length && boundary < 0)
        {
            int read = await connection.ReadAsync(
                response.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }
            length += read;
            boundary = response.AsSpan(0, length).IndexOf("\r\n\r\n"u8);
            if (boundary > 4_092)
            {
                return null;
            }
        }
        string header = Encoding.ASCII.GetString(response, 0, boundary);
        string[] lines = header.Split("\r\n", StringSplitOptions.None);
        if (lines[0].Split(' ').ElementAtOrDefault(1) != "200")
        {
            return null;
        }
        string[] lengths = lines.Skip(1)
            .Where(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (lengths.Length != 1 ||
            !int.TryParse(lengths[0].Split(':', 2)[1].Trim(), out int bodyLength) ||
            bodyLength is <= 0 or > MaxWorldTokenBytes)
        {
            return null;
        }
        int bodyStart = boundary + 4;
        while (length - bodyStart < bodyLength)
        {
            int read = await connection.ReadAsync(
                response.AsMemory(length, bodyStart + bodyLength - length),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }
            length += read;
        }
        return ParseWorldId(response.AsMemory(bodyStart, bodyLength));
    }

    private static string? ParseWorldId(ReadOnlyMemory<byte> body)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            string[] names = root.EnumerateObject().Select(value => value.Name).Order().ToArray();
            if (!names.SequenceEqual(new[] { "expires_in_ms", "format", "world_id" }) ||
                root.GetProperty("expires_in_ms").GetUInt64() != 5_000 ||
                root.GetProperty("format").GetString() != "reproit.world-token.v1")
            {
                return null;
            }
            string? worldId = root.GetProperty("world_id").GetString();
            return worldId is not null && IsDigest(worldId) ? worldId : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool IsDigest(string value) =>
        value.Length == 71 && value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value.AsSpan(7).IndexOfAnyExcept("0123456789abcdef") < 0;

    private void StartWorker() =>
        new Thread(() => WorkAsync().GetAwaiter().GetResult())
        {
            IsBackground = true,
            Name = "reproit-candidate-delivery",
        }.Start();

    private async Task WorkAsync()
    {
        while (true)
        {
            QueuedCandidate candidate;
            lock (stateLock)
            {
                if (!queue.TryDequeue(out candidate!))
                {
                    processing = false;
                    return;
                }
            }
            try
            {
                await DeliverCandidateAsync(candidate).ConfigureAwait(false);
            }
            finally
            {
                lock (stateLock)
                {
                    queuedBytes -= candidate.Bytes.Length;
                    queuedCandidates -= 1;
                }
            }
        }
    }

    private async Task DeliverCandidateAsync(QueuedCandidate candidate)
    {
        foreach (int offsetMilliseconds in new[] { 0, 100, 300 })
        {
            TimeSpan elapsed = Stopwatch.GetElapsedTime(candidate.Enqueued);
            TimeSpan wait = TimeSpan.FromMilliseconds(offsetMilliseconds) - elapsed;
            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait).ConfigureAwait(false);
            }
            TimeSpan remaining =
                TimeSpan.FromSeconds(1) - Stopwatch.GetElapsedTime(candidate.Enqueued);
            if (remaining <= TimeSpan.Zero)
            {
                return;
            }
            string outcome;
            try
            {
                outcome = await DeliverAsync(
                    candidate.CaptureId,
                    candidate.Bytes,
                    remaining).ConfigureAwait(false);
            }
            catch (Exception)
            {
                outcome = "retry";
            }
            if (outcome != "retry") return;
        }
    }

    internal async Task<string> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> bytes,
        TimeSpan timeout)
    {
        string? token;
        try
        {
            token = authorization();
        }
        catch (Exception)
        {
            return "reject";
        }
        if (string.IsNullOrEmpty(token) || token.Length > 4_096 ||
            token.Contains('\r') || token.Contains('\n'))
        {
            return "reject";
        }
        using CancellationTokenSource deadline = new(timeout);
        try
        {
            await using Stream connection = await connect(deadline.Token).ConfigureAwait(false);
            string header =
                $"PUT {path.Replace(
                    "{capture_id}", captureId, StringComparison.Ordinal)} HTTP/1.1\r\n" +
                $"Host: {host}\r\n" +
                $"Content-Type: {contentType}\r\n" +
                $"Idempotency-Key: {captureId}\r\n" +
                "Reproit-Protocol: 1\r\n" +
                $"Authorization: {token}\r\n" +
                $"Content-Length: {bytes.Length}\r\nConnection: close\r\n\r\n";
            byte[] request = [.. Encoding.ASCII.GetBytes(header), .. bytes.Span];
            await connection.WriteAsync(request, deadline.Token).ConfigureAwait(false);
            byte[] response = new byte[5_120];
            int length = 0;
            while (length < response.Length && response.AsSpan(0, length).IndexOf("\r\n\r\n"u8) < 0)
            {
                int read = await connection.ReadAsync(
                    response.AsMemory(length), deadline.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                length += read;
            }
            if (response.AsSpan(0, length).IndexOf("\r\n\r\n"u8) < 0)
            {
                return "reject";
            }
            int boundary = response.AsSpan(0, length).IndexOf("\r\n\r\n"u8);
            string responseHeader = Encoding.ASCII.GetString(response, 0, boundary);
            string[] lines = responseHeader.Split("\r\n", StringSplitOptions.None);
            string[] status = lines[0].Split(' ');
            if (status.Length <= 1)
            {
                return "reject";
            }
            if (status[1] is "429" or "503")
            {
                return "retry";
            }
            if (status[1] is not ("200" or "202"))
            {
                return "reject";
            }
            if (path == "/v1/candidates/{capture_id}")
            {
                return "accept";
            }
            string? contentLengthHeader = lines.Skip(1).FirstOrDefault(line =>
                line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
            if (contentLengthHeader is null ||
                !int.TryParse(
                    contentLengthHeader[(contentLengthHeader.IndexOf(':') + 1)..].Trim(),
                    out int contentLength) ||
                contentLength <= 0 || contentLength > 1_024)
            {
                return "reject";
            }
            int bodyOffset = boundary + 4;
            while (length - bodyOffset < contentLength)
            {
                int read = await connection.ReadAsync(
                    response.AsMemory(length, response.Length - length),
                    deadline.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    return "reject";
                }
                length += read;
            }
            if (length - bodyOffset != contentLength)
            {
                return "reject";
            }
            JsonObject envelope = JsonNode.Parse(bytes.Span)?.AsObject() ?? new JsonObject();
            JsonObject receipt = JsonNode.Parse(
                response.AsSpan(bodyOffset, contentLength))?.AsObject() ?? new JsonObject();
            if (receipt.Count != 3 ||
                receipt["capture_id"]?.GetValue<string>() != captureId ||
                receipt["request_digest"]?.GetValue<string>() !=
                    envelope["identity"]?["request_digest"]?.GetValue<string>())
            {
                return "reject";
            }
            string? state = receipt["state"]?.GetValue<string>();
            if (state == "CLOUD_PROTECTED")
            {
                return "cloud_protected";
            }
            if (path == "/v1/staged-candidates/{capture_id}" && state == "LOCAL_ONLY")
            {
                return "local_only";
            }
            return "reject";
        }
        catch (AuthenticationException)
        {
            return "reject";
        }
        catch (JsonException)
        {
            return "reject";
        }
        catch (InvalidOperationException)
        {
            return "reject";
        }
        catch (IOException)
        {
            return "retry";
        }
        catch (SocketException)
        {
            return "retry";
        }
        catch (OperationCanceledException)
        {
            return "retry";
        }
    }

    private sealed record QueuedCandidate(string CaptureId, byte[] Bytes, long Enqueued);
}
