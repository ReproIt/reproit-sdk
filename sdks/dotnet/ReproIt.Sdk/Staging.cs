using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Reports one bounded staged-candidate delivery result.</summary>
internal enum StagedDeliveryOutcome
{
    /// <summary>A durable staging service owns the candidate.</summary>
    CloudProtected,
    /// <summary>Only the bounded local Runtime journal owns the candidate.</summary>
    LocalOnly,
    /// <summary>The receiver rejected the candidate.</summary>
    Rejected,
    /// <summary>The receiver did not provide a terminal result.</summary>
    Retryable,
}

/// <summary>Delivers one encrypted candidate through a scoped transport.</summary>
internal interface IStagedCandidateTransport
{
    /// <summary>Delivers exact envelope bytes within one timeout.</summary>
    Task<StagedDeliveryOutcome> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout);
}

/// <summary>Delivers encrypted candidates to a host-local Runtime.</summary>
internal sealed class UnixStagedRuntimeTransport : IStagedCandidateTransport
{
    private readonly RuntimeSink sink;

    /// <summary>Creates one scoped Unix Runtime transport.</summary>
    public UnixStagedRuntimeTransport(string socketPath, Func<string?> authorization)
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
            RuntimeTransportFactory.Unix(socketPath),
            "/v1/staged-candidates/{capture_id}",
            "application/reproit-candidate-staging+json");
    }

    /// <inheritdoc />
    public async Task<StagedDeliveryOutcome> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout) =>
        ParseOutcome(await sink.DeliverAsync(captureId, envelope, timeout).ConfigureAwait(false));

    private static StagedDeliveryOutcome ParseOutcome(string value) => value switch
    {
        "cloud_protected" => StagedDeliveryOutcome.CloudProtected,
        "local_only" => StagedDeliveryOutcome.LocalOnly,
        "reject" => StagedDeliveryOutcome.Rejected,
        _ => StagedDeliveryOutcome.Retryable,
    };
}

/// <summary>Delivers encrypted candidates to a shared Runtime through TLS 1.3.</summary>
internal sealed class TlsStagedRuntimeTransport : IStagedCandidateTransport
{
    private readonly RuntimeSink sink;

    /// <summary>Creates one scoped TLS Runtime transport.</summary>
    public TlsStagedRuntimeTransport(
        string host,
        int port,
        string serverName,
        string caCertificatePath,
        Func<string?> authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        sink = CreateTlsSink(host, port, serverName, caCertificatePath, authorization);
    }

    /// <inheritdoc />
    public Task<StagedDeliveryOutcome> DeliverAsync(
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout) => Deliver(sink, captureId, envelope, timeout);

    private static RuntimeSink CreateTlsSink(
        string host,
        int port,
        string serverName,
        string caCertificatePath,
        Func<string?> authorization) => new(
            serverName,
            authorization,
            RuntimeTransportFactory.Tls(host, port, serverName, caCertificatePath),
            "/v1/staged-candidates/{capture_id}",
            "application/reproit-candidate-staging+json");

    private static async Task<StagedDeliveryOutcome> Deliver(
        RuntimeSink sink,
        string captureId,
        ReadOnlyMemory<byte> envelope,
        TimeSpan timeout) =>
        await sink.DeliverAsync(captureId, envelope, timeout).ConfigureAwait(false) switch
        {
            "cloud_protected" => StagedDeliveryOutcome.CloudProtected,
            "local_only" => StagedDeliveryOutcome.LocalOnly,
            "reject" => StagedDeliveryOutcome.Rejected,
            _ => StagedDeliveryOutcome.Retryable,
        };
}

/// <summary>Encrypts complete candidates once and starts two durable deliveries.</summary>
internal sealed class StagedCandidateSink : ICandidateSink, IRecallCounterSource
{
    private const int MaxQueuedCandidates = 16;
    private readonly IStagedCandidateTransport deferred;
    private readonly byte[] key;
    private readonly Queue<QueuedEnvelope> queue = new();
    private readonly IStagedCandidateTransport runtime;
    private readonly object stateLock = new();
    private ulong candidateDeliveryExpired;
    private ulong candidateDurablyAccepted;
    private ulong candidateIncomplete;
    private ulong candidateQueueFull;
    private ulong candidateRejected;
    private bool processing;
    private int queuedBytes;
    private int queuedCandidates;

    /// <summary>Creates one bounded SDK-owned staged delivery queue.</summary>
    public StagedCandidateSink(
        IStagedCandidateTransport runtime,
        IStagedCandidateTransport deferred,
        ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(deferred);
        if (key.Length != 32)
        {
            throw new ArgumentException(
                "The candidate staging key must contain 32 bytes.", nameof(key));
        }
        this.runtime = runtime;
        this.deferred = deferred;
        this.key = key.ToArray();
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

    SdkRecallCounters IRecallCounterSource.RecallCounters
    {
        get
        {
            lock (stateLock)
            {
                return new SdkRecallCounters(
                    candidateDeliveryExpired, candidateDurablyAccepted,
                    candidateIncomplete, candidateQueueFull, candidateRejected,
                    0, 0, 0);
            }
        }
    }

    /// <inheritdoc />
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate)
    {
        byte[] envelope;
        string parsedCaptureId;
        try
        {
            (envelope, parsedCaptureId) = Seal(candidate.Span, key);
        }
        catch (Exception error) when (error is JsonException or CryptographicException or
            FormatException or InvalidOperationException or CaptureException)
        {
            lock (stateLock)
            {
                Increment(ref candidateIncomplete);
            }
            return false;
        }
        if (!string.Equals(captureId, parsedCaptureId, StringComparison.Ordinal))
        {
            lock (stateLock)
            {
                Increment(ref candidateIncomplete);
            }
            return false;
        }
        lock (stateLock)
        {
            if (queuedCandidates >= MaxQueuedCandidates ||
                queuedBytes + envelope.Length > Sdk.MaxGlobalBytes)
            {
                Increment(ref candidateQueueFull);
                return false;
            }
            queue.Enqueue(new QueuedEnvelope(captureId, envelope, Stopwatch.GetTimestamp()));
            queuedBytes += envelope.Length;
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

    private void StartWorker() =>
        new Thread(() => WorkAsync().GetAwaiter().GetResult())
        {
            IsBackground = true,
            Name = "reproit-staged-delivery",
        }.Start();

    private async Task WorkAsync()
    {
        while (true)
        {
            QueuedEnvelope candidate;
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
                StagedDeliveryOutcome outcome =
                    await DeliverCandidateAsync(candidate).ConfigureAwait(false);
                lock (stateLock)
                {
                    if (outcome is StagedDeliveryOutcome.CloudProtected or
                        StagedDeliveryOutcome.LocalOnly)
                    {
                        Increment(ref candidateDurablyAccepted);
                    }
                    else if (outcome == StagedDeliveryOutcome.Rejected)
                    {
                        Increment(ref candidateRejected);
                    }
                    else
                    {
                        Increment(ref candidateDeliveryExpired);
                    }
                }
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

    private async Task<StagedDeliveryOutcome> DeliverCandidateAsync(QueuedEnvelope candidate)
    {
        bool localOnly = false;
        foreach (int offsetMilliseconds in new[] { 0, 100, 300 })
        {
            TimeSpan wait = TimeSpan.FromMilliseconds(offsetMilliseconds) -
                Stopwatch.GetElapsedTime(candidate.Enqueued);
            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait).ConfigureAwait(false);
            }
            TimeSpan remaining = TimeSpan.FromSeconds(1) -
                Stopwatch.GetElapsedTime(candidate.Enqueued);
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }
            StagedDeliveryOutcome[] outcomes = await Task.WhenAll(
                SafeDeliverAsync(runtime, candidate, remaining),
                SafeDeliverAsync(deferred, candidate, remaining)).ConfigureAwait(false);
            if (outcomes.Contains(StagedDeliveryOutcome.CloudProtected))
            {
                return StagedDeliveryOutcome.CloudProtected;
            }
            localOnly |= outcomes.Contains(StagedDeliveryOutcome.LocalOnly);
            if (outcomes.All(value => value == StagedDeliveryOutcome.Rejected) ||
                outcomes.Contains(StagedDeliveryOutcome.LocalOnly) &&
                outcomes.All(value => value is StagedDeliveryOutcome.LocalOnly or
                    StagedDeliveryOutcome.Rejected))
            {
                return localOnly
                    ? StagedDeliveryOutcome.LocalOnly
                    : StagedDeliveryOutcome.Rejected;
            }
        }
        return localOnly ? StagedDeliveryOutcome.LocalOnly : StagedDeliveryOutcome.Retryable;
    }

    private static async Task<StagedDeliveryOutcome> SafeDeliverAsync(
        IStagedCandidateTransport transport,
        QueuedEnvelope candidate,
        TimeSpan timeout)
    {
        try
        {
            return await transport.DeliverAsync(
                candidate.CaptureId, candidate.Bytes, timeout).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return StagedDeliveryOutcome.Retryable;
        }
    }

    private static void Increment(ref ulong counter)
    {
        if (counter < long.MaxValue)
        {
            counter += 1;
        }
    }

    private static (byte[] Envelope, string CaptureId) Seal(
        ReadOnlySpan<byte> candidateBytes,
        ReadOnlySpan<byte> key)
    {
        if (candidateBytes.Length > Sdk.MaxGlobalBytes)
        {
            throw new CaptureException("The complete candidate exceeds the staging limit.");
        }
        JsonNode candidate = JsonNode.Parse(candidateBytes) ?? throw Incomplete();
        if (!CanonicalJson.Bytes(candidate).AsSpan().SequenceEqual(candidateBytes) ||
            !IsComplete(candidate))
        {
            throw Incomplete();
        }
        JsonObject identity = StagingIdentity(candidate);
        byte[] aad = CanonicalJson.Bytes(identity);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[candidateBytes.Length];
        byte[] tag = new byte[16];
        using (AesGcm cipher = new(key, tag.Length))
        {
            cipher.Encrypt(nonce, candidateBytes, ciphertext, tag, aad);
        }
        byte[] stored = [.. nonce, .. ciphertext, .. tag];
        JsonObject envelope = new()
        {
            ["cipher_digest"] = Digest(stored),
            ["cipher_size"] = stored.Length,
            ["ciphertext"] = Base64Url(stored),
            ["format"] = "reproit.candidate-staging-envelope.v1",
            ["identity"] = identity,
        };
        return (
            CanonicalJson.Bytes(envelope),
            candidate["capture_id"]?.GetValue<string>() ?? throw Incomplete());
    }

    private static bool IsComplete(JsonNode candidate)
    {
        try
        {
            CandidateProtocol.Validate(candidate);
            return true;
        }
        catch (CaptureException)
        {
            return false;
        }
    }

    private static JsonObject StagingIdentity(JsonNode candidate)
    {
        JsonNode deployment = candidate["deployment"] ?? throw Incomplete();
        JsonNode subject = deployment["subject"] ?? throw Incomplete();
        JsonNode failure = candidate["failure"] ?? throw Incomplete();
        JsonNode failurePayload = FailurePayload(candidate);
        JsonNode failureIdentity = failurePayload["identity"] ?? throw Incomplete();
        if (!CanonicalJson.Bytes(failurePayload["failure"] ?? throw Incomplete())
            .AsSpan().SequenceEqual(CanonicalJson.Bytes(failure)))
        {
            throw Incomplete();
        }
        JsonObject storm = RequiredStrings(new JsonObject
        {
            ["failure_identity_digest"] = failure["identity"]?.DeepClone(),
            ["format"] = "reproit.failure-storm-identity.v1",
            ["operation_kind"] = failureIdentity["operation_kind"]?.DeepClone(),
            ["operation_name"] = failureIdentity["operation_name"]?.DeepClone(),
            ["service_id"] = deployment["service_id"]?.DeepClone(),
            ["source_revision"] = deployment["source_revision"]?.DeepClone(),
            ["subject_artifact_digest"] = subject["artifact_digest"]?.DeepClone(),
        });
        JsonObject identity = RequiredStrings(new JsonObject
        {
            ["capture_id"] = candidate["capture_id"]?.DeepClone(),
            ["deployment_digest"] = Digest(CanonicalJson.Bytes(deployment)),
            ["expires_at"] = DateTimeOffset.UtcNow.AddHours(1)
                .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
            ["failure_storm_digest"] = Digest(CanonicalJson.Bytes(storm)),
            ["format"] = "reproit.candidate-staging-identity.v1",
            ["organization_id"] = deployment["organization_id"]?.DeepClone(),
            ["processing_mode"] = deployment["processing_mode"]?.DeepClone(),
            ["project_id"] = deployment["project_id"]?.DeepClone(),
            ["provider_lease_digest"] = Digest(CanonicalJson.Bytes(RequiredStrings(new JsonObject
            {
                ["format"] = "reproit.provider-lease-binding.v1",
                ["organization_id"] = deployment["organization_id"]?.DeepClone(),
                ["service_id"] = deployment["service_id"]?.DeepClone(),
                ["world_id"] = candidate["world_id"]?.DeepClone(),
            }))),
            ["request_digest"] = Digest(CanonicalJson.Bytes(candidate)),
            ["service_id"] = deployment["service_id"]?.DeepClone(),
            ["world_id"] = candidate["world_id"]?.DeepClone(),
        });
        if (identity["processing_mode"]?.GetValue<string>() != "private")
        {
            throw Incomplete();
        }
        return identity;
    }

    private static JsonNode FailurePayload(JsonNode candidate)
    {
        JsonNode record = candidate["records"]!.AsArray()
            .Single(value => value?["kind"]?.GetValue<string>() == "failure")!;
        string value = record["payload"]?.GetValue<string>() ?? throw Incomplete();
        return JsonNode.Parse(FromBase64Url(value)) ?? throw Incomplete();
    }

    private static JsonObject RequiredStrings(JsonObject value)
    {
        if (value.Any(part => part.Value is null ||
            string.IsNullOrEmpty(part.Value.GetValue<string>())))
        {
            throw Incomplete();
        }
        return value;
    }

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Digest(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    private static CaptureException Incomplete() =>
        new("The operation does not have complete capture state.");

    private sealed record QueuedEnvelope(string CaptureId, byte[] Bytes, long Enqueued);
}
