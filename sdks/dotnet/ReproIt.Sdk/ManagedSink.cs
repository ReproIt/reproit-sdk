using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Configures one managed candidate sink.</summary>
public sealed record ManagedSinkConfiguration(
    string CaptureSignerId,
    byte[] CaptureSignerPublicKey,
    string ServiceId,
    string WorkloadStateRoot,
    Func<ManagedProjectToken>? ProjectTokenProvider);

/// <summary>Delivers complete managed candidates through the upload session.</summary>
/// <remarks>
/// Mirrors crates/reproit-sdk-rust/src/managed_sink.rs: a bounded
/// in-process queue, one background delivery worker, recall counters
/// without customer values, and fail-open semantics. A managed SDK failure
/// never changes the application's behavior.
/// </remarks>
public sealed class ManagedCandidateSink : ICandidateSink, IRecallCounterSource
{
    /// <summary>The registration and worker startup timeout.</summary>
    public static readonly TimeSpan RegistrationTimeout = TimeSpan.FromSeconds(5);

    private const int MaxQueuedCandidates = 16;

    private readonly IManagedGrantDelivery grantDelivery;
    private readonly IManagedIngressDelivery ingressDelivery;
    private readonly IManagedRegistrationDelivery registrationDelivery;
    private readonly FrozenManagedCaptureClosure closure;
    private readonly ManagedSinkConfiguration configuration;
    private readonly string? operationId;
    private readonly DotnetSubjectPackage subject;
    private readonly BlockingCollection<QueuedCandidate> queue =
        new(MaxQueuedCandidates);
    private readonly object stateLock = new();
    private readonly object registrationLock = new();
    private ManagedWorkloadIdentityState? workloadIdentity;
    private ManagedWorkloadRegistrationReceipt? registrationReceipt;
    private JsonObject? registrationRequest;
    private byte[]? workloadSigningKey;
    private byte[]? workloadPublicKey;
    private string? workloadKeyId;
    private string? deploymentDigest;
    private bool active;
    private ulong candidateDeliveryExpired;
    private ulong candidateDurablyAccepted;
    private ulong candidateIncomplete;
    private ulong candidateQueueFull;
    private ulong candidateRejected;
    private int queuedBytes;
    private int queuedCandidates;

    // Tests shorten this value to prove the expiry path without waiting.
    internal TimeSpan CandidateDeliveryLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Prepares the workload key and starts the delivery worker.</summary>
    /// <param name="client">
    /// One client implementing registration, grant, and ingress delivery,
    /// normally a <see cref="ManagedTlsClient"/>.
    /// </param>
    /// <param name="captureClosure">The static capture closure to prove.</param>
    /// <param name="configuration">The signer and workload key configuration.</param>
    /// <param name="subject">
    /// An already packaged subject, or null to package the running subject.
    /// </param>
    /// <param name="operationId">An optional single-operation restriction.</param>
    public ManagedCandidateSink(
        object client,
        ManagedCaptureClosure captureClosure,
        ManagedSinkConfiguration configuration,
        DotnetSubjectPackage? subject = null,
        string? operationId = null)
        : this(
            client, new FrozenManagedCaptureClosure(captureClosure), configuration,
            subject, operationId)
    {
    }

    /// <summary>Registers the workload key over a frozen capture closure.</summary>
    public ManagedCandidateSink(
        object client,
        FrozenManagedCaptureClosure captureClosure,
        ManagedSinkConfiguration configuration,
        DotnetSubjectPackage? subject = null,
        string? operationId = null)
    {
        ValidateConfiguration(configuration);
        if (client is not IManagedGrantDelivery grants ||
            client is not IManagedIngressDelivery ingress ||
            client is not IManagedRegistrationDelivery registrationDelivery)
        {
            throw ManagedProtocol.SchemaInvalid(
                "The managed client must provide registration, grant, and ingress delivery.");
        }
        if (operationId is not null)
        {
            ManagedProtocol.RequireTypedIdText(operationId, "operation_id");
        }
        grantDelivery = grants;
        ingressDelivery = ingress;
        this.registrationDelivery = registrationDelivery;
        closure = captureClosure;
        this.configuration = configuration;
        this.operationId = operationId;
        this.subject = subject ?? ManagedSubject.PackageRunningDotnetSubject();
        WorldId = captureClosure.WorldId();
        // The event is not disposed: the worker signals it once and a
        // dispose racing a late Set would fault the background thread.
        ManualResetEventSlim ready = new(false);
        Thread worker = new(() => Worker(ready))
        {
            IsBackground = true,
            Name = "reproit-managed-dotnet-capture",
        };
        worker.Start();
        if (!ready.Wait(RegistrationTimeout))
        {
            throw new ManagedCaptureException(
                "SERVICE_UNAVAILABLE", "The managed capture worker could not start.");
        }
    }

    /// <summary>Gets the processing modes this sink accepts.</summary>
    public IReadOnlySet<string> ProcessingModes { get; } =
        new HashSet<string> { "managed" };

    /// <inheritdoc />
    public bool AllowsProcessingMode(string mode) => mode == "managed";

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

    /// <summary>Gets the frozen subject manifest.</summary>
    public JsonObject SubjectManifest => subject.Manifest;

    /// <summary>Gets the registered workload key identifier.</summary>
    public string WorkloadKeyId => workloadKeyId ?? throw new ManagedCaptureException(
        "CONFIG_CONFLICT", "The managed Deployment is not bound.");

    /// <summary>Gets the workload verification key.</summary>
    public byte[] WorkloadPublicKey => workloadPublicKey?.ToArray() ??
        throw new ManagedCaptureException(
            "CONFIG_CONFLICT", "The managed Deployment is not bound.");

    /// <summary>Gets the frozen world identity digest.</summary>
    public string WorldId { get; }

    /// <summary>Gets bounded counters that contain no customer values.</summary>
    public SdkRecallCounters RecallCounters
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

    /// <summary>Binds, signs, and registers one exact managed deployment.</summary>
    public void BindDeployment(JsonObject deployment)
    {
        lock (registrationLock)
        {
            BindDeploymentLocked(deployment);
        }
    }

    private void BindDeploymentLocked(JsonObject deployment)
    {
        if (ManagedProtocol.Text(deployment["service_id"]) != configuration.ServiceId)
        {
            throw new ManagedCaptureException(
                "AUTHORIZATION_DENIED",
                "The managed Deployment belongs to a different service.");
        }
        JsonObject manifest = subject.Manifest;
        deployment["processing_mode"] = "managed";
        deployment["subject"] = ManagedSubject.SubjectBinding(manifest);
        HashSet<string> capabilities = [];
        if (deployment["runtime_capabilities"] is JsonArray existing)
        {
            foreach (JsonNode? entry in existing)
            {
                if (ManagedProtocol.Text(entry) is string capability)
                {
                    capabilities.Add(capability);
                }
            }
        }
        capabilities.Add(ManagedProtocol.Text(manifest["architecture"])!);
        capabilities.Add(ManagedProtocol.Text(manifest["operating_system"])!);
        // The captured World's process-visible processor view travels with
        // the candidate so admission starts from the complete observation
        // (spec 7.8.1).
        capabilities.UnionWith(ProcessorCapture.CaptureProcessorCapabilities());
        JsonArray sorted = [];
        foreach (string capability in capabilities
            .OrderBy(value => value, StringComparer.Ordinal))
        {
            sorted.Add(capability);
        }
        deployment["runtime_capabilities"] = sorted;
        deployment["signer_key_id"] = "";
        deployment["signature"] = "";
        string bindingDigest = ManagedDeploymentBindingDigest(deployment);
        ManagedWorkloadIdentityState identity =
            ManagedWorkloadIdentityState.FromStateRoot(
                configuration.WorkloadStateRoot, bindingDigest);
        byte[] signingKey = identity.LoadOrCreateKey();
        string proposedSignedAt = ManagedProtocol.Text(deployment["signed_at"]) ?? "";
        deployment["signed_at"] = identity.LoadOrCreateDeploymentSignedAt(
            bindingDigest, proposedSignedAt);
        byte[] publicKey = ManagedProtocol.VerificationKey(signingKey);
        string keyId = ManagedProtocol.WorkloadKeyId(publicKey);
        deployment["signer_key_id"] = keyId;
        deployment["signature"] = ManagedProtocol.SignBytes(
            CanonicalJson.Bytes(deployment), signingKey);
        ValidateDeployment(deployment);
        ManagedProtocol.VerifySignedValue(deployment, publicKey);
        string exactDeploymentDigest = ManagedProtocol.CanonicalDigest(deployment);
        JsonObject request = new()
        {
            ["algorithm"] = "Ed25519",
            ["deployment"] = deployment.DeepClone(),
            ["public_key"] = ManagedProtocol.EncodeBase64Url(publicKey),
            ["service_id"] = configuration.ServiceId,
        };
        ManagedWorkloadRegistrationReceipt receipt = new(
            exactDeploymentDigest, configuration.ServiceId, keyId);
        if (registrationRequest is not null)
        {
            if (!CanonicalJson.Bytes(registrationRequest).AsSpan()
                .SequenceEqual(CanonicalJson.Bytes(request)))
            {
                throw new ManagedCaptureException(
                    "CONFIG_CONFLICT",
                    "The managed sink is already bound to another Deployment.");
            }
            return;
        }
        workloadIdentity = identity;
        workloadSigningKey = signingKey;
        workloadPublicKey = publicKey;
        workloadKeyId = keyId;
        registrationRequest = request;
        registrationReceipt = receipt;
        deploymentDigest = exactDeploymentDigest;
    }

    /// <summary>Waits until the queue and the worker are both idle.</summary>
    public bool WaitUntilIdle(TimeSpan timeout)
    {
        long deadline = Stopwatch.GetTimestamp();
        while (true)
        {
            lock (stateLock)
            {
                if (!active && queuedCandidates == 0)
                {
                    return true;
                }
            }
            if (Stopwatch.GetElapsedTime(deadline) >= timeout)
            {
                return false;
            }
            Thread.Sleep(1);
        }
    }

    /// <inheritdoc />
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate)
    {
        JsonObject value;
        try
        {
            value = AuthorizedCandidate(captureId, candidate.Span);
        }
        catch (Exception)
        {
            Increment(ref candidateIncomplete);
            return false;
        }
        lock (stateLock)
        {
            if (queuedCandidates >= MaxQueuedCandidates ||
                !SdkProcessResources.ReserveCandidate(candidate.Length))
            {
                IncrementLocked(ref candidateQueueFull);
                return false;
            }
            queuedBytes += candidate.Length;
            queuedCandidates += 1;
        }
        if (queue.TryAdd(new QueuedCandidate(
            value, candidate.Length, Stopwatch.GetTimestamp())))
        {
            return true;
        }
        lock (stateLock)
        {
            queuedBytes -= candidate.Length;
            queuedCandidates -= 1;
            IncrementLocked(ref candidateQueueFull);
        }
        SdkProcessResources.ReleaseCandidate(candidate.Length);
        return false;
    }

    private JsonObject AuthorizedCandidate(string captureId, ReadOnlySpan<byte> candidate)
    {
        if (candidate.Length > Sdk.MaxOperationBytes)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        JsonNode valueNode =
            ManagedProtocol.ParseStrictJson(candidate, Sdk.MaxOperationBytes);
        if (valueNode is not JsonObject value ||
            !CanonicalJson.Bytes(value).AsSpan().SequenceEqual(candidate) ||
            ManagedProtocol.Text(value["capture_id"]) != captureId ||
            ManagedProtocol.Text(value["processing_mode"]) != "managed")
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        if (value["deployment"] is not JsonObject deployment ||
            ManagedProtocol.Text(deployment["processing_mode"]) != "managed" ||
            ManagedProtocol.Text(deployment["service_id"]) != configuration.ServiceId ||
            ManagedProtocol.Text(deployment["signer_key_id"]) != workloadKeyId ||
            ManagedProtocol.CanonicalDigest(deployment) != deploymentDigest ||
            (operationId is not null &&
                ManagedProtocol.Text(value["operation_id"]) != operationId))
        {
            throw new ManagedCaptureException(
                "AUTHORIZATION_DENIED",
                "The managed deployment does not use the registered workload key.");
        }
        ManagedProtocol.VerifySignedValue(
            deployment,
            workloadPublicKey ?? throw ManagedProtocol.SchemaInvalid(
                "The managed Deployment is not bound."));
        return value;
    }

    private void Worker(ManualResetEventSlim ready)
    {
        ready.Set();
        foreach (QueuedCandidate entry in queue.GetConsumingEnumerable())
        {
            try
            {
                if (Stopwatch.GetElapsedTime(entry.Enqueued) >= CandidateDeliveryLifetime)
                {
                    Increment(ref candidateDeliveryExpired);
                    continue;
                }
                lock (stateLock)
                {
                    active = true;
                }
                try
                {
                    Deliver(entry.Value, entry.Enqueued);
                    Increment(ref candidateDurablyAccepted);
                }
                catch (ManagedCaptureException error)
                {
                    RecordFailure(error);
                }
                catch (Exception)
                {
                    Increment(ref candidateRejected);
                }
            }
            finally
            {
                lock (stateLock)
                {
                    active = false;
                    queuedBytes = Math.Max(0, queuedBytes - entry.Size);
                    queuedCandidates = Math.Max(0, queuedCandidates - 1);
                }
                SdkProcessResources.ReleaseCandidate(entry.Size);
            }
        }
    }

    private void Deliver(JsonObject candidate, long enqueued)
    {
        DeadlineManagedClient client = new(
            registrationDelivery, grantDelivery, ingressDelivery,
            enqueued, CandidateDeliveryLifetime);
        PreparedManagedCandidate prepared =
            PreparedManagedCandidate.PrepareComplete(candidate, subject, closure);
        EnsureRegistered(client);
        string registeredDeploymentDigest = deploymentDigest ??
            throw ManagedProtocol.SchemaInvalid(
                "The managed Deployment is not bound.");
        string registeredWorkloadKeyId = workloadKeyId ??
            throw ManagedProtocol.SchemaInvalid("The managed Deployment is not bound.");
        byte[] registeredWorkloadSigningKey = workloadSigningKey ??
            throw ManagedProtocol.SchemaInvalid("The managed Deployment is not bound.");
        EncryptionResponse grant = prepared.RequestEncryptionGrant(
            client,
            registeredDeploymentDigest,
            registeredWorkloadKeyId,
            registeredWorkloadSigningKey);
        using SealedManagedCandidate sealedCandidate = prepared.Seal(
            grant,
            ManagedProtocol.NowTimestamp(),
            configuration.CaptureSignerId,
            configuration.CaptureSignerPublicKey);
        EncryptionResponse renewal =
            sealedCandidate.RequestCaptureGrantRenewal(
                client,
                registeredDeploymentDigest,
                registeredWorkloadKeyId,
                registeredWorkloadSigningKey);
        sealedCandidate.ApplyRenewedCaptureGrant(
            renewal,
            ManagedProtocol.NowTimestamp(),
            configuration.CaptureSignerId,
            configuration.CaptureSignerPublicKey);
        sealedCandidate.Upload(client);
    }

    private void EnsureRegistered(IManagedRegistrationDelivery delivery)
    {
        lock (registrationLock)
        {
            ManagedWorkloadIdentityState identity = workloadIdentity ??
                throw ManagedProtocol.SchemaInvalid("The managed Deployment is not bound.");
            ManagedWorkloadRegistrationReceipt receipt = registrationReceipt ??
                throw ManagedProtocol.SchemaInvalid("The managed Deployment is not bound.");
            JsonObject request = registrationRequest ??
                throw ManagedProtocol.SchemaInvalid("The managed Deployment is not bound.");
            if (identity.HasRegistrationReceipt(receipt))
            {
                return;
            }
            Func<ManagedProjectToken>? provider = configuration.ProjectTokenProvider;
            if (provider is null)
            {
                throw new ManagedCaptureException(
                    "AUTHENTICATION_REQUIRED",
                    "A project token is required to register this managed workload.");
            }
            ManagedProjectToken projectToken;
            try
            {
                projectToken = provider() ?? throw new ManagedCaptureException(
                    "AUTHENTICATION_REQUIRED",
                    "The project token provider did not return a valid project token.");
            }
            catch (ManagedCaptureException)
            {
                throw;
            }
            catch (Exception)
            {
                throw new ManagedCaptureException(
                    "AUTHENTICATION_REQUIRED",
                    "The project token provider could not provide a project token.");
            }
            JsonObject registration = delivery.RegisterWorkloadKey(
                projectToken, request, RegistrationTimeout);
            if (ManagedProtocol.Text(registration["key_id"]) != receipt.WorkloadKeyId ||
                ManagedProtocol.Text(registration["service_id"]) != receipt.ServiceId ||
                ManagedProtocol.Text(registration["deployment_digest"]) !=
                    receipt.DeploymentDigest)
            {
                throw new ManagedCaptureException(
                    "ATTESTATION_SCOPE",
                    "The managed workload registration does not match this Deployment.");
            }
            identity.PersistRegistrationReceipt(receipt);
        }
    }

    private void RecordFailure(ManagedCaptureException error)
    {
        if (error.Code == "INCOMPLETE_CANDIDATE")
        {
            Increment(ref candidateIncomplete);
        }
        else if (error.Retryable)
        {
            Increment(ref candidateDeliveryExpired);
        }
        else
        {
            Increment(ref candidateRejected);
        }
    }

    private void Increment(ref ulong counter)
    {
        lock (stateLock)
        {
            IncrementLocked(ref counter);
        }
    }

    private static void IncrementLocked(ref ulong counter)
    {
        if (counter < long.MaxValue)
        {
            counter += 1;
        }
    }

    private static void ValidateConfiguration(ManagedSinkConfiguration configuration)
    {
        if (configuration.CaptureSignerId.Length is 0 or > 256 ||
            configuration.CaptureSignerPublicKey.Length != 32 ||
            !Path.IsPathFullyQualified(configuration.WorkloadStateRoot) ||
            Path.GetFullPath(configuration.WorkloadStateRoot) !=
                configuration.WorkloadStateRoot)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        ManagedProtocol.RequireTypedIdText(configuration.ServiceId, "service_id");
    }

    /// <summary>Mirrors the reproit-core deployment checks the SDK can prove.</summary>
    internal static void ValidateDeployment(JsonObject deployment)
    {
        string? repositoryId = ManagedProtocol.Text(deployment["repository_id"]);
        string? runtimeEndpoint = ManagedProtocol.Text(deployment["runtime_endpoint"]);
        string? servicePath = ManagedProtocol.Text(deployment["service_path"]);
        string? signerKeyId = ManagedProtocol.Text(deployment["signer_key_id"]);
        string? sourceRevision = ManagedProtocol.Text(deployment["source_revision"]);
        if (!ManagedProtocol.HasExactly(
                deployment, "format", "organization_id", "processing_mode", "project_id",
                "repository_id", "runtime_capabilities", "runtime_endpoint", "service_id",
                "service_path", "signature", "signed_at", "signer_key_id",
                "source_revision", "subject") ||
            ManagedProtocol.Text(deployment["format"]) != "reproit.deployment.v1" ||
            ManagedProtocol.Text(deployment["processing_mode"]) != "managed" ||
            !ManagedProtocol.ValidTypedId(deployment["organization_id"], "organization_id") ||
            !ManagedProtocol.ValidTypedId(deployment["project_id"], "project_id") ||
            !ManagedProtocol.ValidTypedId(deployment["service_id"], "service_id") ||
            repositoryId is null || repositoryId.Length is 0 or > 256 ||
            runtimeEndpoint is null || runtimeEndpoint.Length is 0 or > 2_048 ||
            servicePath is null || servicePath.Length is 0 or > 1_024 ||
            servicePath.StartsWith('/') ||
            servicePath.Split('/').Any(part => part == "..") ||
            signerKeyId is null || signerKeyId.Length is 0 or > 256 ||
            sourceRevision is null || sourceRevision.Length is 0 or > 256 ||
            !ManagedProtocol.ValidTimestamp(deployment["signed_at"]))
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        ManagedProtocol.ValidateCapabilities(deployment["runtime_capabilities"]);
        ValidateSubject(deployment["subject"]);
        ManagedProtocol.DecodeBase64Url(
            ManagedProtocol.Text(deployment["signature"]), 64);
    }

    private static void ValidateSubject(JsonNode? value)
    {
        if (value is not JsonObject subject || !ManagedProtocol.HasExactly(
                subject, "architecture", "arguments", "artifact_digest",
                "artifact_media_type", "artifact_uri", "environment_names", "executable",
                "format", "operating_system", "working_directory") ||
            ManagedProtocol.Text(subject["format"]) != "reproit.subject.v1" ||
            !ValidBoundedText(subject["architecture"], 128) ||
            !ValidBoundedText(subject["operating_system"], 128) ||
            !ManagedProtocol.ValidDigest(subject["artifact_digest"]) ||
            !ValidBoundedText(subject["artifact_media_type"], 128) ||
            !ValidBoundedText(subject["artifact_uri"], 2_048) ||
            !ValidBoundedText(subject["executable"], 4_096) ||
            !ValidBoundedText(subject["working_directory"], 4_096) ||
            subject["arguments"] is not JsonArray arguments || arguments.Count > 128 ||
            arguments.Any(argument =>
                ManagedProtocol.Text(argument) is not string text || text.Length > 4_096) ||
            subject["environment_names"] is not JsonArray environmentNames ||
            environmentNames.Count > 256)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        HashSet<string> names = [];
        foreach (JsonNode? entry in environmentNames)
        {
            string? name = ManagedProtocol.Text(entry);
            if (name is null || name.Length is 0 or > 256 ||
                name.Any(character => character is < '!' or > '~' or '=') ||
                !names.Add(name))
            {
                throw ManagedProtocol.SchemaInvalid();
            }
        }
    }

    private static bool ValidBoundedText(JsonNode? value, int maximumLength) =>
        ManagedProtocol.Text(value) is string text &&
        text.Length is > 0 && text.Length <= maximumLength;

    /// <summary>Returns the stable Deployment binding without signing state.</summary>
    public static string ManagedDeploymentBindingDigest(JsonObject deployment)
    {
        if (!ManagedProtocol.HasExactly(
                deployment, "format", "organization_id", "processing_mode", "project_id",
                "repository_id", "runtime_capabilities", "runtime_endpoint", "service_id",
                "service_path", "signature", "signed_at", "signer_key_id",
                "source_revision", "subject") ||
            ManagedProtocol.Text(deployment["processing_mode"]) != "managed")
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        JsonObject stable = (JsonObject)deployment.DeepClone();
        stable.Remove("signature");
        stable.Remove("signed_at");
        stable.Remove("signer_key_id");
        return ManagedProtocol.CanonicalDigest(stable);
    }

    private sealed record QueuedCandidate(JsonObject Value, int Size, long Enqueued);

    private sealed class DeadlineManagedClient(
        IManagedRegistrationDelivery registration,
        IManagedGrantDelivery grants,
        IManagedIngressDelivery ingress,
        long enqueued,
        TimeSpan lifetime) :
        IManagedRegistrationDelivery, IManagedGrantDelivery, IManagedIngressDelivery
    {
        public JsonObject RegisterWorkloadKey(
            ManagedProjectToken projectToken, JsonObject request, TimeSpan timeout) =>
            Call(() => registration.RegisterWorkloadKey(
                projectToken, request, Remaining(timeout)));

        public EncryptionResponse RequestEncryptionGrant(
            JsonObject request, TimeSpan timeout) =>
            Call(() => grants.RequestEncryptionGrant(request, Remaining(timeout)));

        public JsonObject Start(JsonObject request, TimeSpan timeout) =>
            Call(() => ingress.Start(request, Remaining(timeout)));

        public JsonObject Missing(
            string uploadId, string uploadToken, string? cursor, TimeSpan timeout) =>
            Call(() => ingress.Missing(
                uploadId, uploadToken, cursor, Remaining(timeout)));

        public void UploadObject(
            string uploadUrl, string digest, byte[] value, TimeSpan timeout)
        {
            ingress.UploadObject(uploadUrl, digest, value, Remaining(timeout));
            EnsureAlive();
        }

        public JsonObject Commit(string uploadId, string uploadToken, TimeSpan timeout) =>
            Call(() => ingress.Commit(uploadId, uploadToken, Remaining(timeout)));

        public JsonObject Cancel(string uploadId, string uploadToken, TimeSpan timeout) =>
            Call(() => ingress.Cancel(uploadId, uploadToken, Remaining(timeout)));

        private T Call<T>(Func<T> operation)
        {
            T result = operation();
            EnsureAlive();
            return result;
        }

        private TimeSpan Remaining(TimeSpan requested)
        {
            TimeSpan remaining = lifetime - Stopwatch.GetElapsedTime(enqueued);
            if (remaining <= TimeSpan.Zero)
            {
                throw Expired();
            }
            return requested <= remaining ? requested : remaining;
        }

        private void EnsureAlive()
        {
            if (Stopwatch.GetElapsedTime(enqueued) >= lifetime)
            {
                throw Expired();
            }
        }

        private static ManagedCaptureException Expired() => new(
            "UPLOAD_EXPIRED", "The managed candidate delivery lifetime expired.");
    }
}
