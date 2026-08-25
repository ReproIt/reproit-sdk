using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Requests managed candidate encryption grants.</summary>
public interface IManagedGrantDelivery
{
    /// <summary>Requests one managed candidate encryption grant.</summary>
    EncryptionResponse RequestEncryptionGrant(JsonObject request, TimeSpan timeout);
}

/// <summary>Drives the bounded managed ingress upload session.</summary>
public interface IManagedIngressDelivery
{
    /// <summary>Starts one managed candidate upload session.</summary>
    JsonObject Start(JsonObject request, TimeSpan timeout);

    /// <summary>Fetches one bounded missing-object page.</summary>
    JsonObject Missing(string uploadId, string uploadToken, string? cursor, TimeSpan timeout);

    /// <summary>Uploads one sealed object to its bound URL.</summary>
    void UploadObject(string uploadUrl, string digest, byte[] value, TimeSpan timeout);

    /// <summary>Commits one complete upload session.</summary>
    JsonObject Commit(string uploadId, string uploadToken, TimeSpan timeout);

    /// <summary>Cancels one upload session.</summary>
    JsonObject Cancel(string uploadId, string uploadToken, TimeSpan timeout);
}

/// <summary>Prepares, seals, and uploads one managed candidate.</summary>
/// <remarks>
/// Mirrors crates/reproit-sdk-rust/src/managed.rs: the SDK proves local
/// completeness first, then requests one managed candidate encryption
/// grant, seals every object with AES-256-GCM keyed through HKDF-SHA-256,
/// and drives the start, missing, object-PUT, commit, and cancel upload
/// session. An incomplete candidate stops before any network request.
/// </remarks>
public sealed class PreparedManagedCandidate
{
    /// <summary>The grant and per-page request timeout.</summary>
    public static readonly TimeSpan GrantTimeout = TimeSpan.FromSeconds(5);

    // The ingress verifies the digest and size of every declared ciphertext
    // byte before it commits, so the commit wait scales with the declared
    // closure. The rule mirrors the Rust reference: a five-second floor, a
    // conservative verification rate, and a hard cap.
    internal const double CommitTimeoutFloorSeconds = 5.0;
    internal const long CommitVerificationBytesPerSecond = 4 * 1024 * 1024;
    internal const double CommitTimeoutCapSeconds = 180.0;

    private static readonly Dictionary<string, HashSet<string>> CompletionsByKind = new()
    {
        ["request-response"] = ["return"],
        ["stream"] = ["stream-end"],
        ["delivered-work"] = ["acknowledgment", "task-end"],
    };

    private readonly JsonObject identity;
    private readonly List<PreparedObject> objects;

    private PreparedManagedCandidate(JsonObject identity, List<PreparedObject> objects)
    {
        this.identity = identity;
        this.objects = objects;
    }

    /// <summary>Gets the validated managed candidate identity.</summary>
    public JsonObject Identity => identity;

    internal static double CommitTimeoutSeconds(long totalCiphertextBytes)
    {
        // Overflow-safe ceiling division: the declared closure can be any
        // non-negative 64-bit byte count.
        long verificationSeconds =
            totalCiphertextBytes / CommitVerificationBytesPerSecond +
            (totalCiphertextBytes % CommitVerificationBytesPerSecond > 0 ? 1 : 0);
        return Math.Min(
            CommitTimeoutCapSeconds, CommitTimeoutFloorSeconds + verificationSeconds);
    }

    /// <summary>Proves one candidate's local closure and prepares its objects.</summary>
    public static PreparedManagedCandidate PrepareComplete(
        JsonObject candidate,
        DotnetSubjectPackage subject,
        FrozenManagedCaptureClosure closure)
    {
        ManagedCaptureClosure frozen = closure.Closure;
        ValidateCandidateLocal(candidate);
        ManagedSubject.ValidateSubjectClosureManifest(subject.Manifest);
        if (ManagedProtocol.Text(candidate["processing_mode"]) != "managed")
        {
            throw ManagedProtocol.SchemaInvalid(
                "Managed capture requires a managed deployment.");
        }
        ValidateSubjectBinding(candidate, subject.Manifest);
        if (closure.WorldId() != ManagedProtocol.Text(candidate["world_id"]))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }

        List<PreparedObject> objects = [];
        try
        {
            PushBytes(
                objects, ManagedProtocol.NewObjectId(), "candidate",
                ManagedProtocol.CandidateMediaType, CanonicalJson.Bytes(candidate));
            PushSubject(objects, subject);
            PushTriggerAndInputs(objects, candidate, frozen.Completion);
            PushFailure(objects, candidate);
            PushBytes(
                objects, ManagedProtocol.NewObjectId(), "world-manifest",
                ManagedProtocol.WorldManifestMediaType, CanonicalJson.Bytes(frozen.World));
            PushCaptureArtifacts(objects, candidate, frozen.World, frozen.Artifacts);
        }
        catch (Exception error) when (error is InvalidOperationException or
            NullReferenceException or KeyNotFoundException or InvalidCastException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        objects.Sort((left, right) => string.CompareOrdinal(
            ManagedProtocol.Text(left.Descriptor["object_id"]),
            ManagedProtocol.Text(right.Descriptor["object_id"])));
        VerifyLocalClosure(objects);

        JsonArray descriptors = [];
        long totalPlaintextBytes = 0;
        foreach (PreparedObject entry in objects)
        {
            descriptors.Add(entry.Descriptor.DeepClone());
            totalPlaintextBytes += ManagedProtocol.Count(entry.Descriptor["plain_size"])!.Value;
        }
        JsonObject deployment = (JsonObject)candidate["deployment"]!;
        JsonObject identity = new()
        {
            ["candidate_digest"] = ManagedProtocol.CanonicalDigest(candidate),
            ["capture_id"] = candidate["capture_id"]!.DeepClone(),
            ["deployment_digest"] = ManagedProtocol.CanonicalDigest(deployment),
            ["format"] = ManagedProtocol.CandidateIdentityFormat,
            ["objects"] = descriptors,
            ["organization_id"] = deployment["organization_id"]!.DeepClone(),
            ["processing_mode"] = "managed",
            ["project_id"] = deployment["project_id"]!.DeepClone(),
            ["required_capabilities"] = deployment["runtime_capabilities"]!.DeepClone(),
            ["service_id"] = deployment["service_id"]!.DeepClone(),
            ["subject_digest"] = ManagedProtocol.CanonicalDigest(subject.Manifest),
            ["total_plaintext_bytes"] = totalPlaintextBytes,
        };
        ManagedProtocol.ValidateManagedCandidateIdentity(identity);
        return new PreparedManagedCandidate(identity, objects);
    }

    /// <summary>Requests one encryption grant after re-proving the closure.</summary>
    public EncryptionResponse RequestEncryptionGrant(
        IManagedGrantDelivery delivery,
        string deploymentDigest,
        string workloadKeyId,
        byte[] workloadSigningKey)
    {
        ManagedProtocol.ValidateManagedCandidateIdentity(identity);
        VerifyLocalClosure(objects);
        JsonObject request = new()
        {
            ["candidate_identity_digest"] = ManagedProtocol.CanonicalDigest(identity),
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["cipher_suite"] = ManagedProtocol.CipherSuite,
            ["deployment_digest"] = deploymentDigest,
            ["organization_id"] = identity["organization_id"]!.DeepClone(),
            ["processing_mode"] = "managed",
            ["project_id"] = identity["project_id"]!.DeepClone(),
            ["service_id"] = identity["service_id"]!.DeepClone(),
            ["signature"] = "",
            ["signer_key_id"] = workloadKeyId,
        };
        request["signature"] = ManagedProtocol.SignBytes(
            CanonicalJson.Bytes(request), workloadSigningKey);
        return delivery.RequestEncryptionGrant(request, GrantTimeout);
    }

    /// <summary>Seals every object under the granted candidate key.</summary>
    public SealedManagedCandidate Seal(
        EncryptionResponse response,
        string now,
        string captureSignerId,
        byte[] captureSignerPublicKey)
    {
        string identityDigest = ManagedProtocol.CanonicalDigest(identity);
        string keyReference =
            ManagedProtocol.Text(response.CaptureGrant["candidate_key_reference"]) ?? "";
        ManagedProtocol.VerifyCaptureGrant(
            response.CaptureGrant,
            new JsonObject
            {
                ["candidate_identity_digest"] = identityDigest,
                ["candidate_key_reference"] = keyReference,
                ["capture_id"] = identity["capture_id"]!.DeepClone(),
                ["organization_id"] = identity["organization_id"]!.DeepClone(),
                ["project_id"] = identity["project_id"]!.DeepClone(),
                ["service_id"] = identity["service_id"]!.DeepClone(),
                ["signer_key_id"] = captureSignerId,
            },
            now,
            captureSignerPublicKey);
        VerifyLocalClosure(objects);

        string spool = Directory
            .CreateTempSubdirectory("reproit-managed-candidate-").FullName;
        try
        {
            Dictionary<string, string> ciphertext = [];
            NonceRegistry nonces = new();
            JsonArray encryptedObjects = [];
            long totalCiphertextBytes = 0;
            foreach (PreparedObject entry in objects)
            {
                JsonObject encrypted = EncryptObject(
                    response.CandidateKey, identity, entry, spool, ciphertext, nonces);
                foreach (JsonNode? chunk in (JsonArray)encrypted["chunks"]!)
                {
                    totalCiphertextBytes += ManagedProtocol.Count(chunk!["cipher_size"])!.Value;
                }
                encryptedObjects.Add(encrypted);
            }
            JsonObject manifest = new()
            {
                ["candidate_identity"] = identity.DeepClone(),
                ["candidate_identity_digest"] = identityDigest,
                ["candidate_key_reference"] = keyReference,
                ["cipher_suite"] = ManagedProtocol.CipherSuite,
                ["format"] = ManagedProtocol.CandidateManifestFormat,
            };
            JsonObject manifestObject = EncryptManifest(
                response.CandidateKey, identity, ManagedProtocol.NewObjectId(),
                CanonicalJson.Bytes(manifest), spool, ciphertext, nonces);
            totalCiphertextBytes += ManagedProtocol.Count(manifestObject["cipher_size"])!.Value;
            JsonObject ciphertextIdentity = new()
            {
                ["candidate_identity_digest"] = identityDigest,
                ["candidate_key_reference"] = keyReference,
                ["capture_id"] = identity["capture_id"]!.DeepClone(),
                ["cipher_suite"] = ManagedProtocol.CipherSuite,
                ["format"] = ManagedProtocol.CiphertextIdentityFormat,
                ["manifest_object"] = manifestObject,
                ["objects"] = encryptedObjects,
                ["organization_id"] = identity["organization_id"]!.DeepClone(),
                ["processing_mode"] = "managed",
                ["project_id"] = identity["project_id"]!.DeepClone(),
                ["required_capabilities"] = identity["required_capabilities"]!.DeepClone(),
                ["service_id"] = identity["service_id"]!.DeepClone(),
                ["total_ciphertext_bytes"] = totalCiphertextBytes,
            };
            ManagedProtocol.ValidateCiphertextIdentity(ciphertextIdentity);
            JsonObject request = new()
            {
                ["capture_grant"] = response.CaptureGrant.DeepClone(),
                ["ciphertext_identity"] = ciphertextIdentity,
                ["encrypted_candidate_digest"] =
                    ManagedProtocol.CanonicalDigest(ciphertextIdentity),
            };
            ManagedProtocol.ValidateUploadRequest(request);
            return new SealedManagedCandidate(
                request, response.CandidateKey, ciphertext, spool);
        }
        catch
        {
            try
            {
                Directory.Delete(spool, recursive: true);
            }
            catch (Exception error) when (error is IOException or
                UnauthorizedAccessException or DirectoryNotFoundException)
            {
                // Spool cleanup is best effort. The directory is private.
            }
            throw;
        }
    }

    /// <summary>Proves the deployment subject binds the running subject package.</summary>
    public static void ValidateSubjectBinding(JsonObject candidate, JsonObject manifest)
    {
        JsonObject? deployment = candidate["deployment"] as JsonObject;
        JsonObject? subject = deployment?["subject"] as JsonObject;
        if (subject is null)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        string manifestDigest = ManagedProtocol.CanonicalDigest(manifest);
        JsonObject launch = (JsonObject)manifest["launch"]!;
        JsonNode? capabilities = deployment!["runtime_capabilities"];
        string? architecture = ManagedProtocol.Text(manifest["architecture"]);
        string? operatingSystem = ManagedProtocol.Text(manifest["operating_system"]);
        if (ManagedProtocol.Text(subject["artifact_digest"]) != manifestDigest ||
            ManagedProtocol.Text(subject["artifact_media_type"]) !=
                ManagedProtocol.SubjectManifestMediaType ||
            ManagedProtocol.Text(subject["architecture"]) != architecture ||
            ManagedProtocol.Text(subject["operating_system"]) != operatingSystem ||
            !JsonEqual(subject["arguments"], launch["arguments"]) ||
            !JsonEqual(subject["environment_names"], launch["environment_names"]) ||
            ManagedProtocol.Text(subject["executable"]) !=
                ManagedProtocol.Text(launch["executable"]) ||
            ManagedProtocol.Text(subject["working_directory"]) !=
                ManagedProtocol.Text(launch["working_directory"]) ||
            capabilities is not JsonArray capabilityList ||
            !capabilityList.Any(entry => ManagedProtocol.Text(entry) == architecture) ||
            !capabilityList.Any(entry => ManagedProtocol.Text(entry) == operatingSystem))
        {
            throw new ManagedCaptureException(
                "SUBJECT_DIGEST_MISMATCH",
                "The managed deployment does not match the running subject package.");
        }
    }

    private static bool JsonEqual(JsonNode? left, JsonNode? right) =>
        left is not null && right is not null &&
        CanonicalJson.Bytes(left).AsSpan().SequenceEqual(CanonicalJson.Bytes(right));

    /// <summary>Proves the candidate record closure locally before any request.</summary>
    private static void ValidateCandidateLocal(JsonObject candidate)
    {
        JsonNode? deploymentNode = candidate["deployment"];
        if (ManagedProtocol.Text(candidate["format"]) != "reproit.candidate.v1" ||
            !ManagedProtocol.ValidTypedId(candidate["capture_id"], "capture_id") ||
            !ManagedProtocol.ValidTypedId(candidate["operation_id"], "operation_id") ||
            !ManagedProtocol.ValidDigest(candidate["world_id"]) ||
            candidate["records"] is not JsonArray ||
            deploymentNode is not JsonObject deployment ||
            !ManagedProtocol.ValidTypedId(deployment["organization_id"], "organization_id") ||
            !ManagedProtocol.ValidTypedId(deployment["project_id"], "project_id") ||
            !ManagedProtocol.ValidTypedId(deployment["service_id"], "service_id") ||
            ManagedProtocol.Text(candidate["processing_mode"]) is null ||
            ManagedProtocol.Text(candidate["processing_mode"]) !=
                ManagedProtocol.Text(deployment["processing_mode"]))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        try
        {
            ManagedProtocol.DecodeBase64Url(
                ManagedProtocol.Text(deployment["signature"]), 64);
        }
        catch (ManagedCaptureException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        try
        {
            CandidateProtocol.Validate(candidate);
        }
        catch (CaptureException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
    }

    internal static JsonObject DecodeRecordPayload(JsonNode? record)
    {
        if (record is not JsonObject value ||
            ManagedProtocol.Text(value["payload"]) is not string payload)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        try
        {
            byte[] decoded = ManagedProtocol.DecodeBase64Url(payload);
            return ManagedProtocol.ParseStrictJson(
                decoded, ManagedProtocol.MaxChunkBytes) as JsonObject
                ?? throw ManagedProtocol.IncompleteCandidate();
        }
        catch (ManagedCaptureException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
    }

    private static void PushBytes(
        List<PreparedObject> objects,
        string objectId,
        string role,
        string mediaType,
        byte[] content)
    {
        JsonObject descriptor = new()
        {
            ["media_type"] = mediaType,
            ["object_id"] = objectId,
            ["plain_digest"] = ManagedProtocol.DigestBytes(content),
            ["plain_size"] = content.LongLength,
            ["role"] = role,
        };
        objects.Add(new PreparedObject(descriptor, content, null));
    }

    private static void PushFile(
        List<PreparedObject> objects,
        string objectId,
        string mediaType,
        string digest,
        long size,
        string path,
        string role)
    {
        JsonObject descriptor = new()
        {
            ["media_type"] = mediaType,
            ["object_id"] = objectId,
            ["plain_digest"] = digest,
            ["plain_size"] = size,
            ["role"] = role,
        };
        objects.Add(new PreparedObject(descriptor, null, path));
    }

    private static void PushSubject(
        List<PreparedObject> objects, DotnetSubjectPackage subject)
    {
        PushBytes(
            objects, ManagedProtocol.NewObjectId(), "subject",
            ManagedProtocol.SubjectManifestMediaType,
            CanonicalJson.Bytes(subject.Manifest));
        Dictionary<string, (string MediaType, long Size)> declared = [];
        foreach (JsonNode? entry in (JsonArray)subject.Manifest["objects"]!)
        {
            declared[ManagedProtocol.Text(entry!["digest"])!] = (
                ManagedProtocol.Text(entry["media_type"])!,
                ManagedProtocol.Count(entry["size"])!.Value);
        }
        if (declared.Count != subject.Objects.Count)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        foreach (PackagedSubjectObject packaged in subject.Objects)
        {
            if (!declared.TryGetValue(
                    packaged.Digest, out (string MediaType, long Size) entry) ||
                entry.Size != packaged.Size)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            PushFile(
                objects, ManagedProtocol.NewObjectId(), entry.MediaType,
                packaged.Digest, packaged.Size, packaged.Path, "subject");
        }
    }

    private static void PushTriggerAndInputs(
        List<PreparedObject> objects, JsonObject candidate, string completion)
    {
        JsonArray records = (JsonArray)candidate["records"]!;
        JsonObject begin = DecodeRecordPayload(records[0]);
        JsonArray inputs = [];
        foreach (JsonNode? record in records)
        {
            if (ManagedProtocol.Text(record!["kind"]) != "input")
            {
                continue;
            }
            JsonObject payload = DecodeRecordPayload(record);
            byte[] content = ManagedProtocol.DecodeBase64Url(
                ManagedProtocol.Text(payload["value"]));
            string objectId = ManagedProtocol.NewObjectId();
            inputs.Add(new JsonObject
            {
                ["channel"] = payload["channel"]!.DeepClone(),
                ["object_id"] = objectId,
                ["plain_digest"] = payload["value_digest"]!.DeepClone(),
                ["sequence"] = inputs.Count,
            });
            PushBytes(
                objects, objectId, "trigger",
                ManagedProtocol.Text(payload["content_type"])!, content);
        }
        string? operationKind = ManagedProtocol.Text(begin["operation_kind"]);
        HashSet<string> allowed = operationKind is not null &&
            CompletionsByKind.TryGetValue(operationKind, out HashSet<string>? found)
                ? found
                : [];
        string? adapterId = ManagedProtocol.Text(begin["adapter_id"]);
        string? adapterVersion = ManagedProtocol.Text(begin["adapter_version"]);
        string? operationName = ManagedProtocol.Text(begin["operation_name"]);
        JsonNode? causalParents = begin["causal_parent_ids"];
        if (inputs.Count is 0 or > 1_024 || !allowed.Contains(completion) ||
            adapterId is null || adapterId.Length is 0 or > 128 ||
            adapterVersion is null || adapterVersion.Length is 0 or > 64 ||
            operationName is null || operationName.Length is 0 or > 128 ||
            causalParents is not JsonArray parents || parents.Count > 32 ||
            parents.Select(parent => ManagedProtocol.Text(parent))
                .Distinct().Count() != parents.Count ||
            parents.Any(parent =>
                !ManagedProtocol.ValidTypedId(parent, "operation_id")))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        JsonObject trigger = new()
        {
            ["adapter_id"] = begin["adapter_id"]!.DeepClone(),
            ["adapter_version"] = begin["adapter_version"]!.DeepClone(),
            ["causal_parent_ids"] = begin["causal_parent_ids"]!.DeepClone(),
            ["completion"] = completion,
            ["format"] = "reproit.trigger.v1",
            ["inputs"] = inputs,
            ["operation_id"] = candidate["operation_id"]!.DeepClone(),
            ["operation_kind"] = operationKind,
            ["operation_name"] = begin["operation_name"]!.DeepClone(),
        };
        PushBytes(
            objects, ManagedProtocol.NewObjectId(), "trigger",
            ManagedProtocol.TriggerMediaType, CanonicalJson.Bytes(trigger));
    }

    private static void PushFailure(List<PreparedObject> objects, JsonObject candidate)
    {
        JsonNode? record = ((JsonArray)candidate["records"]!)
            .FirstOrDefault(entry => ManagedProtocol.Text(entry!["kind"]) == "failure");
        if (record is null)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        JsonObject payload = DecodeRecordPayload(record);
        if (payload["failure"] is not JsonObject failure ||
            !ManagedProtocol.ValidTypedId(failure["object_id"], "object_id"))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        PushBytes(
            objects, ManagedProtocol.Text(failure["object_id"])!, "failure",
            ManagedProtocol.FailureMediaType, CanonicalJson.Bytes(payload));
    }

    private static void PushCaptureArtifacts(
        List<PreparedObject> objects,
        JsonObject candidate,
        JsonObject world,
        IReadOnlyList<ManagedCandidateArtifact> artifacts)
    {
        List<JsonNode?> dependencyRecords = ((JsonArray)candidate["records"]!)
            .Where(record => ManagedProtocol.Text(record!["kind"]) == "dependency")
            .ToList();
        bool requiresArtifacts =
            ManagedClosure.ExpectedWorldArtifacts(world).Count > 0 ||
            dependencyRecords.Count > 0;
        if (artifacts.Count == 0 && requiresArtifacts)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        foreach (ManagedCandidateArtifact artifact in artifacts)
        {
            (long size, string digest) = ManagedClosure.HashFile(artifact.Path);
            PushFile(
                objects, artifact.ObjectId, artifact.MediaType, digest, size,
                artifact.Path, artifact.Role);
        }
        ValidateDependencyClosure(candidate, objects, dependencyRecords);
    }

    private static void ValidateDependencyClosure(
        JsonObject candidate,
        List<PreparedObject> objects,
        List<JsonNode?> dependencyRecords)
    {
        List<JsonObject> cursors =
            dependencyRecords.Select(DecodeRecordPayload).ToList();
        Dictionary<string, JsonObject> descriptors = objects.ToDictionary(
            entry => ManagedProtocol.Text(entry.Descriptor["object_id"])!,
            entry => entry.Descriptor);
        string operationId = ManagedProtocol.Text(candidate["operation_id"])!;
        List<JsonObject> transcripts = [];
        foreach (PreparedObject entry in objects)
        {
            JsonObject descriptor = entry.Descriptor;
            if (ManagedProtocol.Text(descriptor["role"]) != "dependency-transcript" ||
                ManagedProtocol.Text(descriptor["media_type"]) !=
                    ManagedProtocol.DependencyTranscriptMediaType)
            {
                continue;
            }
            JsonObject transcript = ManagedClosure.ValidateTranscriptBytes(entry.Read());
            foreach (JsonNode? interaction in (JsonArray)transcript["interactions"]!)
            {
                bool boundToOperation =
                    ManagedProtocol.Text(interaction!["operation_id"]) == operationId ||
                    ManagedProtocol.Text(interaction["causal_parent_id"]) == operationId;
                if (!boundToOperation ||
                    !DescriptorMatches(
                        descriptors,
                        ManagedProtocol.Text(interaction["request_object_id"]),
                        ManagedProtocol.Text(interaction["request_digest"])) ||
                    !DescriptorMatches(
                        descriptors,
                        ManagedProtocol.Text(interaction["response_object_id"]),
                        ManagedProtocol.Text(interaction["response_digest"])))
                {
                    throw ManagedProtocol.IncompleteCandidate();
                }
            }
            transcripts.Add(transcript);
        }
        if (cursors.Count != transcripts.Count || cursors.Any(cursor =>
            transcripts.Count(transcript =>
                ManagedProtocol.Text(transcript["adapter_id"]) ==
                    ManagedProtocol.Text(cursor["adapter_id"]) &&
                ManagedProtocol.Text(transcript["adapter_version"]) ==
                    ManagedProtocol.Text(cursor["adapter_version"])) != 1))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
    }

    private static bool DescriptorMatches(
        Dictionary<string, JsonObject> descriptors, string? objectId, string? digest) =>
        objectId is not null &&
        descriptors.TryGetValue(objectId, out JsonObject? descriptor) &&
        ManagedProtocol.Text(descriptor["plain_digest"]) == digest;

    private static void VerifyLocalClosure(List<PreparedObject> objects)
    {
        if (objects.Count is < 5 or > 32_767)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        HashSet<string> objectIds = [];
        long totalBytes = 0;
        foreach (PreparedObject entry in objects)
        {
            JsonObject descriptor = entry.Descriptor;
            if (!objectIds.Add(ManagedProtocol.Text(descriptor["object_id"])!))
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            long actualSize;
            string actualDigest;
            if (entry.Content is byte[] content)
            {
                actualSize = content.LongLength;
                actualDigest = ManagedProtocol.DigestBytes(content);
            }
            else
            {
                (actualSize, actualDigest) = ManagedClosure.HashFile(entry.Path!);
            }
            if (actualSize != ManagedProtocol.Count(descriptor["plain_size"]) ||
                actualDigest != ManagedProtocol.Text(descriptor["plain_digest"]))
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            totalBytes = checked(totalBytes + actualSize);
            if (totalBytes > 4L * 1024 * 1024 * 1024)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
        }
    }

    private static JsonObject EncryptObject(
        byte[] candidateKey,
        JsonObject identity,
        PreparedObject entry,
        string spoolPath,
        Dictionary<string, string> ciphertext,
        NonceRegistry nonces)
    {
        JsonObject descriptor = entry.Descriptor;
        long plainSize = ManagedProtocol.Count(descriptor["plain_size"])!.Value;
        long chunkCount = (Math.Max(plainSize, 1) + ManagedProtocol.MaxChunkBytes - 1) /
            ManagedProtocol.MaxChunkBytes;
        if (chunkCount > 32_767)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        string captureId = ManagedProtocol.Text(identity["capture_id"])!;
        JsonObject context = ManagedProtocol.ObjectKeyContext(
            identity,
            ManagedProtocol.Text(descriptor["object_id"])!,
            ManagedProtocol.Text(descriptor["role"])!);
        string contextDigest = ManagedProtocol.CanonicalDigest(context);
        byte[] objectKey = ManagedProtocol.DeriveObjectKey(candidateKey, captureId, context);
        using ObjectReader reader = new(entry);
        using IncrementalHash plainHasher =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        JsonArray chunks = [];
        long remaining = plainSize;
        for (long index = 0; index < chunkCount; index += 1)
        {
            int chunkPlainSize = (int)Math.Min(remaining, ManagedProtocol.MaxChunkBytes);
            byte[] plaintext = reader.ReadExact(chunkPlainSize);
            plainHasher.AppendData(plaintext);
            JsonObject chunkContext = ManagedProtocol.ChunkKeyContext(
                contextDigest, chunkCount, index, chunkPlainSize);
            byte[] chunkKey = ManagedProtocol.DeriveChunkKey(objectKey, chunkContext);
            byte[] nonce = RandomNonce(nonces);
            byte[] stored =
                ManagedProtocol.EncryptChunk(chunkKey, nonce, plaintext, chunkContext);
            chunks.Add(StoreCiphertext(spoolPath, ciphertext, index, nonce, stored));
            remaining -= chunkPlainSize;
        }
        string plainDigest = "sha256:" + Convert
            .ToHexString(plainHasher.GetHashAndReset()).ToLowerInvariant();
        if (remaining != 0 || !reader.AtEnd() ||
            plainDigest != ManagedProtocol.Text(descriptor["plain_digest"]))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        return new JsonObject
        {
            ["chunks"] = chunks,
            ["descriptor"] = descriptor.DeepClone(),
        };
    }

    private static JsonObject EncryptManifest(
        byte[] candidateKey,
        JsonObject identity,
        string objectId,
        byte[] plaintext,
        string spoolPath,
        Dictionary<string, string> ciphertext,
        NonceRegistry nonces)
    {
        if (plaintext.Length > ManagedProtocol.MaxChunkBytes)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        string captureId = ManagedProtocol.Text(identity["capture_id"])!;
        JsonObject context =
            ManagedProtocol.ObjectKeyContext(identity, objectId, "capture-batch-manifest");
        JsonObject chunkContext = ManagedProtocol.ChunkKeyContext(
            ManagedProtocol.CanonicalDigest(context), 1, 0, plaintext.Length);
        byte[] objectKey = ManagedProtocol.DeriveObjectKey(candidateKey, captureId, context);
        byte[] chunkKey = ManagedProtocol.DeriveChunkKey(objectKey, chunkContext);
        byte[] nonce = RandomNonce(nonces);
        byte[] stored = ManagedProtocol.EncryptChunk(chunkKey, nonce, plaintext, chunkContext);
        JsonObject chunk = StoreCiphertext(spoolPath, ciphertext, 0, nonce, stored);
        return new JsonObject
        {
            ["cipher_digest"] = chunk["cipher_digest"]!.DeepClone(),
            ["cipher_size"] = chunk["cipher_size"]!.DeepClone(),
            ["nonce"] = chunk["nonce"]!.DeepClone(),
            ["object_id"] = objectId,
        };
    }

    private static JsonObject StoreCiphertext(
        string spoolPath,
        Dictionary<string, string> ciphertext,
        long index,
        byte[] nonce,
        byte[] stored)
    {
        string digest = ManagedProtocol.DigestBytes(stored);
        string path = Path.Combine(spoolPath, digest["sha256:".Length..]);
        try
        {
            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, stored);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw LocalStorageError();
        }
        if (ciphertext.TryGetValue(digest, out string? existing) && existing != path)
        {
            throw ManagedProtocol.ObjectDigestMismatch();
        }
        ciphertext[digest] = path;
        return new JsonObject
        {
            ["cipher_digest"] = digest,
            ["cipher_size"] = stored.LongLength,
            ["index"] = index,
            ["nonce"] = ManagedProtocol.EncodeBase64Url(nonce),
        };
    }

    private static byte[] RandomNonce(NonceRegistry nonces)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        nonces.Register(nonce);
        return nonce;
    }

    internal static ManagedCaptureException LocalStorageError() => new(
        "SERVICE_UNAVAILABLE",
        "Repro It could not create the bounded local ciphertext staging area.");

    internal static ManagedCaptureException UploadStateError() => new(
        "SERVICE_UNAVAILABLE",
        "The managed candidate upload did not reach a valid durable state.");

    internal sealed class PreparedObject(JsonObject descriptor, byte[]? content, string? path)
    {
        public JsonObject Descriptor { get; } = descriptor;
        public byte[]? Content { get; } = content;
        public string? Path { get; } = path;

        public byte[] Read()
        {
            if (ManagedProtocol.Count(Descriptor["plain_size"]) >
                ManagedProtocol.MaxChunkBytes)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            if (Content is byte[] content)
            {
                return content;
            }
            return ManagedClosure.ReadBounded(
                Path!, ManagedProtocol.Count(Descriptor["plain_size"])!.Value);
        }
    }

    /// <summary>Reads bounded chunks over an in-memory or spooled object.</summary>
    private sealed class ObjectReader : IDisposable
    {
        private readonly byte[] content = [];
        private readonly FileStream? source;
        private int offset;

        public ObjectReader(PreparedObject entry)
        {
            if (entry.Content is byte[] value)
            {
                content = value;
                return;
            }
            try
            {
                source = File.OpenRead(entry.Path!);
            }
            catch (Exception error) when (error is IOException or
                UnauthorizedAccessException)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
        }

        public byte[] ReadExact(int size)
        {
            byte[] value = new byte[size];
            if (source is null)
            {
                if (offset + size > content.Length)
                {
                    throw ManagedProtocol.IncompleteCandidate();
                }
                content.AsSpan(offset, size).CopyTo(value);
                offset += size;
                return value;
            }
            try
            {
                if (source.ReadAtLeast(value, size, throwOnEndOfStream: false) != size)
                {
                    throw ManagedProtocol.IncompleteCandidate();
                }
            }
            catch (IOException)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            return value;
        }

        public bool AtEnd()
        {
            if (source is null)
            {
                return offset >= content.Length;
            }
            try
            {
                return source.ReadByte() < 0;
            }
            catch (IOException)
            {
                return false;
            }
        }

        public void Dispose() => source?.Dispose();
    }
}
