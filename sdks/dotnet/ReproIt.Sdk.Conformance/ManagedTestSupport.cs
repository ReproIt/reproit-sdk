using System.Text.Json.Nodes;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

/// <summary>Shared fixtures for the managed-mode capture client checks.</summary>
internal static class ManagedFixtures
{
    internal const string CaptureId = "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc";
    internal const string OperationId = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1";
    internal const string OrganizationId = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd";
    internal const string ProjectId = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe";
    internal const string ServiceId = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf";
    internal const string UploadId = "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1";
    internal const string CaptureSignerId = "managed-candidate-capture-test";
    internal const string GrantVerificationTime = "2026-01-01T00:00:30.000Z";

    internal static readonly byte[] CaptureSignerSeed = Repeat(0x83);
    internal static readonly byte[] WorkloadSeed = Repeat(0x77);
    internal static readonly string WorkloadKeyId = ManagedProtocol.WorkloadKeyId(
        ManagedProtocol.VerificationKey(WorkloadSeed));
    internal static readonly byte[] CandidateKey = Repeat(0x42);
    internal static readonly string KeyReference =
        ManagedProtocol.EncodeBase64Url(Repeat(0x91));
    internal static readonly string GrantId =
        ManagedProtocol.EncodeBase64Url(Repeat(0x92));

    private static JsonObject? protocolVectors;
    private static JsonObject? cloudVectors;
    private static DotnetSubjectPackage? sharedSubject;

    internal static byte[] Repeat(byte value)
    {
        byte[] bytes = new byte[32];
        Array.Fill(bytes, value);
        return bytes;
    }

    internal static void Check(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    internal static TExpected CheckThrows<TExpected>(Action action, string message)
        where TExpected : Exception
    {
        try
        {
            action();
        }
        catch (TExpected expected)
        {
            return expected;
        }
        throw new InvalidOperationException(message);
    }

    internal static void RequireManagedFailure(
        Action action, string expectedCode, string message)
    {
        ManagedCaptureException failure =
            CheckThrows<ManagedCaptureException>(action, message);
        Check(failure.Code == expectedCode,
            $"{message} (code {failure.Code}, wanted {expectedCode})");
    }

    internal static string ProtocolVectorsPath() =>
        Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS")
            ?? throw new InvalidOperationException("REPROIT_PROTOCOL_VECTORS is required.");

    internal static string CloudVectorsPath() =>
        Environment.GetEnvironmentVariable("REPROIT_CLOUD_API_VECTORS")
            ?? Path.Combine(
                Path.GetDirectoryName(ProtocolVectorsPath())!, "cloud-api-vectors.json");

    internal static JsonObject ProtocolVectors() => protocolVectors ??=
        (JsonObject)JsonNode.Parse(File.ReadAllText(ProtocolVectorsPath()))!;

    internal static JsonObject CloudVectors() => cloudVectors ??=
        (JsonObject)JsonNode.Parse(File.ReadAllText(CloudVectorsPath()))!;

    internal static JsonObject ProtocolPositive(string name) =>
        (JsonObject)ProtocolVectors()["positive"]![name]!["value"]!.DeepClone();

    internal static JsonObject CloudPositive(string name) =>
        (JsonObject)CloudVectors()["positive"]![name]!["value"]!.DeepClone();

    internal static string CanonicalSha256(string name) =>
        ProtocolVectors()["canonical_sha256"]![name]!.GetValue<string>();

    /// <summary>Packages one running-subject closure and reuses it.</summary>
    internal static DotnetSubjectPackage SharedSubject() =>
        sharedSubject ??= ManagedSubject.PackageRunningDotnetSubject();

    internal static JsonObject EmptyWorld() => new()
    {
        ["created_at"] = "2026-01-01T00:00:00.000Z",
        ["format"] = "reproit.world-checkpoint.v1",
        ["points"] = new JsonArray(),
    };

    internal static JsonObject BoundDeployment(
        DotnetSubjectPackage subject,
        byte[]? workloadSeed = null,
        string? signerKeyId = null)
    {
        workloadSeed ??= WorkloadSeed;
        signerKeyId ??= WorkloadKeyId;
        JsonObject manifest = subject.Manifest;
        HashSet<string> capabilities =
        [
            "runtime.dotnet",
            ManagedProtocol.Text(manifest["architecture"])!,
            ManagedProtocol.Text(manifest["operating_system"])!,
        ];
        JsonArray runtimeCapabilities = [];
        foreach (string capability in capabilities
            .OrderBy(value => value, StringComparer.Ordinal))
        {
            runtimeCapabilities.Add(capability);
        }
        JsonObject deployment = new()
        {
            ["format"] = "reproit.deployment.v1",
            ["organization_id"] = OrganizationId,
            ["processing_mode"] = "managed",
            ["project_id"] = ProjectId,
            ["repository_id"] = "source.example/acme/commerce",
            ["runtime_capabilities"] = runtimeCapabilities,
            ["runtime_endpoint"] = "https://managed.reproit.example",
            ["service_id"] = ServiceId,
            ["service_path"] = "services/orders",
            ["signature"] = "",
            ["signed_at"] = "2026-01-01T00:00:00.000Z",
            ["signer_key_id"] = signerKeyId,
            ["source_revision"] = "0123456789abcdef",
            ["subject"] = ManagedSubject.SubjectBinding(subject.Manifest),
        };
        deployment["signature"] = ManagedProtocol.SignBytes(
            CanonicalJson.Bytes(deployment), workloadSeed);
        return deployment;
    }

    /// <summary>Captures one complete managed candidate through the SDK.</summary>
    internal static JsonObject CapturedCandidate(JsonObject deployment, string worldId)
    {
        SdkProcessResources.ResetForTests();
        MemorySink sink = new();
        Sdk sdk = new(sink);
        CandidateStart start = new(
            CaptureId, deployment.DeepClone(), OperationId, worldId);
        sdk.Begin(start, ProtocolPositive("operation_begin_payload"));
        sdk.RecordInput(OperationId, ProtocolPositive("operation_input_payload"));
        sdk.Fail(OperationId, ProtocolPositive("failure_payload"));
        return (JsonObject)JsonNode.Parse(sink.Candidates.Single())!;
    }

    internal static JsonObject SignedCaptureGrant(
        JsonObject request,
        string? keyReference = null,
        string notBefore = "2026-01-01T00:00:00.000Z",
        string expiresAt = "2026-01-01T00:01:00.000Z",
        byte[]? signerSeed = null)
    {
        JsonObject grant = new()
        {
            ["candidate_identity_digest"] =
                request["candidate_identity_digest"]!.DeepClone(),
            ["candidate_key_reference"] = keyReference ?? KeyReference,
            ["capture_id"] = request["capture_id"]!.DeepClone(),
            ["cipher_suite"] = ManagedProtocol.CipherSuite,
            ["expires_at"] = expiresAt,
            ["format"] = ManagedProtocol.CaptureGrantFormat,
            ["grant_id"] = GrantId,
            ["not_before"] = notBefore,
            ["operation"] = "encrypt-and-upload-candidate",
            ["organization_id"] = request["organization_id"]!.DeepClone(),
            ["processing_mode"] = "managed",
            ["project_id"] = request["project_id"]!.DeepClone(),
            ["service_id"] = request["service_id"]!.DeepClone(),
            ["signature"] = "",
            ["signer_key_id"] = CaptureSignerId,
        };
        grant["signature"] = ManagedProtocol.SignBytes(
            CanonicalJson.Bytes(grant), signerSeed ?? CaptureSignerSeed);
        return grant;
    }

    /// <summary>Applies one negative-vector JSON-pointer replace mutation.</summary>
    internal static JsonObject ApplyMutation(JsonObject baseValue, JsonObject mutation)
    {
        Check(
            ManagedProtocol.Text(mutation["operation"]) == "replace",
            "only replace mutations are supported");
        JsonObject changed = (JsonObject)baseValue.DeepClone();
        string[] parts = ManagedProtocol.Text(mutation["path"])!
            .TrimStart('/').Split('/');
        JsonNode target = changed;
        foreach (string part in parts[..^1])
        {
            target = target is JsonArray array
                ? array[int.Parse(part)]!
                : target[part]!;
        }
        JsonNode? value = mutation["value"]?.DeepClone();
        if (target is JsonArray leafArray)
        {
            leafArray[int.Parse(parts[^1])] = value;
        }
        else
        {
            target[parts[^1]] = value;
        }
        return changed;
    }

    /// <summary>Independently decrypts every sealed object, verifying digests.</summary>
    internal static Dictionary<string, byte[]> OpenSealedObjectBytes(
        SealedManagedCandidate sealedCandidate, byte[] candidateKey)
    {
        JsonObject identity = (JsonObject)sealedCandidate.Request["ciphertext_identity"]!;
        string captureId = ManagedProtocol.Text(identity["capture_id"])!;
        Dictionary<string, byte[]> recovered = [];
        foreach (JsonNode? entry in (JsonArray)identity["objects"]!)
        {
            JsonObject descriptor = (JsonObject)entry!["descriptor"]!;
            JsonObject context = ManagedProtocol.ObjectKeyContext(
                identity,
                ManagedProtocol.Text(descriptor["object_id"])!,
                ManagedProtocol.Text(descriptor["role"])!);
            byte[] objectKey =
                ManagedProtocol.DeriveObjectKey(candidateKey, captureId, context);
            string contextDigest = ManagedProtocol.CanonicalDigest(context);
            JsonArray chunks = (JsonArray)entry["chunks"]!;
            using MemoryStream content = new();
            foreach (JsonNode? chunk in chunks)
            {
                JsonObject chunkContext = ManagedProtocol.ChunkKeyContext(
                    contextDigest,
                    chunks.Count,
                    ManagedProtocol.Count(chunk!["index"])!.Value,
                    ManagedProtocol.Count(chunk["cipher_size"])!.Value - 28);
                byte[] chunkKey =
                    ManagedProtocol.DeriveChunkKey(objectKey, chunkContext);
                byte[] stored = File.ReadAllBytes(sealedCandidate.CiphertextPath(
                    ManagedProtocol.Text(chunk["cipher_digest"])!)!);
                content.Write(
                    ManagedProtocol.DecryptChunk(chunkKey, stored, chunkContext));
            }
            byte[] plaintext = content.ToArray();
            Check(
                ManagedProtocol.DigestBytes(plaintext) ==
                    ManagedProtocol.Text(descriptor["plain_digest"]),
                "decrypted object digest mismatch");
            recovered[ManagedProtocol.Text(descriptor["object_id"])!] = plaintext;
        }
        return recovered;
    }

    internal static JsonObject OpenSealedManifest(
        SealedManagedCandidate sealedCandidate, byte[] candidateKey)
    {
        JsonObject identity = (JsonObject)sealedCandidate.Request["ciphertext_identity"]!;
        JsonObject manifestObject = (JsonObject)identity["manifest_object"]!;
        JsonObject context = ManagedProtocol.ObjectKeyContext(
            identity,
            ManagedProtocol.Text(manifestObject["object_id"])!,
            "capture-batch-manifest");
        byte[] objectKey = ManagedProtocol.DeriveObjectKey(
            candidateKey, ManagedProtocol.Text(identity["capture_id"])!, context);
        JsonObject chunkContext = ManagedProtocol.ChunkKeyContext(
            ManagedProtocol.CanonicalDigest(context), 1, 0,
            ManagedProtocol.Count(manifestObject["cipher_size"])!.Value - 28);
        byte[] chunkKey = ManagedProtocol.DeriveChunkKey(objectKey, chunkContext);
        byte[] stored = File.ReadAllBytes(sealedCandidate.CiphertextPath(
            ManagedProtocol.Text(manifestObject["cipher_digest"])!)!);
        return (JsonObject)JsonNode.Parse(
            ManagedProtocol.DecryptChunk(chunkKey, stored, chunkContext))!;
    }
}

/// <summary>Records every grant request and answers with a signed grant.</summary>
internal sealed class GrantDeliverySpy : IManagedGrantDelivery
{
    private readonly byte[] candidateKey;
    private readonly string keyReference;

    internal GrantDeliverySpy(byte[]? candidateKey = null, string? keyReference = null)
    {
        this.candidateKey = candidateKey ?? ManagedFixtures.CandidateKey;
        this.keyReference = keyReference ?? ManagedFixtures.KeyReference;
    }

    internal List<JsonObject> Calls { get; } = [];

    public EncryptionResponse RequestEncryptionGrant(JsonObject request, TimeSpan timeout)
    {
        Calls.Add((JsonObject)request.DeepClone());
        return new EncryptionResponse(
            candidateKey,
            ManagedFixtures.SignedCaptureGrant(request, keyReference));
    }
}

/// <summary>An in-memory ingress double that verifies the session order.</summary>
internal sealed class RecordingIngress : IManagedIngressDelivery
{
    private readonly bool failCommit;
    private readonly bool failObjectUploads;
    private JsonObject? request;

    internal RecordingIngress(bool failObjectUploads = false, bool failCommit = false)
    {
        this.failObjectUploads = failObjectUploads;
        this.failCommit = failCommit;
    }

    internal HashSet<string> ExpectedDigests { get; } = [];
    internal List<string> Sequence { get; } = [];
    internal HashSet<string> UploadedDigests { get; } = [];

    public JsonObject Start(JsonObject startRequest, TimeSpan timeout)
    {
        ManagedProtocol.ValidateUploadRequest(startRequest);
        Sequence.Add("start");
        request = (JsonObject)startRequest.DeepClone();
        JsonObject identity = (JsonObject)startRequest["ciphertext_identity"]!;
        ExpectedDigests.Add(
            ManagedProtocol.Text(identity["manifest_object"]!["cipher_digest"])!);
        foreach (JsonNode? entry in (JsonArray)identity["objects"]!)
        {
            foreach (JsonNode? chunk in (JsonArray)entry!["chunks"]!)
            {
                ExpectedDigests.Add(ManagedProtocol.Text(chunk!["cipher_digest"])!);
            }
        }
        JsonArray missing = [];
        foreach (string digest in ExpectedDigests
            .OrderBy(value => value, StringComparer.Ordinal))
        {
            missing.Add(new JsonObject
            {
                ["cipher_digest"] = digest,
                ["expires_at"] = "2026-01-01T00:01:00.000Z",
                ["upload_url"] = $"https://upload.reproit.example/{digest}",
            });
        }
        return new JsonObject
        {
            ["expires_at"] = "2026-01-01T00:01:00.000Z",
            ["limits"] = ManagedFixtures.CloudPositive("managed_candidate_limits"),
            ["missing_objects"] = missing,
            ["next_missing_cursor"] = null,
            ["state"] = "OPEN",
            ["upload_id"] = ManagedFixtures.UploadId,
            ["upload_token"] =
                ManagedProtocol.EncodeBase64Url(ManagedFixtures.Repeat(0x93)),
        };
    }

    public JsonObject Missing(
        string uploadId, string uploadToken, string? cursor, TimeSpan timeout) =>
        throw new InvalidOperationException("one bounded page contains this fixture");

    public void UploadObject(string uploadUrl, string digest, byte[] value, TimeSpan timeout)
    {
        Sequence.Add("upload_object");
        if (failObjectUploads)
        {
            throw ManagedProtocol.SchemaInvalid("the double rejects this object");
        }
        ManagedFixtures.Check(
            ManagedProtocol.DigestBytes(value) == digest &&
            ExpectedDigests.Contains(digest),
            "the double received an unexpected object");
        UploadedDigests.Add(digest);
    }

    public JsonObject Commit(string uploadId, string uploadToken, TimeSpan timeout)
    {
        Sequence.Add("commit");
        if (failCommit)
        {
            throw ManagedProtocol.SchemaInvalid("the double rejects this commit");
        }
        ManagedFixtures.Check(
            ExpectedDigests.SetEquals(UploadedDigests),
            "the double committed before every object arrived");
        JsonObject identity = (JsonObject)request!["ciphertext_identity"]!;
        return new JsonObject
        {
            ["candidate_identity_digest"] =
                identity["candidate_identity_digest"]!.DeepClone(),
            ["candidate_key_reference"] =
                identity["candidate_key_reference"]!.DeepClone(),
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["encrypted_candidate_digest"] =
                request["encrypted_candidate_digest"]!.DeepClone(),
            ["state"] = "CLOUD_PROTECTED",
            ["upload_id"] = uploadId,
        };
    }

    public JsonObject Cancel(string uploadId, string uploadToken, TimeSpan timeout)
    {
        Sequence.Add("cancel");
        return new JsonObject { ["cancelled"] = true };
    }
}
