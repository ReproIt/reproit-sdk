using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Reports a managed capture step failure with a stable protocol code.</summary>
public sealed class ManagedCaptureException : Exception
{
    /// <summary>Creates one managed failure with a stable protocol error code.</summary>
    public ManagedCaptureException(string code, string message, bool? retryable = null)
        : base(message)
    {
        Code = code;
        Retryable = retryable ?? ManagedProtocol.RetryableCodes.Contains(code);
    }

    /// <summary>Gets the stable protocol error code.</summary>
    public string Code { get; }

    /// <summary>Gets whether the failed step is retryable.</summary>
    public bool Retryable { get; }
}

/// <summary>Mirrors the reproit-core managed-mode protocol primitives.</summary>
/// <remarks>
/// The Rust implementation in crates/reproit-core is normative. Every rule
/// here has a direct counterpart there, and the cross-language vectors in
/// specs/v1 pin the byte-level behavior.
/// </remarks>
public static class ManagedProtocol
{
    /// <summary>The per-chunk plaintext byte bound.</summary>
    public const int MaxChunkBytes = 8 * 1024 * 1024;
    /// <summary>The per-candidate logical object bound.</summary>
    public const int MaxCandidateObjects = 32_767;
    /// <summary>The candidate record plaintext byte bound.</summary>
    public const int MaxCandidatePlaintextBytes = 1_048_576;
    /// <summary>The candidate record ciphertext byte bound.</summary>
    public const int MaxCandidateCiphertextBytes = 1_048_604;
    /// <summary>The total candidate ciphertext byte bound.</summary>
    public const long MaxTotalCandidateCiphertextBytes = 274_878_824_448;

    /// <summary>The managed candidate cipher suite identifier.</summary>
    public const string CipherSuite = "AES-256-GCM+HKDF-SHA-256";
    /// <summary>The signed capture grant format.</summary>
    public const string CaptureGrantFormat = "reproit.managed-candidate-capture-grant.v1";
    /// <summary>The candidate identity format.</summary>
    public const string CandidateIdentityFormat = "reproit.managed-candidate-identity.v1";
    /// <summary>The sealed candidate manifest format.</summary>
    public const string CandidateManifestFormat = "reproit.managed-candidate-manifest.v1";
    /// <summary>The ciphertext identity format.</summary>
    public const string CiphertextIdentityFormat =
        "reproit.managed-candidate-ciphertext-identity.v1";
    /// <summary>The per-object key derivation context format.</summary>
    public const string ObjectKeyContextFormat = "reproit.object-key-context.v1";
    /// <summary>The per-chunk key derivation context format.</summary>
    public const string ChunkKeyContextFormat = "reproit.chunk-key-context.v1";
    /// <summary>The capture batch format bound into every object context.</summary>
    public const string CaptureBatchFormat = "reproit.capture-batch.v1";

    /// <summary>The candidate record media type.</summary>
    public const string CandidateMediaType = "application/vnd.reproit.candidate.v1+json";
    /// <summary>The failure record media type.</summary>
    public const string FailureMediaType = "application/vnd.reproit.failure.v1+json";
    /// <summary>The subject closure manifest media type.</summary>
    public const string SubjectManifestMediaType =
        "application/vnd.reproit.subject-closure.v1+json";
    /// <summary>The trigger record media type.</summary>
    public const string TriggerMediaType = "application/vnd.reproit.trigger.v1+json";
    /// <summary>The world manifest media type.</summary>
    public const string WorldManifestMediaType =
        "application/vnd.reproit.world-manifest.v1+json";
    /// <summary>The dependency transcript media type.</summary>
    public const string DependencyTranscriptMediaType =
        "application/vnd.reproit.dependency-transcript.v1+json";

    private static readonly string[] RequiredRoles =
        ["candidate", "failure", "subject", "trigger", "world-manifest"];
    private static readonly (string Role, string MediaType)[] RoleMediaTypes =
    [
        ("candidate", CandidateMediaType),
        ("failure", FailureMediaType),
        ("subject", SubjectManifestMediaType),
        ("trigger", TriggerMediaType),
        ("world-manifest", WorldManifestMediaType),
    ];
    private static readonly HashSet<string> LogicalObjectRoles =
    [
        "admission-proof", "candidate", "debug-symbols", "dependency-transcript",
        "failure", "replay-capsule-manifest", "subject", "trigger",
        "world-manifest", "world-state",
    ];

    // Wire values of reproit_core::ErrorCode. The transport rejects a
    // server error whose code is not in this closed set.
    internal static readonly HashSet<string> ErrorCodes =
    [
        "ADMISSION_PROOF_BINDING", "ADMISSION_PROOF_COUNT", "ASSIGNEE_NOT_AUTHORIZED",
        "ARTIFACT_NOT_FOUND", "ATTESTATION_REVOKED", "ATTESTATION_SCOPE",
        "AUTHENTICATION_REQUIRED", "AUTHORIZATION_DENIED", "CAPTURE_ID_CONFLICT",
        "CONFIG_CONFLICT", "CROSS_TENANT_SCOPE", "DECRYPTION_AUTHENTICATION",
        "DEPENDENCY_TRANSCRIPT_MISMATCH", "DIFFERENT_FAILURE", "EVALUATION_ERROR",
        "FORBIDDEN", "INCOMPLETE_CANDIDATE", "INCOMPLETE_RECORD_SEQUENCE",
        "LIVE_EGRESS_BLOCKED", "KEY_PROVIDER_UNAVAILABLE", "KEY_UNWRAP_FAILED",
        "KEEP_DESTINATION_UNAVAILABLE", "LEGAL_DELETION_CONFLICT", "NONCE_REUSE",
        "NOT_FOUND", "OBJECT_DIGEST_MISMATCH", "PRIORITY_INVALID", "RATE_LIMITED",
        "RUNTIME_QUOTA", "SCHEMA_INVALID", "SERVICE_UNAVAILABLE",
        "SOURCE_ACCESS_DENIED", "SOURCE_CHECKOUT_FAILED", "SOURCE_DEPENDENCY_MISSING",
        "SOURCE_REVISION_MISSING", "STATE_SCOPE_VIOLATION", "SUBJECT_DIGEST_MISMATCH",
        "TRIAGE_CONFLICT", "UNSUPPORTED", "UNSUPPORTED_CAPABILITY_SET",
        "UPLOAD_EXPIRED", "UPLOAD_INCOMPLETE", "UPLOAD_LIMIT_EXCEEDED",
        "WORLD_NOT_CLOSED", "WORLD_POINT_EXPIRED", "WORLD_PROVIDER_MISSING",
    ];

    internal static readonly HashSet<string> RetryableCodes =
    [
        "KEY_PROVIDER_UNAVAILABLE", "KEEP_DESTINATION_UNAVAILABLE", "RATE_LIMITED",
        "RUNTIME_QUOTA", "SERVICE_UNAVAILABLE", "SOURCE_CHECKOUT_FAILED",
        "UPLOAD_EXPIRED", "UPLOAD_INCOMPLETE",
    ];

    private static readonly Dictionary<string, string> IdPrefixes = new()
    {
        ["capture_id"] = "cap_",
        ["object_id"] = "obj_",
        ["operation_id"] = "op_",
        ["organization_id"] = "org_",
        ["project_id"] = "prj_",
        ["service_id"] = "svc_",
        ["upload_id"] = "upl_",
    };

    /// <summary>Creates one SCHEMA_INVALID managed failure.</summary>
    public static ManagedCaptureException SchemaInvalid(
        string message = "The value does not satisfy the schema.") =>
        new("SCHEMA_INVALID", message);

    /// <summary>Creates one INCOMPLETE_CANDIDATE managed failure.</summary>
    public static ManagedCaptureException IncompleteCandidate() => new(
        "INCOMPLETE_CANDIDATE",
        "The managed candidate is incomplete and cannot be uploaded.");

    /// <summary>Creates one ATTESTATION_SCOPE managed failure.</summary>
    public static ManagedCaptureException AttestationError() =>
        new("ATTESTATION_SCOPE", "The signature is invalid for this attestation.");

    /// <summary>Creates one OBJECT_DIGEST_MISMATCH managed failure.</summary>
    public static ManagedCaptureException ObjectDigestMismatch() => new(
        "OBJECT_DIGEST_MISMATCH", "The object bytes do not match the bound digest.");

    /// <summary>Encodes bytes as unpadded base64url.</summary>
    public static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decodes strict unpadded base64url and rejects non-canonical text.</summary>
    public static byte[] DecodeBase64Url(string? value, int? expectedLength = null)
    {
        if (value is null || value.Contains('='))
        {
            throw SchemaInvalid();
        }
        foreach (char character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))
            {
                throw SchemaInvalid();
            }
        }
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            throw SchemaInvalid();
        }
        if (EncodeBase64Url(decoded) != value ||
            (expectedLength is int length && decoded.Length != length))
        {
            throw SchemaInvalid();
        }
        return decoded;
    }

    /// <summary>Computes the sha256:&lt;hex&gt; digest of bytes.</summary>
    public static string DigestBytes(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    /// <summary>Computes the digest of one value's canonical bytes.</summary>
    public static string CanonicalDigest(JsonNode value) =>
        DigestBytes(CanonicalJson.Bytes(value));

    /// <summary>Reports whether a value is a well-formed sha256 digest.</summary>
    public static bool ValidDigest(JsonNode? value) =>
        Text(value) is string digest && ValidDigestText(digest);

    /// <summary>Reports whether a string is a well-formed sha256 digest.</summary>
    public static bool ValidDigestText(string value) =>
        value.Length == 71 && value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value.AsSpan(7).IndexOfAnyExcept("0123456789abcdef") < 0;

    /// <summary>Reports whether a value is a valid typed identifier.</summary>
    public static bool ValidTypedId(JsonNode? value, string kind) =>
        Text(value) is string text &&
        CandidateProtocol.ValidPrefixedUuid7(text, IdPrefixes[kind]);

    /// <summary>Requires and returns one valid typed identifier.</summary>
    public static string RequireTypedId(JsonNode? value, string kind) =>
        ValidTypedId(value, kind) ? Text(value)! : throw SchemaInvalid();

    /// <summary>Requires and returns one valid typed identifier string.</summary>
    public static string RequireTypedIdText(string value, string kind) =>
        CandidateProtocol.ValidPrefixedUuid7(value, IdPrefixes[kind])
            ? value
            : throw SchemaInvalid();

    /// <summary>Returns the 16 UUID bytes of a typed identifier.</summary>
    public static byte[] IdUuidBytes(string value, string kind)
    {
        string uuid = RequireTypedIdText(value, kind)[IdPrefixes[kind].Length..];
        return Convert.FromHexString(uuid.Replace("-", ""));
    }

    /// <summary>Creates one fresh obj_ UUIDv7 identifier.</summary>
    public static string NewObjectId()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(16);
        long milliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        for (int index = 0; index < 6; index += 1)
        {
            bytes[index] = (byte)(milliseconds >> (8 * (5 - index)));
        }
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x70);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        string hex = Convert.ToHexString(bytes).ToLowerInvariant();
        return $"obj_{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    /// <summary>Reports whether a value is a 43-character opaque key reference.</summary>
    public static bool ValidOpaqueReference(JsonNode? value)
    {
        if (Text(value) is not string text || text.Length != 43)
        {
            return false;
        }
        try
        {
            DecodeBase64Url(text, 32);
            return true;
        }
        catch (ManagedCaptureException)
        {
            return false;
        }
    }

    /// <summary>Reports whether a value is a canonical millisecond UTC timestamp.</summary>
    public static bool ValidTimestamp(JsonNode? value) =>
        Text(value) is string text && ValidTimestampText(text);

    /// <summary>Reports whether a string is a canonical millisecond UTC timestamp.</summary>
    public static bool ValidTimestampText(string value) =>
        value.Length == 24 && value.EndsWith('Z') && DateTime.TryParseExact(
            value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out _);

    /// <summary>Parses one canonical timestamp or fails closed.</summary>
    public static DateTime ParseTimestamp(JsonNode? value) =>
        Text(value) is string text ? ParseTimestampText(text) : throw SchemaInvalid();

    /// <summary>Parses one canonical timestamp string or fails closed.</summary>
    public static DateTime ParseTimestampText(string value) =>
        ValidTimestampText(value)
            ? DateTime.ParseExact(
                value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
            : throw SchemaInvalid();

    /// <summary>Returns the current time as a canonical timestamp.</summary>
    public static string NowTimestamp() => DateTime.UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>Reports whether a value matches the canonical capability shape.</summary>
    public static bool ValidCapability(JsonNode? value) =>
        Text(value) is string text && ValidCapabilityText(text);

    /// <summary>Reports whether a string matches ^[a-z][a-z0-9.-]*$ up to 128.</summary>
    public static bool ValidCapabilityText(string value) =>
        value.Length is > 0 and <= 128 && value[0] is >= 'a' and <= 'z' &&
        value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');

    /// <summary>Validates one sorted bounded capability list.</summary>
    public static void ValidateCapabilities(JsonNode? values)
    {
        if (values is not JsonArray list || list.Count > 64)
        {
            throw SchemaInvalid();
        }
        string? previous = null;
        foreach (JsonNode? entry in list)
        {
            if (!ValidCapability(entry) ||
                (previous is not null &&
                    string.CompareOrdinal(previous, Text(entry)) >= 0))
            {
                throw SchemaInvalid();
            }
            previous = Text(entry);
        }
    }

    /// <summary>Signs bytes with a 32-byte Ed25519 seed as unpadded base64url.</summary>
    public static string SignBytes(ReadOnlySpan<byte> value, ReadOnlySpan<byte> signingKey)
    {
        if (signingKey.Length != 32)
        {
            throw SchemaInvalid();
        }
        return EncodeBase64Url(ManagedEd25519.Sign(value, signingKey));
    }

    /// <summary>Returns the 32-byte verification key of an Ed25519 seed.</summary>
    public static byte[] VerificationKey(ReadOnlySpan<byte> signingKey)
    {
        if (signingKey.Length != 32)
        {
            throw SchemaInvalid();
        }
        return ManagedEd25519.PublicKey(signingKey);
    }

    /// <summary>Returns the canonical identity of an Ed25519 verification key.</summary>
    public static string WorkloadKeyId(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32)
        {
            throw SchemaInvalid();
        }
        string encoded = EncodeBase64Url(publicKey);
        return $"managed-workload-{DigestBytes(Encoding.ASCII.GetBytes(encoded))}";
    }

    /// <summary>Verifies the detached Ed25519 signature in the signature field.</summary>
    public static void VerifySignedValue(JsonObject value, ReadOnlySpan<byte> publicKey)
    {
        if (Text(value["signature"]) is not string signatureText)
        {
            throw SchemaInvalid();
        }
        byte[] signature = DecodeBase64Url(signatureText, 64);
        JsonObject unsigned = (JsonObject)value.DeepClone();
        unsigned["signature"] = "";
        if (publicKey.Length != 32 ||
            !ManagedEd25519.Verify(CanonicalJson.Bytes(unsigned), signature, publicKey))
        {
            throw AttestationError();
        }
    }

    /// <summary>Builds the canonical per-object key derivation context.</summary>
    public static JsonObject ObjectKeyContext(
        JsonObject identity, string objectId, string role) => new()
        {
            ["capture_batch_format"] = CaptureBatchFormat,
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["format"] = ObjectKeyContextFormat,
            ["object_id"] = objectId,
            ["organization_id"] = identity["organization_id"]!.DeepClone(),
            ["processing_mode"] = "managed",
            ["project_id"] = identity["project_id"]!.DeepClone(),
            ["role"] = role,
            ["service_id"] = identity["service_id"]!.DeepClone(),
        };

    /// <summary>Builds the canonical per-chunk key derivation context.</summary>
    public static JsonObject ChunkKeyContext(
        string objectContextDigest, long chunkCount, long chunkIndex, long plainSize) => new()
        {
            ["chunk_count"] = chunkCount,
            ["chunk_index"] = chunkIndex,
            ["format"] = ChunkKeyContextFormat,
            ["object_context_digest"] = objectContextDigest,
            ["plain_size"] = plainSize,
        };

    private static byte[] HkdfExtract(byte[] salt, byte[] inputKeyMaterial) =>
        HMACSHA256.HashData(salt, inputKeyMaterial);

    private static byte[] HkdfExpand32(byte[] pseudoRandomKey, byte[] info)
    {
        // One SHA-256 block covers the full 32-byte output.
        byte[] block = new byte[info.Length + 1];
        info.CopyTo(block, 0);
        block[^1] = 0x01;
        return HMACSHA256.HashData(pseudoRandomKey, block);
    }

    /// <summary>Derives one object key with the capture UUID salt.</summary>
    public static byte[] DeriveObjectKey(
        byte[] candidateKey, string captureId, JsonObject objectContext)
    {
        if (candidateKey.Length != 32 || Text(objectContext["capture_id"]) != captureId)
        {
            throw SchemaInvalid();
        }
        byte[] salt = IdUuidBytes(captureId, "capture_id");
        return HkdfExpand32(
            HkdfExtract(salt, candidateKey), CanonicalJson.Bytes(objectContext));
    }

    /// <summary>Derives one chunk key from an object key and chunk context.</summary>
    public static byte[] DeriveChunkKey(byte[] objectKey, JsonObject context)
    {
        if (objectKey.Length != 32)
        {
            throw SchemaInvalid();
        }
        return HkdfExpand32(objectKey, CanonicalJson.Bytes(context));
    }

    /// <summary>Encrypts one chunk with the canonical context as associated data.</summary>
    public static byte[] EncryptChunk(
        byte[] chunkKey, byte[] nonce, ReadOnlySpan<byte> plaintext, JsonObject context)
    {
        if (chunkKey.Length != 32 || nonce.Length != 12 ||
            plaintext.Length > MaxChunkBytes ||
            Count(context["plain_size"]) != plaintext.Length)
        {
            throw SchemaInvalid();
        }
        byte[] associatedData = CanonicalJson.Bytes(context);
        byte[] stored = new byte[12 + plaintext.Length + 16];
        nonce.CopyTo(stored, 0);
        using AesGcm cipher = new(chunkKey, 16);
        cipher.Encrypt(
            nonce, plaintext, stored.AsSpan(12, plaintext.Length),
            stored.AsSpan(12 + plaintext.Length, 16), associatedData);
        return stored;
    }

    /// <summary>Decrypts one stored chunk or fails with DECRYPTION_AUTHENTICATION.</summary>
    public static byte[] DecryptChunk(byte[] chunkKey, byte[] stored, JsonObject context)
    {
        long? plainSize = Count(context["plain_size"]);
        if (chunkKey.Length != 32 || stored.Length is < 28 or > MaxChunkBytes + 28 ||
            plainSize is null || plainSize + 28 != stored.Length)
        {
            throw DecryptionFailed();
        }
        byte[] associatedData = CanonicalJson.Bytes(context);
        byte[] plaintext = new byte[stored.Length - 28];
        try
        {
            using AesGcm cipher = new(chunkKey, 16);
            cipher.Decrypt(
                stored.AsSpan(0, 12), stored.AsSpan(12, plaintext.Length),
                stored.AsSpan(12 + plaintext.Length, 16), plaintext, associatedData);
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            throw DecryptionFailed();
        }
        return plaintext;

        static ManagedCaptureException DecryptionFailed() => new(
            "DECRYPTION_AUTHENTICATION", "Ciphertext authentication failed.");
    }

    /// <summary>Validates one logical candidate object descriptor.</summary>
    public static void ValidateLogicalObject(JsonNode? value)
    {
        if (value is not JsonObject descriptor || !HasExactly(
            descriptor, "media_type", "object_id", "plain_digest", "plain_size", "role"))
        {
            throw SchemaInvalid();
        }
        string? mediaType = Text(descriptor["media_type"]);
        long? plainSize = Count(descriptor["plain_size"]);
        if (mediaType is null || mediaType.Length is 0 or > 128 ||
            !ValidTypedId(descriptor["object_id"], "object_id") ||
            !ValidDigest(descriptor["plain_digest"]) ||
            plainSize is null or < 0 or > MaxTotalCandidateCiphertextBytes ||
            Text(descriptor["role"]) is not string role ||
            !LogicalObjectRoles.Contains(role))
        {
            throw SchemaInvalid();
        }
    }

    private static JsonObject RequireOneManifest(
        List<JsonObject> descriptors, string role, string mediaType)
    {
        List<JsonObject> matches = descriptors
            .Where(value => Text(value["role"]) == role &&
                Text(value["media_type"]) == mediaType)
            .ToList();
        if (matches.Count != 1)
        {
            throw SchemaInvalid();
        }
        return matches[0];
    }

    /// <summary>Mirrors reproit-core ManagedCandidateIdentity::validate exactly.</summary>
    public static void ValidateManagedCandidateIdentity(JsonNode? value)
    {
        if (value is not JsonObject identity || !HasExactly(
            identity, "candidate_digest", "capture_id", "deployment_digest", "format",
            "objects", "organization_id", "processing_mode", "project_id",
            "required_capabilities", "service_id", "subject_digest",
            "total_plaintext_bytes"))
        {
            throw SchemaInvalid();
        }
        if (Text(identity["format"]) != CandidateIdentityFormat ||
            Text(identity["processing_mode"]) != "managed" ||
            !ValidDigest(identity["candidate_digest"]) ||
            !ValidDigest(identity["deployment_digest"]) ||
            !ValidDigest(identity["subject_digest"]) ||
            !ValidTypedId(identity["capture_id"], "capture_id") ||
            !ValidTypedId(identity["organization_id"], "organization_id") ||
            !ValidTypedId(identity["project_id"], "project_id") ||
            !ValidTypedId(identity["service_id"], "service_id") ||
            identity["objects"] is not JsonArray objects ||
            objects.Count is < 5 or > MaxCandidateObjects)
        {
            throw SchemaInvalid();
        }
        ValidateCapabilities(identity["required_capabilities"]);
        long totalPlaintextBytes = 0;
        HashSet<string> roles = [];
        List<JsonObject> descriptors = [];
        string? previousObjectId = null;
        foreach (JsonNode? entry in objects)
        {
            ValidateLogicalObject(entry);
            JsonObject descriptor = (JsonObject)entry!;
            string objectId = Text(descriptor["object_id"])!;
            if (previousObjectId is not null &&
                string.CompareOrdinal(previousObjectId, objectId) >= 0)
            {
                throw SchemaInvalid();
            }
            previousObjectId = objectId;
            roles.Add(Text(descriptor["role"])!);
            totalPlaintextBytes += Count(descriptor["plain_size"])!.Value;
            descriptors.Add(descriptor);
        }
        if (RequiredRoles.Any(role => !roles.Contains(role)))
        {
            throw SchemaInvalid();
        }
        foreach ((string role, string mediaType) in RoleMediaTypes)
        {
            RequireOneManifest(descriptors, role, mediaType);
        }
        JsonObject candidate = RequireOneManifest(
            descriptors, "candidate", CandidateMediaType);
        JsonObject subject = RequireOneManifest(
            descriptors, "subject", SubjectManifestMediaType);
        if (Text(candidate["plain_digest"]) != Text(identity["candidate_digest"]) ||
            Count(candidate["plain_size"]) > MaxCandidatePlaintextBytes ||
            Text(subject["plain_digest"]) != Text(identity["subject_digest"]) ||
            Count(identity["total_plaintext_bytes"]) != totalPlaintextBytes ||
            totalPlaintextBytes > MaxTotalCandidateCiphertextBytes)
        {
            throw SchemaInvalid();
        }
    }

    private static void ValidateChunk(JsonNode? value)
    {
        if (value is not JsonObject chunk ||
            !HasExactly(chunk, "cipher_digest", "cipher_size", "index", "nonce"))
        {
            throw SchemaInvalid();
        }
        long? cipherSize = Count(chunk["cipher_size"]);
        string? nonce = Text(chunk["nonce"]);
        if (!ValidDigest(chunk["cipher_digest"]) ||
            cipherSize is null or < 28 or > MaxChunkBytes + 28 ||
            Count(chunk["index"]) is null || nonce is null || nonce.Length != 16)
        {
            throw SchemaInvalid();
        }
        DecodeBase64Url(nonce, 12);
    }

    private static void ValidateManifestObject(JsonNode? value)
    {
        if (value is not JsonObject manifest ||
            !HasExactly(manifest, "cipher_digest", "cipher_size", "nonce", "object_id"))
        {
            throw SchemaInvalid();
        }
        long? cipherSize = Count(manifest["cipher_size"]);
        string? nonce = Text(manifest["nonce"]);
        if (!ValidDigest(manifest["cipher_digest"]) ||
            cipherSize is null or < 28 or > MaxChunkBytes + 28 ||
            nonce is null || nonce.Length != 16 ||
            !ValidTypedId(manifest["object_id"], "object_id"))
        {
            throw SchemaInvalid();
        }
        DecodeBase64Url(nonce, 12);
    }

    /// <summary>Mirrors ManagedCandidateCiphertextIdentity::validate exactly.</summary>
    public static void ValidateCiphertextIdentity(JsonNode? value)
    {
        if (value is not JsonObject identity || !HasExactly(
            identity, "candidate_identity_digest", "candidate_key_reference",
            "capture_id", "cipher_suite", "format", "manifest_object", "objects",
            "organization_id", "processing_mode", "project_id",
            "required_capabilities", "service_id", "total_ciphertext_bytes"))
        {
            throw SchemaInvalid();
        }
        if (Text(identity["format"]) != CiphertextIdentityFormat ||
            Text(identity["cipher_suite"]) != CipherSuite ||
            Text(identity["processing_mode"]) != "managed" ||
            !ValidOpaqueReference(identity["candidate_key_reference"]) ||
            !ValidDigest(identity["candidate_identity_digest"]) ||
            !ValidTypedId(identity["capture_id"], "capture_id") ||
            !ValidTypedId(identity["organization_id"], "organization_id") ||
            !ValidTypedId(identity["project_id"], "project_id") ||
            !ValidTypedId(identity["service_id"], "service_id") ||
            identity["objects"] is not JsonArray objects ||
            objects.Count is < 5 or > MaxCandidateObjects ||
            identity["required_capabilities"] is not JsonArray capabilities ||
            capabilities.Count == 0)
        {
            throw SchemaInvalid();
        }
        ValidateCapabilities(identity["required_capabilities"]);
        ValidateManifestObject(identity["manifest_object"]);
        JsonObject manifestObject = (JsonObject)identity["manifest_object"]!;
        HashSet<string> nonces = [Text(manifestObject["nonce"])!];
        long chunkCount = 1;
        long totalCiphertextBytes = Count(manifestObject["cipher_size"])!.Value;
        HashSet<string> roles = [];
        List<JsonObject> descriptors = [];
        long candidateCiphertextBytes = 0;
        int candidateEntries = 0;
        string? previousObjectId = null;
        foreach (JsonNode? entryNode in objects)
        {
            if (entryNode is not JsonObject entry ||
                !HasExactly(entry, "chunks", "descriptor"))
            {
                throw SchemaInvalid();
            }
            ValidateLogicalObject(entry["descriptor"]);
            JsonObject descriptor = (JsonObject)entry["descriptor"]!;
            descriptors.Add(descriptor);
            string objectId = Text(descriptor["object_id"])!;
            if (previousObjectId is not null &&
                string.CompareOrdinal(previousObjectId, objectId) >= 0)
            {
                throw SchemaInvalid();
            }
            previousObjectId = objectId;
            if (entry["chunks"] is not JsonArray chunks ||
                chunks.Count is < 1 or > MaxCandidateObjects)
            {
                throw SchemaInvalid();
            }
            roles.Add(Text(descriptor["role"])!);
            chunkCount += chunks.Count;
            long entryCiphertextBytes = 0;
            for (int chunkIndex = 0; chunkIndex < chunks.Count; chunkIndex += 1)
            {
                ValidateChunk(chunks[chunkIndex]);
                JsonObject chunk = (JsonObject)chunks[chunkIndex]!;
                if (Count(chunk["index"]) != chunkIndex ||
                    !nonces.Add(Text(chunk["nonce"])!))
                {
                    throw SchemaInvalid();
                }
                long cipherSize = Count(chunk["cipher_size"])!.Value;
                totalCiphertextBytes += cipherSize;
                entryCiphertextBytes += cipherSize;
            }
            if (Text(descriptor["role"]) == "candidate" &&
                Text(descriptor["media_type"]) == CandidateMediaType)
            {
                candidateEntries += 1;
                candidateCiphertextBytes = entryCiphertextBytes;
            }
        }
        if (RequiredRoles.Any(role => !roles.Contains(role)))
        {
            throw SchemaInvalid();
        }
        foreach ((string role, string mediaType) in RoleMediaTypes)
        {
            RequireOneManifest(descriptors, role, mediaType);
        }
        if (candidateEntries != 1 || chunkCount > 32_768 ||
            Count(identity["total_ciphertext_bytes"]) != totalCiphertextBytes ||
            totalCiphertextBytes > MaxTotalCandidateCiphertextBytes ||
            candidateCiphertextBytes > MaxCandidateCiphertextBytes ||
            descriptors.Any(descriptor =>
                Text(descriptor["object_id"]) == Text(manifestObject["object_id"])))
        {
            throw SchemaInvalid();
        }
    }

    /// <summary>Mirrors ManagedCandidateCaptureGrant::validate exactly.</summary>
    public static void ValidateCaptureGrant(JsonNode? value)
    {
        if (value is not JsonObject grant || !HasExactly(
            grant, "candidate_identity_digest", "candidate_key_reference", "capture_id",
            "cipher_suite", "expires_at", "format", "grant_id", "not_before",
            "operation", "organization_id", "processing_mode", "project_id",
            "service_id", "signature", "signer_key_id"))
        {
            throw SchemaInvalid();
        }
        string? signerKeyId = Text(grant["signer_key_id"]);
        string? signature = Text(grant["signature"]);
        if (Text(grant["format"]) != CaptureGrantFormat ||
            Text(grant["cipher_suite"]) != CipherSuite ||
            Text(grant["operation"]) != "encrypt-and-upload-candidate" ||
            Text(grant["processing_mode"]) != "managed" ||
            !ValidOpaqueReference(grant["candidate_key_reference"]) ||
            !ValidOpaqueReference(grant["grant_id"]) ||
            !ValidDigest(grant["candidate_identity_digest"]) ||
            !ValidTypedId(grant["capture_id"], "capture_id") ||
            !ValidTypedId(grant["organization_id"], "organization_id") ||
            !ValidTypedId(grant["project_id"], "project_id") ||
            !ValidTypedId(grant["service_id"], "service_id") ||
            signerKeyId is null || signerKeyId.Length is 0 or > 256 ||
            signature is null || signature.Length != 86 ||
            ParseTimestamp(grant["not_before"]) >= ParseTimestamp(grant["expires_at"]))
        {
            throw SchemaInvalid();
        }
        DecodeBase64Url(signature, 64);
    }

    /// <summary>Mirrors verify_managed_candidate_capture_grant exactly.</summary>
    public static void VerifyCaptureGrant(
        JsonNode? grant, JsonObject expected, string now, byte[] publicKey)
    {
        ValidateCaptureGrant(grant);
        JsonObject value = (JsonObject)grant!;
        DateTime currentTime = ParseTimestampText(now);
        if (Text(value["candidate_identity_digest"]) !=
                Text(expected["candidate_identity_digest"]) ||
            Text(value["candidate_key_reference"]) !=
                Text(expected["candidate_key_reference"]) ||
            Text(value["capture_id"]) != Text(expected["capture_id"]) ||
            Text(value["organization_id"]) != Text(expected["organization_id"]) ||
            Text(value["project_id"]) != Text(expected["project_id"]) ||
            Text(value["service_id"]) != Text(expected["service_id"]) ||
            Text(value["signer_key_id"]) != Text(expected["signer_key_id"]) ||
            currentTime < ParseTimestamp(value["not_before"]) ||
            currentTime >= ParseTimestamp(value["expires_at"]))
        {
            throw new ManagedCaptureException(
                "ATTESTATION_SCOPE",
                "The managed candidate capture grant does not match this capture.");
        }
        VerifySignedValue(value, publicKey);
    }

    /// <summary>Mirrors ManagedCandidateUploadRequest::validate exactly.</summary>
    public static void ValidateUploadRequest(JsonNode? value)
    {
        if (value is not JsonObject request || !HasExactly(
            request, "capture_grant", "ciphertext_identity",
            "encrypted_candidate_digest"))
        {
            throw SchemaInvalid();
        }
        ValidateCaptureGrant(request["capture_grant"]);
        ValidateCiphertextIdentity(request["ciphertext_identity"]);
        JsonObject grant = (JsonObject)request["capture_grant"]!;
        JsonObject identity = (JsonObject)request["ciphertext_identity"]!;
        if (Text(grant["candidate_identity_digest"]) !=
                Text(identity["candidate_identity_digest"]) ||
            Text(grant["candidate_key_reference"]) !=
                Text(identity["candidate_key_reference"]) ||
            Text(grant["capture_id"]) != Text(identity["capture_id"]) ||
            Text(grant["organization_id"]) != Text(identity["organization_id"]) ||
            Text(grant["project_id"]) != Text(identity["project_id"]) ||
            Text(grant["service_id"]) != Text(identity["service_id"]) ||
            Text(grant["processing_mode"]) != Text(identity["processing_mode"]) ||
            Text(grant["cipher_suite"]) != Text(identity["cipher_suite"]))
        {
            throw new ManagedCaptureException(
                "ATTESTATION_SCOPE",
                "The capture grant does not cover this ciphertext identity.");
        }
        if (CanonicalDigest(identity) != Text(request["encrypted_candidate_digest"]))
        {
            throw ObjectDigestMismatch();
        }
    }

    /// <summary>Parses bounded strict protocol JSON.</summary>
    /// <remarks>
    /// Duplicate object keys, non-finite numbers, non-integer numbers, and
    /// trailing data are rejected. Protocol JSON carries integers only, so
    /// rejecting fractional numbers at the parse boundary fails closed
    /// exactly where the reference validators would reject the value.
    /// </remarks>
    public static JsonNode ParseStrictJson(ReadOnlySpan<byte> value, int maximumBytes)
    {
        if (value.Length > maximumBytes)
        {
            throw SchemaInvalid();
        }
        try
        {
            Utf8JsonReader reader = new(value, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });
            if (!reader.Read())
            {
                throw SchemaInvalid();
            }
            JsonNode? root = ReadStrictNode(ref reader);
            if (reader.Read())
            {
                throw SchemaInvalid();
            }
            return root ?? throw SchemaInvalid();
        }
        catch (JsonException)
        {
            throw SchemaInvalid();
        }
    }

    private static JsonNode? ReadStrictNode(ref Utf8JsonReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.StartObject:
                JsonObject item = [];
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    if (reader.TokenType != JsonTokenType.PropertyName)
                    {
                        throw SchemaInvalid();
                    }
                    string name = reader.GetString() ?? throw SchemaInvalid();
                    if (item.ContainsKey(name) || !reader.Read())
                    {
                        throw SchemaInvalid();
                    }
                    item[name] = ReadStrictNode(ref reader);
                }
                if (reader.TokenType != JsonTokenType.EndObject)
                {
                    throw SchemaInvalid();
                }
                return item;
            case JsonTokenType.StartArray:
                JsonArray items = [];
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    items.Add(ReadStrictNode(ref reader));
                }
                if (reader.TokenType != JsonTokenType.EndArray)
                {
                    throw SchemaInvalid();
                }
                return items;
            case JsonTokenType.String:
                return JsonValue.Create(reader.GetString())!;
            case JsonTokenType.Number:
                if (!reader.TryGetInt64(out long number))
                {
                    throw SchemaInvalid();
                }
                // A parse-backed node converts to any fitting integer type,
                // matching nodes produced by JsonNode.Parse elsewhere.
                return JsonNode.Parse(
                    number.ToString(CultureInfo.InvariantCulture))!;
            case JsonTokenType.True:
                return JsonValue.Create(true);
            case JsonTokenType.False:
                return JsonValue.Create(false);
            case JsonTokenType.Null:
                // An explicit null member is stored as a null-valued entry.
                // The exact-keys checks still see the member as present.
                return null;
            default:
                throw SchemaInvalid();
        }
    }

    /// <summary>Reports whether an object has exactly the named members.</summary>
    public static bool HasExactly(JsonObject value, params string[] keys) =>
        value.Count == keys.Length && keys.All(value.ContainsKey);

    /// <summary>Returns a value's text when it is a JSON string.</summary>
    public static string? Text(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    /// <summary>Returns a value's integer when it is a JSON integer.</summary>
    public static long? Count(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.Number &&
        long.TryParse(
            value.ToJsonString(), NumberStyles.AllowLeadingSign,
            CultureInfo.InvariantCulture, out long number)
            ? number
            : null;
}

/// <summary>Rejects any nonce reuse within one sealed candidate.</summary>
public sealed class NonceRegistry
{
    private readonly HashSet<string> used = [];

    /// <summary>Registers one 12-byte nonce or fails with NONCE_REUSE.</summary>
    public void Register(byte[] nonce)
    {
        if (nonce.Length != 12 || !used.Add(Convert.ToHexString(nonce)))
        {
            throw new ManagedCaptureException(
                "NONCE_REUSE", "An occurrence cannot reuse an encryption nonce.");
        }
    }
}
