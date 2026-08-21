using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Describes one frozen capture artifact in the static closure.</summary>
public sealed record ManagedCandidateArtifact(
    string MediaType,
    string ObjectId,
    string Path,
    string Role,
    string Uri);

/// <summary>Holds the static capture closure the application proves before upload.</summary>
public sealed record ManagedCaptureClosure(
    IReadOnlyList<ManagedCandidateArtifact> Artifacts,
    string Completion,
    JsonObject World);

/// <summary>Freezes a capture closure's artifact bytes into a private spool.</summary>
/// <remarks>
/// Mirrors the closure half of crates/reproit-sdk-rust/src/managed.rs: the
/// world checkpoint shape the SDK consumes, the static artifact set proof,
/// dependency-transcript validation, and freezing artifact bytes so they
/// cannot change between proof and upload.
/// </remarks>
public sealed class FrozenManagedCaptureClosure : IDisposable
{
    private readonly string? spool;

    /// <summary>Validates and freezes one static capture closure.</summary>
    public FrozenManagedCaptureClosure(ManagedCaptureClosure closure)
    {
        ManagedClosure.ValidateWorldCheckpoint(closure.World);
        ManagedClosure.ValidateStaticArtifactSet(closure.World, closure.Artifacts);
        List<ManagedCandidateArtifact> artifacts = [.. closure.Artifacts];
        if (artifacts.Count > 0)
        {
            spool = Directory.CreateTempSubdirectory("reproit-managed-world-").FullName;
            artifacts = closure.Artifacts
                .Select(artifact => ManagedClosure.FreezeArtifact(artifact, spool))
                .ToList();
        }
        ManagedClosure.ValidateStaticArtifactSet(closure.World, artifacts);
        Closure = new ManagedCaptureClosure(artifacts, closure.Completion, closure.World);
    }

    /// <summary>Gets the frozen capture closure.</summary>
    public ManagedCaptureClosure Closure { get; }

    /// <summary>Returns the world identity digest of the frozen closure.</summary>
    public string WorldId()
    {
        ManagedClosure.ValidateWorldCheckpoint(Closure.World);
        return ManagedProtocol.CanonicalDigest(Closure.World);
    }

    /// <summary>Removes the private artifact spool.</summary>
    public void Dispose()
    {
        if (spool is not null)
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
        }
    }
}

/// <summary>Validates and freezes the static managed capture closure.</summary>
public static class ManagedClosure
{
    /// <summary>The per-artifact byte bound.</summary>
    public const long MaxCaptureArtifactBytes = 274_878_824_448;
    /// <summary>The canonical world manifest byte bound.</summary>
    public const int MaxWorldManifestBytes = 262_144;
    internal const int CopyBufferBytes = 64 * 1024;

    private static readonly HashSet<string> ArtifactRoles =
        ["dependency-transcript", "world-state"];

    /// <summary>Validates the bounded world checkpoint shape the SDK consumes.</summary>
    public static void ValidateWorldCheckpoint(JsonNode? value)
    {
        if (value is not JsonObject world ||
            !ManagedProtocol.HasExactly(world, "created_at", "format", "points") ||
            ManagedProtocol.Text(world["format"]) != "reproit.world-checkpoint.v1" ||
            !ManagedProtocol.ValidTimestamp(world["created_at"]) ||
            world["points"] is not JsonArray points || points.Count > 64)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        HashSet<string> providers = [];
        foreach (JsonNode? pointNode in points)
        {
            if (pointNode is not JsonObject point ||
                ManagedProtocol.Text(point["format"]) != "reproit.recoverable-point.v1" ||
                ManagedProtocol.Text(point["provider_id"]) is not string providerId ||
                point["artifacts"] is not JsonArray artifacts ||
                artifacts.Count > 32_767 || !providers.Add(providerId))
            {
                throw ManagedProtocol.SchemaInvalid();
            }
            foreach (JsonNode? artifactNode in artifacts)
            {
                if (artifactNode is not JsonObject artifact ||
                    !ManagedProtocol.ValidDigest(artifact["digest"]) ||
                    ManagedProtocol.Count(artifact["size"]) is null or < 0 ||
                    ManagedProtocol.Text(artifact["uri"]) is not string uri ||
                    uri.Length is 0 or > 2_048 ||
                    ManagedProtocol.Text(artifact["media_type"]) is null)
                {
                    throw ManagedProtocol.SchemaInvalid();
                }
            }
        }
        if (CanonicalJson.Bytes(world).Length > MaxWorldManifestBytes)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
    }

    /// <summary>Returns the artifact identity tuples a world checkpoint declares.</summary>
    public static HashSet<(string Uri, string Digest, long Size, string MediaType)>
        ExpectedWorldArtifacts(JsonObject world)
    {
        HashSet<(string, string, long, string)> expected = [];
        foreach (JsonNode? point in (JsonArray)world["points"]!)
        {
            foreach (JsonNode? artifact in (JsonArray)point!["artifacts"]!)
            {
                expected.Add((
                    ManagedProtocol.Text(artifact!["uri"])!,
                    ManagedProtocol.Text(artifact["digest"])!,
                    ManagedProtocol.Count(artifact["size"])!.Value,
                    ManagedProtocol.Text(artifact["media_type"])!));
            }
        }
        return expected;
    }

    /// <summary>Proves the supplied artifacts exactly cover the declared world.</summary>
    public static void ValidateStaticArtifactSet(
        JsonObject world, IReadOnlyList<ManagedCandidateArtifact> artifacts)
    {
        if (artifacts.Count > 32_767)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        HashSet<(string Uri, string Digest, long Size, string MediaType)> expectedWorld =
            ExpectedWorldArtifacts(world);
        HashSet<string> suppliedWorld = artifacts
            .Where(artifact => artifact.Role == "world-state")
            .Select(artifact => artifact.Uri)
            .ToHashSet();
        if (expectedWorld.Count != suppliedWorld.Count ||
            expectedWorld.Any(entry => !suppliedWorld.Contains(entry.Uri)))
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        HashSet<string> objectIds = [];
        HashSet<string> uris = [];
        foreach (ManagedCandidateArtifact artifact in artifacts)
        {
            if (!ArtifactRoles.Contains(artifact.Role) ||
                artifact.Uri.Length is 0 or > 2_048 ||
                artifact.MediaType.Length is 0 or > 256 ||
                !objectIds.Add(artifact.ObjectId) || !uris.Add(artifact.Uri))
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            (long size, string digest) = HashFile(artifact.Path);
            if (artifact.Role == "world-state" && !expectedWorld.Contains(
                (artifact.Uri, digest, size, artifact.MediaType)))
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            if (artifact.Role == "dependency-transcript" &&
                artifact.MediaType == ManagedProtocol.DependencyTranscriptMediaType)
            {
                if (size > ManagedProtocol.MaxChunkBytes)
                {
                    throw ManagedProtocol.IncompleteCandidate();
                }
                ValidateTranscriptBytes(ReadBounded(artifact.Path, size));
            }
        }
    }

    /// <summary>Mirrors the DependencyTranscript strict parse and validation.</summary>
    public static JsonObject ValidateTranscriptBytes(byte[] value)
    {
        JsonNode parsedNode =
            ManagedProtocol.ParseStrictJson(value, ManagedProtocol.MaxChunkBytes);
        if (parsedNode is not JsonObject parsed ||
            !CanonicalJson.Bytes(parsed).AsSpan().SequenceEqual(value) ||
            !ManagedProtocol.HasExactly(
                parsed, "adapter_id", "adapter_version", "format", "interactions") ||
            ManagedProtocol.Text(parsed["format"]) != "reproit.dependency-transcript.v1")
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        string? adapterId = ManagedProtocol.Text(parsed["adapter_id"]);
        string? adapterVersion = ManagedProtocol.Text(parsed["adapter_version"]);
        if (adapterId is null || adapterId.Length is 0 or > 128 ||
            adapterVersion is null || adapterVersion.Length is 0 or > 64 ||
            parsed["interactions"] is not JsonArray interactions ||
            interactions.Count is < 1 or > 1_024)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        for (int index = 0; index < interactions.Count; index += 1)
        {
            ValidateInteraction(interactions[index], index);
        }
        return parsed;
    }

    private static void ValidateInteraction(JsonNode? value, int index)
    {
        if (value is not JsonObject interaction || !ManagedProtocol.HasExactly(
            interaction, "causal_parent_id", "operation_id", "outcome",
            "request_digest", "request_object_id", "response_digest",
            "response_object_id", "sequence", "session_position"))
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        long? sessionPosition = ManagedProtocol.Count(interaction["session_position"]);
        if (ManagedProtocol.Count(interaction["sequence"]) != index ||
            !ManagedProtocol.ValidTypedId(interaction["operation_id"], "operation_id") ||
            !(interaction["causal_parent_id"] is null || ManagedProtocol.ValidTypedId(
                interaction["causal_parent_id"], "operation_id")) ||
            !ManagedProtocol.ValidDigest(interaction["request_digest"]) ||
            !ManagedProtocol.ValidDigest(interaction["response_digest"]) ||
            !ManagedProtocol.ValidTypedId(interaction["request_object_id"], "object_id") ||
            !ManagedProtocol.ValidTypedId(interaction["response_object_id"], "object_id") ||
            sessionPosition is null or < 0 or > 9_007_199_254_740_991)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
    }

    internal static ManagedCandidateArtifact FreezeArtifact(
        ManagedCandidateArtifact artifact, string spoolPath)
    {
        long expectedSize = ArtifactLength(artifact.Path);
        string temporary = Path.Combine(
            spoolPath, $"artifact-{ManagedProtocol.NewObjectId()}");
        (string firstDigest, long copied) =
            CopyAndDigest(artifact.Path, temporary, expectedSize);
        (string secondDigest, long verified) = DigestFile(artifact.Path, expectedSize);
        if (firstDigest != secondDigest || copied != verified)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        string frozenPath = Path.Combine(spoolPath, firstDigest["sha256:".Length..]);
        if (File.Exists(frozenPath))
        {
            (string storedDigest, long storedSize) = DigestFile(frozenPath, copied);
            if (storedDigest != firstDigest || storedSize != copied)
            {
                throw ManagedProtocol.ObjectDigestMismatch();
            }
            File.Delete(temporary);
        }
        else
        {
            File.Move(temporary, frozenPath);
        }
        return artifact with { Path = frozenPath };
    }

    internal static long ArtifactLength(string path)
    {
        FileInfo metadata = new(path);
        if (!metadata.Exists || metadata.LinkTarget is not null ||
            metadata.Length == 0 || metadata.Length > MaxCaptureArtifactBytes)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        return metadata.Length;
    }

    private static (string Digest, long Size) CopyAndDigest(
        string source, string target, long expected)
    {
        try
        {
            using IncrementalHash hasher =
                IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using FileStream reader = File.OpenRead(source);
            using FileStream writer = new(target, FileMode.CreateNew, FileAccess.Write);
            long total = CopyBounded(reader, writer, hasher, expected);
            writer.Flush();
            return (FinishDigest(hasher), total);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new ManagedCaptureException(
                "SERVICE_UNAVAILABLE",
                "Repro It could not create the bounded local ciphertext staging area.");
        }
    }

    private static (string Digest, long Size) DigestFile(string path, long expected)
    {
        try
        {
            using IncrementalHash hasher =
                IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using FileStream reader = File.OpenRead(path);
            long total = CopyBounded(reader, null, hasher, expected);
            return (FinishDigest(hasher), total);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
    }

    private static long CopyBounded(
        FileStream reader, FileStream? writer, IncrementalHash hasher, long expected)
    {
        byte[] buffer = new byte[CopyBufferBytes];
        long total = 0;
        while (true)
        {
            int read = reader.Read(buffer);
            if (read == 0)
            {
                break;
            }
            total += read;
            if (total > expected)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
            hasher.AppendData(buffer.AsSpan(0, read));
            writer?.Write(buffer.AsSpan(0, read));
        }
        if (total != expected)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        return total;
    }

    private static string FinishDigest(IncrementalHash hasher) =>
        $"sha256:{Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant()}";

    /// <summary>Reads one bounded regular file completely or fails closed.</summary>
    public static byte[] ReadBounded(string path, long expected)
    {
        if (expected is < 0 or > int.MaxValue)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        byte[] value = new byte[expected];
        try
        {
            using FileStream source = File.OpenRead(path);
            int read = source.ReadAtLeast(value, (int)expected, throwOnEndOfStream: false);
            if (read != expected || source.ReadByte() >= 0)
            {
                throw ManagedProtocol.IncompleteCandidate();
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        return value;
    }

    /// <summary>Hashes a stable regular file, failing closed if it changes.</summary>
    public static (long Size, string Digest) HashFile(string path)
    {
        FileInfo before = new(path);
        long expectedSize = ArtifactLength(path);
        DateTime beforeWrite = before.LastWriteTimeUtc;
        (string digest, long size) = DigestFile(path, expectedSize);
        FileInfo after = new(path);
        if (!after.Exists || after.LinkTarget is not null ||
            after.Length != size || after.LastWriteTimeUtc != beforeWrite)
        {
            throw ManagedProtocol.IncompleteCandidate();
        }
        return (size, digest);
    }
}
