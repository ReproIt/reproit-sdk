using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Stores one protected managed workload identity.</summary>
public sealed class ManagedWorkloadIdentityState
{
    /// <summary>The maximum deployment metadata size.</summary>
    public const int MaxDeploymentMetadataBytes = 256;

    /// <summary>The maximum registration receipt size.</summary>
    public const int MaxRegistrationReceiptBytes = 512;

    private const string DeploymentMetadataFile = "deployment.json";
    private const string RegistrationReceiptFile = "registration.json";
    private const string WorkloadKeyFile = "workload.key";

    private readonly string directory;

    private ManagedWorkloadIdentityState(string directory)
    {
        this.directory = directory;
    }

    /// <summary>Creates protected state for one stable Deployment binding.</summary>
    public static ManagedWorkloadIdentityState FromStateRoot(
        string stateRoot,
        string bindingDigest)
    {
        RequireDigest(bindingDigest);
        EnsureStateRoot(stateRoot);
        string reproit = Path.Combine(stateRoot, "reproit");
        EnsurePrivateDirectory(reproit);
        string workloads = Path.Combine(reproit, "workloads");
        EnsurePrivateDirectory(workloads);
        string directory = Path.Combine(workloads, bindingDigest);
        EnsurePrivateDirectory(directory);
        return new ManagedWorkloadIdentityState(directory);
    }

    /// <summary>Gets the protected Deployment directory.</summary>
    public string DirectoryPath => directory;

    /// <summary>Creates or loads the managed workload signing key.</summary>
    public byte[] LoadOrCreateKey()
    {
        ValidatePrivateDirectory(directory);
        return ManagedIdentity.LoadOrCreateManagedWorkloadKey(
            Path.Combine(directory, WorkloadKeyFile));
    }

    /// <summary>Creates or loads the stable signing time for one Deployment binding.</summary>
    public string LoadOrCreateDeploymentSignedAt(
        string bindingDigest,
        string proposedSignedAt)
    {
        RequireDigest(bindingDigest);
        if (!ManagedProtocol.ValidTimestamp(JsonValue.Create(proposedSignedAt)))
        {
            throw DeploymentMetadataInvalid();
        }
        JsonObject expected = new()
        {
            ["binding_digest"] = bindingDigest,
            ["format"] = 1,
            ["signed_at"] = proposedSignedAt,
        };
        string path = Path.Combine(directory, DeploymentMetadataFile);
        JsonObject? stored = ReadJsonIfPresent(
            path, MaxDeploymentMetadataBytes, DeploymentMetadataInvalid);
        if (stored is not null)
        {
            ValidateDeploymentMetadata(stored);
            if (ManagedProtocol.Text(stored["binding_digest"]) != bindingDigest)
            {
                throw DeploymentMetadataScopeMismatch();
            }
            return ManagedProtocol.Text(stored["signed_at"])!;
        }
        byte[] bytes = CanonicalJson.Bytes(expected);
        if (bytes.Length is 0 or > MaxDeploymentMetadataBytes)
        {
            throw DeploymentMetadataInvalid();
        }
        if (AtomicCreate(path, bytes))
        {
            return proposedSignedAt;
        }
        stored = ReadJson(path, MaxDeploymentMetadataBytes, DeploymentMetadataInvalid);
        ValidateDeploymentMetadata(stored);
        if (ManagedProtocol.Text(stored["binding_digest"]) != bindingDigest)
        {
            throw DeploymentMetadataScopeMismatch();
        }
        return ManagedProtocol.Text(stored["signed_at"])!;
    }

    /// <summary>Loads one exact non-secret registration receipt.</summary>
    public bool HasRegistrationReceipt(ManagedWorkloadRegistrationReceipt expected)
    {
        JsonObject expectedValue = expected.Value();
        ValidateRegistrationReceipt(expectedValue);
        string path = Path.Combine(directory, RegistrationReceiptFile);
        JsonObject? stored = ReadJsonIfPresent(
            path, MaxRegistrationReceiptBytes, RegistrationReceiptInvalid);
        if (stored is null)
        {
            return false;
        }
        ValidateRegistrationReceipt(stored);
        if (!JsonEqual(stored, expectedValue))
        {
            throw RegistrationReceiptScopeMismatch();
        }
        return true;
    }

    /// <summary>Persists one exact non-secret registration receipt.</summary>
    public void PersistRegistrationReceipt(ManagedWorkloadRegistrationReceipt receipt)
    {
        JsonObject value = receipt.Value();
        ValidateRegistrationReceipt(value);
        byte[] bytes = CanonicalJson.Bytes(value);
        if (bytes.Length is 0 or > MaxRegistrationReceiptBytes)
        {
            throw RegistrationReceiptInvalid();
        }
        string path = Path.Combine(directory, RegistrationReceiptFile);
        JsonObject? stored = ReadJsonIfPresent(
            path, MaxRegistrationReceiptBytes, RegistrationReceiptInvalid);
        if (stored is not null)
        {
            ValidateRegistrationReceipt(stored);
            if (!JsonEqual(stored, value))
            {
                throw RegistrationReceiptScopeMismatch();
            }
            return;
        }
        if (AtomicCreate(path, bytes))
        {
            return;
        }
        stored = ReadJson(path, MaxRegistrationReceiptBytes, RegistrationReceiptInvalid);
        ValidateRegistrationReceipt(stored);
        if (!JsonEqual(stored, value))
        {
            throw RegistrationReceiptScopeMismatch();
        }
    }

    private static void ValidateDeploymentMetadata(JsonObject value)
    {
        if (!ManagedProtocol.HasExactly(value, "binding_digest", "format", "signed_at") ||
            !ManagedProtocol.ValidDigest(value["binding_digest"]) ||
            ManagedProtocol.Count(value["format"]) != 1 ||
            !ManagedProtocol.ValidTimestamp(value["signed_at"]))
        {
            throw DeploymentMetadataInvalid();
        }
    }

    private static JsonObject? ReadJsonIfPresent(
        string path,
        int maximumBytes,
        Func<ManagedCaptureException> invalid)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        return ReadJson(path, maximumBytes, invalid);
    }

    private static JsonObject ReadJson(
        string path,
        int maximumBytes,
        Func<ManagedCaptureException> invalid)
    {
        ValidateProtectedFile(path, 1, maximumBytes, invalid);
        byte[] bytes;
        try
        {
            using FileStream input = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            bytes = new byte[input.Length];
            input.ReadExactly(bytes);
            if (input.ReadByte() >= 0)
            {
                throw invalid();
            }
        }
        catch (ManagedCaptureException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw StateUnavailable();
        }
        JsonNode parsed;
        try
        {
            parsed = ManagedProtocol.ParseStrictJson(bytes, maximumBytes);
        }
        catch (ManagedCaptureException)
        {
            throw invalid();
        }
        if (parsed is not JsonObject value ||
            !CanonicalJson.Bytes(value).AsSpan().SequenceEqual(bytes))
        {
            throw invalid();
        }
        return value;
    }

    private static bool AtomicCreate(string path, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw StateInvalid();
        }
        ValidatePrivateDirectory(Path.GetDirectoryName(path) ?? "");
        string name = Path.GetFileName(path);
        string temporary = Path.Combine(
            Path.GetDirectoryName(path)!,
            $".{name}." +
            $"{ManagedProtocol.EncodeBase64Url(RandomNumberGenerator.GetBytes(12))}.pending");
        try
        {
            using (FileStream output = new(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }
            ValidateProtectedFile(temporary, bytes.Length, bytes.Length, StateInvalid);
            try
            {
                File.Move(temporary, path);
                return true;
            }
            catch (IOException) when (File.Exists(path))
            {
                return false;
            }
        }
        catch (ManagedCaptureException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw StateUnavailable();
        }
        finally
        {
            try
            {
                File.Delete(temporary);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // A private pending file has no authority. A later bounded cleanup can remove it.
            }
        }
    }

    private static void EnsureStateRoot(string path)
    {
        if (!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) != path)
        {
            throw StateInvalid();
        }
        string current = Path.GetPathRoot(path)!;
        foreach (string component in path[Path.GetPathRoot(path)!.Length..]
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            if (!Directory.Exists(current))
            {
                try
                {
                    Directory.CreateDirectory(current, UnixFileMode.UserRead |
                        UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                catch (Exception error) when (error is IOException or
                    UnauthorizedAccessException)
                {
                    throw StateUnavailable();
                }
            }
            FileSystemInfo metadata = new DirectoryInfo(current);
            if (!metadata.Exists || metadata.LinkTarget is not null)
            {
                throw StateInvalid();
            }
        }
        DirectoryInfo root = new(path);
        if ((root.UnixFileMode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw StateInvalid();
        }
    }

    private static void EnsurePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw StateInvalid();
        }
        if (!Directory.Exists(path))
        {
            try
            {
                Directory.CreateDirectory(path, UnixFileMode.UserRead |
                    UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                throw StateUnavailable();
            }
        }
        ValidatePrivateDirectory(path);
    }

    private static void ValidatePrivateDirectory(string path)
    {
        DirectoryInfo metadata = new(path);
        UnixFileMode expected = UnixFileMode.UserRead |
            UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (!metadata.Exists || metadata.LinkTarget is not null ||
            metadata.UnixFileMode != expected)
        {
            throw StateInvalid();
        }
    }

    private static void ValidateProtectedFile(
        string path,
        long minimumBytes,
        long maximumBytes,
        Func<ManagedCaptureException> invalid)
    {
        FileInfo metadata = new(path);
        UnixFileMode expected = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (!metadata.Exists || metadata.LinkTarget is not null ||
            metadata.UnixFileMode != expected ||
            metadata.Length < minimumBytes || metadata.Length > maximumBytes)
        {
            throw invalid();
        }
    }

    private static void ValidateRegistrationReceipt(JsonObject value)
    {
        string? keyId = ManagedProtocol.Text(value["workload_key_id"]);
        if (!ManagedProtocol.HasExactly(
                value, "deployment_digest", "service_id", "workload_key_id") ||
            !ManagedProtocol.ValidDigest(value["deployment_digest"]) ||
            !ManagedProtocol.ValidTypedId(value["service_id"], "service_id") ||
            keyId is null ||
            !keyId.StartsWith("managed-workload-sha256:", StringComparison.Ordinal) ||
            !ManagedProtocol.ValidDigest(JsonValue.Create(
                keyId["managed-workload-".Length..])))
        {
            throw RegistrationReceiptInvalid();
        }
    }

    private static bool JsonEqual(JsonNode left, JsonNode right) =>
        CanonicalJson.Bytes(left).AsSpan().SequenceEqual(CanonicalJson.Bytes(right));

    private static void RequireDigest(string value)
    {
        if (!ManagedProtocol.ValidDigest(JsonValue.Create(value)))
        {
            throw StateInvalid();
        }
    }

    private static ManagedCaptureException StateInvalid() => new(
        "CONFIG_CONFLICT", "The managed workload state directory is not private or valid.");

    private static ManagedCaptureException StateUnavailable() => new(
        "SERVICE_UNAVAILABLE", "The managed workload state directory is unavailable.");

    private static ManagedCaptureException DeploymentMetadataInvalid() => new(
        "CONFIG_CONFLICT", "The managed Deployment metadata is corrupt or invalid.");

    private static ManagedCaptureException DeploymentMetadataScopeMismatch() => new(
        "CONFIG_CONFLICT", "The managed Deployment metadata belongs to another build binding.");

    private static ManagedCaptureException RegistrationReceiptInvalid() => new(
        "CONFIG_CONFLICT", "The managed workload registration receipt is corrupt or invalid.");

    private static ManagedCaptureException RegistrationReceiptScopeMismatch() => new(
        "CONFIG_CONFLICT",
        "The managed workload registration receipt belongs to another Deployment.");
}

/// <summary>Identifies one exact managed workload registration.</summary>
public sealed record ManagedWorkloadRegistrationReceipt(
    string DeploymentDigest,
    string ServiceId,
    string WorkloadKeyId)
{
    internal JsonObject Value()
    {
        JsonObject value = new()
        {
            ["deployment_digest"] = DeploymentDigest,
            ["service_id"] = ServiceId,
            ["workload_key_id"] = WorkloadKeyId,
        };
        return value;
    }
}

/// <summary>Manages one protected local Ed25519 managed workload key file.</summary>
public static class ManagedIdentity
{
    /// <summary>The managed workload signing key size in bytes.</summary>
    public const int WorkloadKeyBytes = 32;

    private const UnixFileMode GroupOtherWrite =
        UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
    private const UnixFileMode GroupOtherAll =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <summary>Creates or loads the 32-byte managed workload signing key.</summary>
    public static byte[] LoadOrCreateManagedWorkloadKey(string path)
    {
        string parent = Path.GetDirectoryName(path) ?? "";
        if (parent.Length == 0)
        {
            throw KeyStoreInvalid();
        }
        ValidateParent(parent);
        FileStream descriptor;
        try
        {
            if (!OperatingSystem.IsLinux())
            {
                throw KeyStoreUnavailable();
            }
            descriptor = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
        }
        catch (IOException) when (File.Exists(path))
        {
            return ReadKey(path, parent);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw KeyStoreUnavailable();
        }
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(WorkloadKeyBytes);
            try
            {
                descriptor.Write(key);
                descriptor.Flush(flushToDisk: true);
            }
            catch (IOException)
            {
                throw KeyStoreUnavailable();
            }
            ValidateFile(path);
            return key;
        }
        finally
        {
            descriptor.Dispose();
        }
    }

    private static byte[] ReadKey(string path, string parent)
    {
        ValidateParent(parent);
        ValidateFile(path);
        byte[] key = new byte[WorkloadKeyBytes];
        try
        {
            using FileStream source = File.OpenRead(path);
            int read = source.ReadAtLeast(key, WorkloadKeyBytes, throwOnEndOfStream: false);
            if (read != WorkloadKeyBytes || source.ReadByte() >= 0)
            {
                throw KeyStoreInvalid();
            }
        }
        catch (ManagedCaptureException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw KeyStoreUnavailable();
        }
        return key;
    }

    private static void ValidateParent(string parent)
    {
        DirectoryInfo metadata = new(parent);
        if (!metadata.Exists || metadata.LinkTarget is not null ||
            (metadata.UnixFileMode & GroupOtherWrite) != 0)
        {
            throw KeyStoreInvalid();
        }
    }

    private static void ValidateFile(string path)
    {
        FileInfo metadata = new(path);
        if (!metadata.Exists || metadata.LinkTarget is not null ||
            metadata.Length != WorkloadKeyBytes ||
            (metadata.UnixFileMode & GroupOtherAll) != 0)
        {
            throw KeyStoreInvalid();
        }
    }

    private static ManagedCaptureException KeyStoreInvalid() => new(
        "CONFIG_CONFLICT", "The managed workload key file is not private or valid.");

    private static ManagedCaptureException KeyStoreUnavailable() => new(
        "SERVICE_UNAVAILABLE", "The managed workload key file is unavailable.");
}
