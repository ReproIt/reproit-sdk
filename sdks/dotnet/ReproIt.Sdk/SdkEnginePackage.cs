using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace ReproIt.Sdk;

internal static class SdkEnginePackage
{
    internal const string ArtifactManifestFormat = "reproit.sdk-engine-artifacts.v1";
    internal const string ArtifactManifestName = "sdk-engine-artifacts.json";
    internal const string PackageDirectory = "reproit-sdk-engine";
    internal const string LinuxLibrary = "libreproit_sdk_engine.so";
    internal const string MacOSLibrary = "libreproit_sdk_engine.dylib";
    internal const string WindowsLibrary = "reproit_sdk_engine.dll";
    internal const long MaxLibraryBytes = 256L * 1024 * 1024;
    internal const int MaxManifestBytes = 64 * 1024;

    private static readonly IReadOnlyDictionary<string, Target> Targets =
        new Dictionary<string, Target>(StringComparer.Ordinal)
        {
            ["linux-arm64"] = new("linux-arm64", LinuxLibrary),
            ["linux-x86_64"] = new("linux-x86_64", LinuxLibrary),
            ["macos-arm64"] = new("macos-arm64", MacOSLibrary),
            ["windows-x86_64"] = new("windows-x86_64", WindowsLibrary),
        };

    internal static string LibraryPath()
    {
        string assemblyPath = Assembly.GetExecutingAssembly().Location;
        if (string.IsNullOrEmpty(assemblyPath))
        {
            throw Unavailable();
        }
        FileInfo assembly = new(assemblyPath);
        FileSystemInfo resolved = assembly.ResolveLinkTarget(true) ?? assembly;
        if (!resolved.Exists || resolved is not FileInfo resolvedFile ||
            resolvedFile.DirectoryName is not string root)
        {
            throw Unavailable();
        }
        return LibraryPathAt(root, RuntimeTarget());
    }

    internal static string LibraryPathAt(string root, string targetName)
    {
        if (!Path.IsPathFullyQualified(root) ||
            !Targets.TryGetValue(targetName, out Target? target))
        {
            throw Unavailable();
        }
        string packageDirectory = Path.Combine(root, PackageDirectory);
        string targetDirectory = Path.Combine(packageDirectory, target.Name);
        RequireDirectory(packageDirectory);
        RequireDirectory(targetDirectory);
        string manifestPath = Path.Combine(targetDirectory, ArtifactManifestName);
        byte[] manifest = ReadStableFile(manifestPath, MaxManifestBytes);
        Artifact artifact = ParseManifest(manifest, target);
        string libraryPath = Path.Combine(targetDirectory, artifact.File);
        VerifyLibrary(libraryPath, artifact.Size, artifact.Digest);
        return libraryPath;
    }

    private static Artifact ParseManifest(byte[] value, Target target)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(value);
            JsonElement root = document.RootElement;
            if (!ExactProperties(root, "abi_contract_digest", "artifacts", "format", "target") ||
                root.GetProperty("abi_contract_digest").GetString() !=
                    SdkEngineBridge.AbiContractDigest ||
                root.GetProperty("format").GetString() != ArtifactManifestFormat ||
                root.GetProperty("target").GetString() != target.Name)
            {
                throw Unavailable();
            }
            JsonElement artifacts = root.GetProperty("artifacts");
            if (artifacts.ValueKind != JsonValueKind.Array || artifacts.GetArrayLength() != 1)
            {
                throw Unavailable();
            }
            JsonElement artifact = artifacts[0];
            if (!ExactProperties(artifact, "digest", "file", "role", "size") ||
                artifact.GetProperty("role").GetString() != "engine")
            {
                throw Unavailable();
            }
            string? file = artifact.GetProperty("file").GetString();
            string? digest = artifact.GetProperty("digest").GetString();
            if (file != target.Library || Path.GetFileName(file) != file ||
                file.Contains('/') || file.Contains('\\') || !ValidDigest(digest) ||
                !artifact.GetProperty("size").TryGetInt64(out long size) ||
                size <= 0 || size > MaxLibraryBytes)
            {
                throw Unavailable();
            }
            return new Artifact(digest!, file, size);
        }
        catch (SdkEngineBridgeException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or
            KeyNotFoundException or ArgumentException)
        {
            throw Unavailable();
        }
    }

    private static void VerifyLibrary(string path, long expectedSize, string expectedDigest)
    {
        FileInfo metadata = RequireRegularFile(path, expectedSize);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != expectedSize)
        {
            throw Unavailable();
        }
        byte[] digest = SHA256.HashData(stream);
        metadata.Refresh();
        if (!metadata.Exists || metadata.Length != expectedSize ||
            $"sha256:{Convert.ToHexString(digest).ToLowerInvariant()}" != expectedDigest)
        {
            throw Unavailable();
        }
    }

    private static byte[] ReadStableFile(string path, int maximumBytes)
    {
        FileInfo metadata = RequireRegularFile(path, maximumBytes);
        if (metadata.Length <= 0)
        {
            throw Unavailable();
        }
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != metadata.Length)
        {
            throw Unavailable();
        }
        byte[] value = new byte[checked((int)stream.Length)];
        stream.ReadExactly(value);
        if (stream.ReadByte() != -1)
        {
            throw Unavailable();
        }
        metadata.Refresh();
        if (!metadata.Exists || metadata.Length != value.Length)
        {
            throw Unavailable();
        }
        return value;
    }

    private static FileInfo RequireRegularFile(string path, long maximumBytes)
    {
        FileInfo file = new(path);
        file.Refresh();
        if (!file.Exists || file.LinkTarget is not null ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length <= 0 || file.Length > maximumBytes)
        {
            throw Unavailable();
        }
        return file;
    }

    private static void RequireDirectory(string path)
    {
        DirectoryInfo directory = new(path);
        directory.Refresh();
        if (!directory.Exists || directory.LinkTarget is not null ||
            (directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw Unavailable();
        }
    }

    private static string RuntimeTarget()
    {
        if (OperatingSystem.IsLinux() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            return "linux-arm64";
        }
        if (OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            return "linux-x86_64";
        }
        if (OperatingSystem.IsMacOS() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            return "macos-arm64";
        }
        if (OperatingSystem.IsWindows() &&
            RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            return "windows-x86_64";
        }
        throw Unavailable();
    }

    private static bool ExactProperties(JsonElement value, params string[] expected)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        string[] actual = value.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        return actual.SequenceEqual(expected.Order(StringComparer.Ordinal));
    }

    private static bool ValidDigest(string? value)
    {
        if (value is null || value.Length != 71 ||
            !value.StartsWith("sha256:", StringComparison.Ordinal))
        {
            return false;
        }
        return value.AsSpan(7).IndexOfAnyExcept("0123456789abcdef") < 0;
    }

    private static SdkEngineBridgeException Unavailable() => new(
        "The Repro It SDK engine is unavailable.");

    private sealed record Artifact(string Digest, string File, long Size);
    private sealed record Target(string Name, string Library);
}
