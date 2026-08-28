using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Holds one packaged content-addressed subject object.</summary>
public sealed record PackagedSubjectObject(string Digest, string Path, long Size);

/// <summary>Holds the frozen subject manifest plus spooled object files.</summary>
public sealed class DotnetSubjectPackage : IDisposable
{
    private readonly string spool;

    internal DotnetSubjectPackage(
        JsonObject manifest,
        List<PackagedSubjectObject> objects,
        string spool,
        string adapterImplementationDigest)
    {
        Manifest = manifest;
        Objects = objects;
        this.spool = spool;
        AdapterImplementationDigest = adapterImplementationDigest;
    }

    internal string AdapterImplementationDigest { get; }

    /// <summary>Gets the validated subject closure manifest.</summary>
    public JsonObject Manifest { get; }

    /// <summary>Gets the content-addressed subject object files.</summary>
    public IReadOnlyList<PackagedSubjectObject> Objects { get; }

    /// <summary>Removes the private subject spool.</summary>
    public void Dispose()
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

/// <summary>Packages the running .NET subject closure for managed capture.</summary>
/// <remarks>
/// Mirrors crates/reproit-sdk-rust/src/subject.rs for the language-neutral
/// manifest shape. The .NET subject closure contains the entry assembly,
/// its portable PDB debug artifact, the runtime identity, loaded
/// dependency-closure facts, and launch data.
/// </remarks>
public static class ManagedSubject
{
    /// <summary>The raw subject file media type.</summary>
    public const string SubjectFileMediaType = "application/vnd.reproit.subject-file.v1";
    /// <summary>The launch data media type.</summary>
    public const string SubjectLaunchMediaType =
        "application/vnd.reproit.subject-launch.v1+json";
    /// <summary>The module identity media type.</summary>
    public const string ModuleIdentityMediaType =
        "application/vnd.reproit.subject-module-identity.v1+json";
    /// <summary>The portable PDB media type.</summary>
    public const string PortablePdbMediaType = "application/vnd.reproit.subject-file.v1";

    internal const int MaxArguments = 128;
    internal const int MaxDependencies = 4_096;
    internal const int MaxEnvironmentNames = 256;
    internal const long MaxSubjectObjectBytes = 512L * 1024 * 1024;
    internal const long MaxSubjectBytes = 2L * 1024 * 1024 * 1024;

    private static readonly HashSet<string> ObjectKinds =
    [
        "application", "debug-artifact", "launch-data", "module-identity",
        "native-dependency", "runtime",
    ];
    private static readonly HashSet<string> RuntimeFamilies =
        ["dotnet", "go", "node", "python", "rust"];

    /// <summary>Freezes and hashes the running .NET subject closure locally.</summary>
    /// <remarks>
    /// A null entry path uses the entry assembly. The entry assembly must
    /// carry an adjacent portable PDB so the captured subject binds its
    /// debug artifact, mirroring the Go port's embedded DWARF requirement.
    /// </remarks>
    public static DotnetSubjectPackage PackageRunningDotnetSubject(
        string? entryAssemblyPath = null)
    {
        string assemblyPath = entryAssemblyPath ??
            Assembly.GetEntryAssembly()?.Location ?? "";
        if (assemblyPath.Length == 0)
        {
            throw SubjectUnsupported();
        }
        assemblyPath = Path.GetFullPath(assemblyPath);
        byte[] assemblyBytes = ReadStableFile(assemblyPath);
        string assemblyDigest = SubjectProtocol.DigestBytes(assemblyBytes);
        string assemblyName = Path.GetFileName(assemblyPath);
        if (assemblyName.Length == 0)
        {
            assemblyName = "application";
        }
        string assemblySubjectPath =
            $"/reproit/subject/application/{DigestName(assemblyDigest)}/{assemblyName}";

        string adapterPath = Path.GetFullPath(typeof(AutomaticProject).Assembly.Location);
        if (adapterPath.Length == 0)
        {
            throw SubjectUnsupported();
        }
        bool adapterIsApplication = string.Equals(
            adapterPath, assemblyPath, StringComparison.Ordinal);
        byte[] adapterBytes = adapterIsApplication
            ? assemblyBytes
            : ReadStableFile(adapterPath);
        string adapterDigest = SubjectProtocol.DigestBytes(adapterBytes);
        string adapterName = Path.GetFileName(adapterPath);
        if (adapterName.Length == 0)
        {
            throw SubjectUnsupported();
        }
        string adapterSubjectPath = adapterIsApplication
            ? assemblySubjectPath
            : $"/reproit/subject/dotnet/modules/{DigestName(adapterDigest)}/{adapterName}";

        string pdbPath = Path.ChangeExtension(assemblyPath, ".pdb");
        if (!File.Exists(pdbPath))
        {
            throw new ManagedCaptureException(
                "UNSUPPORTED",
                "The running .NET subject does not carry its portable PDB artifact.");
        }
        byte[] pdbBytes = ReadStableFile(pdbPath);
        string pdbDigest = SubjectProtocol.DigestBytes(pdbBytes);
        string pdbName = Path.GetFileName(pdbPath);
        string pdbSubjectPath =
            $"/reproit/subject/application/{DigestName(pdbDigest)}/{pdbName}";

        JsonObject runtimeIdentity = RuntimeIdentity();
        byte[] runtimeBytes = CanonicalJson.Bytes(runtimeIdentity);
        string runtimeDigest = SubjectProtocol.DigestBytes(runtimeBytes);
        JsonObject dependencies = DependencyClosure();
        byte[] dependencyBytes = CanonicalJson.Bytes(dependencies);
        string dependencyDigest = SubjectProtocol.DigestBytes(dependencyBytes);

        JsonObject launch = new()
        {
            ["arguments"] = UnicodeArguments(),
            ["environment_names"] = EnvironmentNames(),
            ["executable"] = assemblySubjectPath,
            ["working_directory"] = "/reproit/subject/work",
        };
        byte[] launchBytes = CanonicalJson.Bytes(launch);
        string launchDigest = SubjectProtocol.DigestBytes(launchBytes);

        List<(string Digest, string Kind, string MediaType, long Size)> objectInputs =
        [
            (assemblyDigest, "application", SubjectFileMediaType, assemblyBytes.Length),
            (pdbDigest, "debug-artifact", PortablePdbMediaType, pdbBytes.Length),
            (runtimeDigest, "module-identity", ModuleIdentityMediaType,
                runtimeBytes.Length),
            (dependencyDigest, "module-identity", ModuleIdentityMediaType,
                dependencyBytes.Length),
            (launchDigest, "launch-data", SubjectLaunchMediaType, launchBytes.Length),
        ];
        if (!adapterIsApplication)
        {
            objectInputs.Add(
                (adapterDigest, "native-dependency", SubjectFileMediaType, adapterBytes.Length));
        }
        JsonArray objects = AssembleObjects(objectInputs);
        long totalBytes = objects
            .Sum(entry => SubjectProtocol.Count(entry!["size"])!.Value);
        List<JsonObject> fileInputs =
        [
            new JsonObject
            {
                ["executable"] = true,
                ["object_digest"] = assemblyDigest,
                ["path"] = assemblySubjectPath,
            },
            new JsonObject
            {
                ["executable"] = false,
                ["object_digest"] = pdbDigest,
                ["path"] = pdbSubjectPath,
            },
            new JsonObject
            {
                ["executable"] = false,
                ["object_digest"] = launchDigest,
                ["path"] = "/reproit/subject/launch.json",
            },
            new JsonObject
            {
                ["executable"] = false,
                ["object_digest"] = dependencyDigest,
                ["path"] = "/reproit/subject/dotnet/dependencies.json",
            },
            new JsonObject
            {
                ["executable"] = false,
                ["object_digest"] = runtimeDigest,
                ["path"] = "/reproit/subject/dotnet/runtime.json",
            },
        ];
        if (!adapterIsApplication)
        {
            fileInputs.Add(new JsonObject
            {
                ["executable"] = false,
                ["object_digest"] = adapterDigest,
                ["path"] = adapterSubjectPath,
            });
        }
        JsonArray files = SortedByKey(fileInputs, "path");
        List<JsonObject> moduleInputs =
        [
            new JsonObject
            {
                ["identity"] = assemblyDigest,
                ["module_digest"] = assemblyDigest,
                ["path"] = assemblySubjectPath,
            },
            new JsonObject
            {
                ["identity"] = SubjectProtocol.Text(runtimeIdentity["identity"]),
                ["module_digest"] = runtimeDigest,
                ["path"] = "/reproit/subject/dotnet/runtime.json",
            },
        ];
        if (!adapterIsApplication)
        {
            moduleInputs.Add(new JsonObject
            {
                ["identity"] = adapterDigest,
                ["module_digest"] = adapterDigest,
                ["path"] = adapterSubjectPath,
            });
        }
        JsonArray modules = SortedByKey(moduleInputs, "path");
        JsonArray debugArtifacts =
        [
            new JsonObject
            {
                ["artifact_digest"] = pdbDigest,
                ["kind"] = "portable-pdb",
                ["module_digest"] = assemblyDigest,
                ["path"] = pdbSubjectPath,
            },
        ];
        JsonObject manifest = new()
        {
            ["architecture"] = Architecture(),
            ["debug_artifacts"] = debugArtifacts,
            ["files"] = files,
            ["format"] = "reproit.subject-closure.v1",
            ["launch"] = launch,
            ["modules"] = modules,
            ["objects"] = objects,
            ["operating_system"] = OperatingSystemCapability(),
            ["runtime_family"] = "dotnet",
            ["total_bytes"] = totalBytes,
        };
        ValidateSubjectClosureManifest(manifest);
        string spool = Directory.CreateTempSubdirectory("reproit-dotnet-subject-").FullName;
        Dictionary<string, byte[]> spoolInputs = new()
        {
            [assemblyDigest] = assemblyBytes,
            [pdbDigest] = pdbBytes,
            [runtimeDigest] = runtimeBytes,
            [dependencyDigest] = dependencyBytes,
            [launchDigest] = launchBytes,
        };
        spoolInputs[adapterDigest] = adapterBytes;
        List<PackagedSubjectObject> packaged = SpoolObjects(spool, spoolInputs);
        return new DotnetSubjectPackage(manifest, packaged, spool, adapterDigest);
    }

    /// <summary>Builds the deployment subject descriptor bound to a manifest.</summary>
    public static JsonObject SubjectBinding(JsonObject manifest)
    {
        JsonObject launch = (JsonObject)manifest["launch"]!;
        string manifestDigest = SubjectProtocol.CanonicalDigest(manifest);
        return new JsonObject
        {
            ["architecture"] = manifest["architecture"]!.DeepClone(),
            ["arguments"] = launch["arguments"]!.DeepClone(),
            ["artifact_digest"] = manifestDigest,
            ["artifact_media_type"] = SubjectProtocol.SubjectManifestMediaType,
            ["artifact_uri"] = $"reproit-managed://{manifestDigest}",
            ["environment_names"] = launch["environment_names"]!.DeepClone(),
            ["executable"] = launch["executable"]!.DeepClone(),
            ["format"] = "reproit.subject.v1",
            ["operating_system"] = manifest["operating_system"]!.DeepClone(),
            ["working_directory"] = launch["working_directory"]!.DeepClone(),
        };
    }

    /// <summary>Mirrors reproit-core SubjectClosureManifest::validate.</summary>
    public static void ValidateSubjectClosureManifest(JsonNode? value)
    {
        if (value is not JsonObject manifest || !SubjectProtocol.HasExactly(
            manifest, "architecture", "debug_artifacts", "files", "format", "launch",
            "modules", "objects", "operating_system", "runtime_family", "total_bytes"))
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        if (SubjectProtocol.Text(manifest["format"]) != "reproit.subject-closure.v1" ||
            SubjectProtocol.Text(manifest["runtime_family"]) is not string family ||
            !RuntimeFamilies.Contains(family) ||
            !SubjectProtocol.ValidCapability(manifest["architecture"]) ||
            !SubjectProtocol.ValidCapability(manifest["operating_system"]))
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        if (manifest["objects"] is not JsonArray objects ||
            objects.Count is < 1 or > 32_767 ||
            manifest["files"] is not JsonArray files ||
            files.Count is < 1 or > 32_767 ||
            manifest["modules"] is not JsonArray modules ||
            modules.Count is < 1 or > 4_096 ||
            manifest["debug_artifacts"] is not JsonArray debugArtifacts ||
            debugArtifacts.Count is < 1 or > 4_096)
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        ValidateLaunch(manifest["launch"]);
        Dictionary<string, string> objectKinds =
            ValidateObjects(objects, manifest["total_bytes"]);
        Dictionary<string, string> fileDigests = ValidateFiles(files, objectKinds);
        HashSet<string> moduleDigests =
            ValidateModules(modules, fileDigests, objectKinds);
        ValidateDebugArtifacts(debugArtifacts, fileDigests, objectKinds, moduleDigests);
        JsonObject launch = (JsonObject)manifest["launch"]!;
        string executable = SubjectProtocol.Text(launch["executable"])!;
        if (!files.Any(file =>
            SubjectProtocol.Text(file!["path"]) == executable &&
            file["executable"]?.GetValueKind() == System.Text.Json.JsonValueKind.True))
        {
            throw SubjectProtocol.SchemaInvalid();
        }
    }

    private static void ValidateLaunch(JsonNode? value)
    {
        if (value is not JsonObject launch || !SubjectProtocol.HasExactly(
            launch, "arguments", "environment_names", "executable", "working_directory"))
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        if (launch["arguments"] is not JsonArray arguments ||
            arguments.Count > MaxArguments ||
            arguments.Any(argument => SubjectProtocol.Text(argument) is not string text ||
                text.Length > 4_096) ||
            launch["environment_names"] is not JsonArray names ||
            names.Count > MaxEnvironmentNames ||
            !ValidSubjectPath(SubjectProtocol.Text(launch["executable"])) ||
            !ValidSubjectPath(SubjectProtocol.Text(launch["working_directory"])))
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        string? previous = null;
        foreach (JsonNode? nameNode in names)
        {
            string? name = SubjectProtocol.Text(nameNode);
            if (name is null || name.Length is 0 or > 256 || name.Contains('=') ||
                name.Any(character => character is < '!' or > '~') ||
                (previous is not null && string.CompareOrdinal(previous, name) >= 0))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            previous = name;
        }
    }

    private static Dictionary<string, string> ValidateObjects(
        JsonArray objects, JsonNode? totalBytes)
    {
        Dictionary<string, string> kinds = [];
        long total = 0;
        string? previous = null;
        foreach (JsonNode? entryNode in objects)
        {
            if (entryNode is not JsonObject entry || !SubjectProtocol.HasExactly(
                entry, "digest", "kind", "media_type", "size"))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            long? size = SubjectProtocol.Count(entry["size"]);
            string? mediaType = SubjectProtocol.Text(entry["media_type"]);
            string? kind = SubjectProtocol.Text(entry["kind"]);
            string? digest = SubjectProtocol.Text(entry["digest"]);
            if (size is null or <= 0 or > MaxSubjectObjectBytes ||
                mediaType is null || mediaType.Length is 0 or > 128 ||
                kind is null || !ObjectKinds.Contains(kind) || digest is null ||
                (previous is not null && string.CompareOrdinal(previous, digest) >= 0))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            previous = digest;
            total = checked(total + size.Value);
            if (total > MaxSubjectBytes)
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            kinds[digest] = kind;
        }
        if (SubjectProtocol.Count(totalBytes) != total)
        {
            throw SubjectProtocol.SchemaInvalid();
        }
        return kinds;
    }

    private static Dictionary<string, string> ValidateFiles(
        JsonArray files, Dictionary<string, string> objectKinds)
    {
        Dictionary<string, string> digests = [];
        string? previous = null;
        foreach (JsonNode? entryNode in files)
        {
            if (entryNode is not JsonObject entry || !SubjectProtocol.HasExactly(
                entry, "executable", "object_digest", "path"))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            string? path = SubjectProtocol.Text(entry["path"]);
            string? objectDigest = SubjectProtocol.Text(entry["object_digest"]);
            if (entry["executable"]?.GetValueKind() is not
                    (System.Text.Json.JsonValueKind.True or
                        System.Text.Json.JsonValueKind.False) ||
                !ValidSubjectPath(path) || objectDigest is null ||
                !objectKinds.ContainsKey(objectDigest) ||
                (previous is not null && string.CompareOrdinal(previous, path) >= 0))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            previous = path;
            digests[path!] = objectDigest;
        }
        return digests;
    }

    private static HashSet<string> ValidateModules(
        JsonArray modules,
        Dictionary<string, string> fileDigests,
        Dictionary<string, string> objectKinds)
    {
        HashSet<string> moduleDigests = [];
        string? previous = null;
        foreach (JsonNode? entryNode in modules)
        {
            if (entryNode is not JsonObject entry || !SubjectProtocol.HasExactly(
                entry, "identity", "module_digest", "path"))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            string? identity = SubjectProtocol.Text(entry["identity"]);
            string? path = SubjectProtocol.Text(entry["path"]);
            string? moduleDigest = SubjectProtocol.Text(entry["module_digest"]);
            if (identity is null || identity.Length is 0 or > 512 ||
                !ValidSubjectPath(path) || moduleDigest is null ||
                !fileDigests.TryGetValue(path!, out string? fileDigest) ||
                fileDigest != moduleDigest || !objectKinds.ContainsKey(moduleDigest) ||
                (previous is not null && string.CompareOrdinal(previous, path) >= 0))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            previous = path;
            moduleDigests.Add(moduleDigest);
        }
        return moduleDigests;
    }

    private static void ValidateDebugArtifacts(
        JsonArray debugArtifacts,
        Dictionary<string, string> fileDigests,
        Dictionary<string, string> objectKinds,
        HashSet<string> moduleDigests)
    {
        string? previous = null;
        foreach (JsonNode? entryNode in debugArtifacts)
        {
            if (entryNode is not JsonObject entry || !SubjectProtocol.HasExactly(
                entry, "artifact_digest", "kind", "module_digest", "path"))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            string? kind = SubjectProtocol.Text(entry["kind"]);
            string? artifactDigest = SubjectProtocol.Text(entry["artifact_digest"]);
            string? moduleDigest = SubjectProtocol.Text(entry["module_digest"]);
            string? path = SubjectProtocol.Text(entry["path"]);
            string? artifactKind = artifactDigest is not null &&
                objectKinds.TryGetValue(artifactDigest, out string? found)
                    ? found
                    : null;
            bool validKind = kind switch
            {
                "interpreted-source-identity" => artifactKind is not null,
                "dwarf" when artifactDigest == moduleDigest => artifactKind is not null,
                "dwarf" or "portable-pdb" or "source-map" =>
                    artifactKind == "debug-artifact",
                _ => false,
            };
            if (!ValidSubjectPath(path) || artifactDigest is null ||
                !fileDigests.TryGetValue(path!, out string? fileDigest) ||
                fileDigest != artifactDigest || !validKind ||
                moduleDigest is null || !moduleDigests.Contains(moduleDigest) ||
                (previous is not null && string.CompareOrdinal(previous, path) >= 0))
            {
                throw SubjectProtocol.SchemaInvalid();
            }
            previous = path;
        }
    }

    private static bool ValidSubjectPath(string? path)
    {
        const string Root = "/reproit/subject/";
        if (path is null || !path.StartsWith(Root, StringComparison.Ordinal))
        {
            return false;
        }
        string relative = path[Root.Length..];
        return relative.Length > 0 && path.Length <= 4_096 && !path.Contains('\0') &&
            relative.Split('/').All(part => part.Length > 0 && part is not ("." or ".."));
    }

    private static JsonArray AssembleObjects(
        List<(string Digest, string Kind, string MediaType, long Size)> entries)
    {
        Dictionary<string, JsonObject> merged = [];
        foreach ((string digest, string kind, string mediaType, long size) in entries)
        {
            if (size == 0)
            {
                throw SubjectUnsupported();
            }
            JsonObject candidate = new()
            {
                ["digest"] = digest,
                ["kind"] = kind,
                ["media_type"] = mediaType,
                ["size"] = size,
            };
            if (merged.TryGetValue(digest, out JsonObject? existing) &&
                !CanonicalJson.Bytes(existing).AsSpan()
                    .SequenceEqual(CanonicalJson.Bytes(candidate)))
            {
                throw SubjectUnsupported();
            }
            merged[digest] = candidate;
        }
        JsonArray objects = [];
        foreach (string digest in merged.Keys.OrderBy(key => key, StringComparer.Ordinal))
        {
            objects.Add(merged[digest]);
        }
        return objects;
    }

    private static JsonArray SortedByKey(List<JsonObject> entries, string key)
    {
        JsonArray sorted = [];
        foreach (JsonObject entry in entries
            .OrderBy(entry => SubjectProtocol.Text(entry[key]), StringComparer.Ordinal))
        {
            sorted.Add(entry);
        }
        return sorted;
    }

    private static List<PackagedSubjectObject> SpoolObjects(
        string spoolPath, Dictionary<string, byte[]> contents)
    {
        List<PackagedSubjectObject> packaged = [];
        foreach ((string digest, byte[] value) in contents)
        {
            string path = Path.Combine(spoolPath, DigestName(digest));
            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, value);
            }
            packaged.Add(new PackagedSubjectObject(digest, path, value.Length));
        }
        return packaged;
    }

    /// <summary>Reads a bounded regular file, failing if it changes underneath.</summary>
    public static byte[] ReadStableFile(string path)
    {
        FileInfo before = new(path);
        if (!before.Exists || before.LinkTarget is not null ||
            before.Length == 0 || before.Length > MaxSubjectObjectBytes)
        {
            throw SubjectUnbounded();
        }
        DateTime beforeWrite = before.LastWriteTimeUtc;
        byte[] content;
        try
        {
            content = ReadBounded(path, before.Length);
        }
        catch (ManagedCaptureException)
        {
            throw SubjectChanging();
        }
        FileInfo after = new(path);
        if (!after.Exists || after.Length != before.Length ||
            after.LastWriteTimeUtc != beforeWrite)
        {
            throw SubjectChanging();
        }
        return content;
    }

    private static byte[] ReadBounded(string path, long expectedBytes)
    {
        if (expectedBytes <= 0 || expectedBytes > MaxSubjectObjectBytes)
        {
            throw SubjectUnbounded();
        }
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != expectedBytes)
        {
            throw SubjectChanging();
        }
        byte[] value = new byte[checked((int)expectedBytes)];
        stream.ReadExactly(value);
        if (stream.ReadByte() != -1)
        {
            throw SubjectChanging();
        }
        return value;
    }

    private static JsonObject RuntimeIdentity()
    {
        string version = Environment.Version.ToString();
        string processPath = Environment.ProcessPath ?? "";
        if (processPath.Length == 0)
        {
            throw SubjectUnsupported();
        }
        byte[] executableBytes = ReadStableFile(Path.GetFullPath(processPath));
        return new JsonObject
        {
            ["executable_digest"] = SubjectProtocol.DigestBytes(executableBytes),
            ["executable_size"] = executableBytes.LongLength,
            ["format"] = "reproit.dotnet-runtime-identity.v1",
            ["framework_description"] = RuntimeInformation.FrameworkDescription,
            ["identity"] = $"dotnet-{version}",
            ["version"] = version,
        };
    }

    private static JsonObject DependencyClosure()
    {
        // Record the loaded assembly closure as bounded identity facts.
        Dictionary<(string Name, string Version), JsonObject> unique = [];
        foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            AssemblyName name = assembly.GetName();
            if (name.Name is not string assemblyName || assemblyName.Length == 0)
            {
                throw SubjectUnreadable();
            }
            string version = name.Version?.ToString() ?? "0.0.0.0";
            unique[(assemblyName, version)] = new JsonObject
            {
                ["name"] = assemblyName,
                ["version"] = version,
            };
            if (unique.Count > MaxDependencies)
            {
                throw SubjectUnbounded();
            }
        }
        JsonArray assemblies = [];
        foreach (JsonObject entry in unique
            .OrderBy(pair => pair.Key.Name, StringComparer.Ordinal)
            .ThenBy(pair => pair.Key.Version, StringComparer.Ordinal)
            .Select(pair => pair.Value))
        {
            assemblies.Add(entry);
        }
        return new JsonObject
        {
            ["assemblies"] = assemblies,
            ["format"] = "reproit.dotnet-dependency-closure.v1",
        };
    }

    private static JsonArray UnicodeArguments()
    {
        string[] arguments = Environment.GetCommandLineArgs().Skip(1).ToArray();
        if (arguments.Length > MaxArguments ||
            arguments.Any(argument => argument.Length > 4_096))
        {
            throw SubjectUnsupported();
        }
        JsonArray values = [];
        foreach (string argument in arguments)
        {
            values.Add(argument);
        }
        return values;
    }

    private static JsonArray EnvironmentNames()
    {
        List<string> names = Environment.GetEnvironmentVariables().Keys
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
        if (names.Count > MaxEnvironmentNames)
        {
            throw SubjectUnbounded();
        }
        JsonArray values = [];
        foreach (string name in names)
        {
            if (name.Length is 0 or > 256 || name.Contains('=') ||
                name.Any(character => character is < '!' or > '~'))
            {
                throw SubjectUnsupported();
            }
            values.Add(name);
        }
        return values;
    }

    private static string Architecture() =>
        RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => "architecture.arm64",
            System.Runtime.InteropServices.Architecture.X64 => "architecture.x86-64",
            _ => throw UnsupportedHost(),
        };

    private static string OperatingSystemCapability() =>
        OperatingSystem.IsMacOS()
            ? "operating-system.macos"
            : OperatingSystem.IsLinux()
                ? "operating-system.linux"
                : OperatingSystem.IsWindows()
                    ? "operating-system.windows"
                    : throw UnsupportedHost();

    private static string DigestName(string digest) => digest["sha256:".Length..];

    private static ManagedCaptureException SubjectUnreadable() => new(
        "INCOMPLETE_CANDIDATE",
        "The running .NET subject is not completely readable.");

    private static ManagedCaptureException SubjectChanging() => new(
        "INCOMPLETE_CANDIDATE",
        "The running .NET subject changed during local packaging.");

    private static ManagedCaptureException SubjectUnbounded() => new(
        "UPLOAD_LIMIT_EXCEEDED",
        "The running .NET subject exceeds a Backend v1 bound.");

    private static ManagedCaptureException SubjectUnsupported() => new(
        "UNSUPPORTED",
        "The running .NET subject has an unsupported file or launch identity.");

    private static ManagedCaptureException UnsupportedHost() => new(
        "UNSUPPORTED",
        "This host cannot package a Backend v1 .NET production subject.");
}
