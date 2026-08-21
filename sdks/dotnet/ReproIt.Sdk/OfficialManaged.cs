using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Holds the immutable managed release bindings.</summary>
public sealed record OfficialManagedConfiguration(
    string ManagedOrigin,
    string CaptureSignerId,
    byte[] CaptureSignerPublicKey);

/// <summary>Binds one reviewed project to an installed SDK package.</summary>
public sealed class OfficialManagedProject
{
    private readonly JsonObject project;
    private readonly string sourceRevision;

    /// <summary>Validates the release and exact reviewed build binding.</summary>
    public OfficialManagedProject(
        JsonObject project, string buildRepositoryId, string sourceRevision)
    {
        _ = OfficialManaged.Configuration();
        ValidateProject(project, buildRepositoryId, sourceRevision);
        this.project = (JsonObject)project.DeepClone();
        this.sourceRevision = sourceRevision;
    }

    /// <summary>Creates one package-owned operation without network work.</summary>
    public OfficialManagedOperation StartOperation(string worldId)
    {
        if (!ManagedProtocol.ValidDigest(worldId))
        {
            throw ProjectBindingInvalid();
        }
        return new OfficialManagedOperation(
            $"cap_{Guid.CreateVersion7()}",
            $"op_{Guid.CreateVersion7()}",
            worldId,
            Deployment(project, sourceRevision));
    }

    private static void ValidateProject(
        JsonObject project, string buildRepositoryId, string sourceRevision)
    {
        string servicePath = ManagedProtocol.Text(project["service_path"]) ?? "";
        if (project["format"]?.GetValue<int>() != 1 ||
            ManagedProtocol.Text(project["profile"]) != "backend" ||
            project["profile_format"]?.GetValue<int>() != 1 ||
            ManagedProtocol.Text(project["processing_mode"]) != "managed" ||
            ManagedProtocol.Text(project["sdk"]) != "dotnet" ||
            ManagedProtocol.Text(project["repository_id"]) != buildRepositoryId ||
            !ValidRevision(sourceRevision) || servicePath.Length == 0 ||
            servicePath.StartsWith('/') || servicePath.Split('/').Contains(".."))
        {
            throw ProjectBindingInvalid();
        }
        foreach (string name in new[] { "organization_id", "project_id", "service_id" })
        {
            ManagedProtocol.RequireTypedIdText(
                ManagedProtocol.Text(project[name]) ?? "", name);
        }
    }

    private static bool ValidRevision(string value) =>
        value.Length is 40 or 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static JsonObject Deployment(JsonObject project, string sourceRevision) => new()
    {
        ["format"] = "reproit.deployment.v1",
        ["organization_id"] = project["organization_id"]!.DeepClone(),
        ["processing_mode"] = "managed",
        ["project_id"] = project["project_id"]!.DeepClone(),
        ["repository_id"] = project["repository_id"]!.DeepClone(),
        ["runtime_capabilities"] = new JsonArray("runtime.dotnet-native"),
        ["runtime_endpoint"] = "pending-official-managed-origin",
        ["service_id"] = project["service_id"]!.DeepClone(),
        ["service_path"] = project["service_path"]!.DeepClone(),
        ["signature"] = new string('A', 86),
        ["signed_at"] = "1970-01-01T00:00:00.000Z",
        ["signer_key_id"] = "pending-managed-registration",
        ["source_revision"] = sourceRevision,
        ["subject"] = new JsonObject(),
    };

    private static ManagedCaptureException ProjectBindingInvalid() => new(
        "CONFIG_CONFLICT", "The managed project build binding is invalid.");
}

/// <summary>Owns one managed operation identity and deployment.</summary>
public sealed class OfficialManagedOperation(
    string captureId, string operationId, string worldId, JsonObject deployment)
{
    /// <summary>Gets the package-owned capture ID.</summary>
    public string CaptureId { get; } = captureId;
    /// <summary>Gets the package-owned operation ID.</summary>
    public string OperationId { get; } = operationId;
    /// <summary>Gets the captured World ID.</summary>
    public string WorldId { get; } = worldId;
    /// <summary>Gets the deployment bound by the official sink.</summary>
    public JsonObject Deployment { get; private set; } = deployment;

    /// <summary>Binds one complete closure to the installed official package.</summary>
    public ManagedCandidateSink CandidateSink(
        FrozenManagedCaptureClosure closure,
        Func<ManagedProjectToken> projectTokenProvider,
        DotnetSubjectPackage? subject = null)
    {
        (ManagedCandidateSink sink, JsonObject bound) = OfficialManaged.CandidateSinkBound(
            closure, Deployment, projectTokenProvider, subject, OperationId);
        Deployment = bound;
        return sink;
    }
}

/// <summary>Loads the managed bindings that release construction installs.</summary>
public static class OfficialManaged
{
    private const string ManagedOrigin =
        "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__";
    private const string CaptureSignerId =
        "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__";
    private const string CaptureSignerPublicKey =
        "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__";

    private static readonly HashSet<string> FixtureSignerKeys =
    [
        "1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA",
        "Pm6nrLpZVoxfNqy0GBb7FqsrJ6sTq9OLCSTKJpGtZZk",
        "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI",
        "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY",
        "p_bfr484uJuozmSbWU-R5NAf3Ff5yUk99DteUKmYc2c",
    ];

    /// <summary>Returns the validated immutable managed release bindings.</summary>
    public static OfficialManagedConfiguration Configuration()
    {
        if (IsSentinel(ManagedOrigin) || IsSentinel(CaptureSignerId) ||
            IsSentinel(CaptureSignerPublicKey))
        {
            throw new ManagedCaptureException(
                "CONFIG_CONFLICT",
                "This Repro It SDK has no official managed release binding.");
        }
        if (!ValidOfficialOrigin(ManagedOrigin, out Uri? origin))
        {
            throw ReleaseBindingInvalid();
        }
        string loweredSignerId = CaptureSignerId.ToLowerInvariant();
        if (CaptureSignerId.Length is 0 or > 256 ||
            !char.IsAsciiLetterOrDigit(CaptureSignerId[0]) ||
            CaptureSignerId.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not
                    ('.' or '_' or ':' or '-')) ||
            new[] { "example", "fixture", "placeholder", "replace-me" }
                .Any(loweredSignerId.Contains) ||
            loweredSignerId is "test" or "testing" or "changeme")
        {
            throw ReleaseBindingInvalid();
        }
        byte[] signerKey;
        try
        {
            signerKey = ManagedProtocol.DecodeBase64Url(CaptureSignerPublicKey, 32);
        }
        catch (ManagedCaptureException)
        {
            throw ReleaseBindingInvalid();
        }
        if (signerKey.All(value => value == 0) ||
            FixtureSignerKeys.Contains(CaptureSignerPublicKey))
        {
            throw ReleaseBindingInvalid();
        }
        return new OfficialManagedConfiguration(
            ManagedOrigin, CaptureSignerId, signerKey);
    }

    /// <summary>Creates the official managed Cloud client.</summary>
    public static ManagedTlsClient Client()
    {
        OfficialManagedConfiguration configuration = Configuration();
        ManagedTlsEndpoint endpoint = new(configuration.ManagedOrigin);
        return new ManagedTlsClient(endpoint, endpoint);
    }

    /// <summary>Creates the released framework-neutral managed candidate sink.</summary>
    public static ManagedCandidateSink CandidateSink(
        ManagedCaptureClosure captureClosure,
        JsonObject deployment,
        Func<ManagedProjectToken> projectTokenProvider,
        DotnetSubjectPackage? subject = null,
        string? operationId = null)
    {
        return CandidateSink(
            new FrozenManagedCaptureClosure(captureClosure), deployment,
            projectTokenProvider, subject, operationId);
    }

    /// <summary>Creates the released framework-neutral managed candidate sink.</summary>
    public static ManagedCandidateSink CandidateSink(
        FrozenManagedCaptureClosure captureClosure,
        JsonObject deployment,
        Func<ManagedProjectToken> projectTokenProvider,
        DotnetSubjectPackage? subject = null,
        string? operationId = null)
    {
        return CandidateSinkBound(
            captureClosure, deployment, projectTokenProvider, subject, operationId).Sink;
    }

    internal static (ManagedCandidateSink Sink, JsonObject Deployment) CandidateSinkBound(
        FrozenManagedCaptureClosure captureClosure,
        JsonObject deployment,
        Func<ManagedProjectToken> projectTokenProvider,
        DotnetSubjectPackage? subject,
        string? operationId)
    {
        OfficialManagedConfiguration official = Configuration();
        JsonObject boundDeployment = (JsonObject)deployment.DeepClone();
        boundDeployment["runtime_endpoint"] = official.ManagedOrigin;
        ManagedTlsEndpoint endpoint = new(official.ManagedOrigin);
        ManagedCandidateSink sink = new(
            new ManagedTlsClient(endpoint, endpoint),
            captureClosure,
            new ManagedSinkConfiguration(
                official.CaptureSignerId,
                official.CaptureSignerPublicKey,
                RequireServiceId(boundDeployment),
                ProtectedStateRoot(),
                projectTokenProvider),
            subject,
            operationId);
        sink.BindDeployment(boundDeployment);
        return (sink, boundDeployment);
    }

    private static bool IsSentinel(string value) =>
        value.StartsWith("__REPROIT_OFFICIAL_", StringComparison.Ordinal) &&
        value.EndsWith("_SENTINEL__", StringComparison.Ordinal);

    private static bool ValidOfficialOrigin(string value, out Uri? origin)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out origin) ||
            origin.Scheme != Uri.UriSchemeHttps || !origin.IsDefaultPort ||
            origin.PathAndQuery != "/" || origin.Fragment.Length != 0 ||
            origin.UserInfo.Length != 0 || origin.Host.Length is 0 or > 253 ||
            value != $"https://{origin.Host}" ||
            origin.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            origin.Host.EndsWith(".example", StringComparison.Ordinal) ||
            origin.Host.EndsWith(".invalid", StringComparison.Ordinal) ||
            origin.Host.EndsWith(".localhost", StringComparison.Ordinal) ||
            origin.Host.EndsWith(".test", StringComparison.Ordinal))
        {
            return false;
        }
        string[] labels = origin.Host.Split('.');
        return labels.Length >= 2 && labels.All(label =>
            label.Length is > 0 and <= 63 &&
            label[0] != '-' && label[^1] != '-' &&
            label.All(character =>
                char.IsAsciiLetterOrDigit(character) || character == '-'));
    }

    private static ManagedCaptureException ReleaseBindingInvalid() => new(
        "CONFIG_CONFLICT", "The official managed release binding is invalid.");

    private static string RequireServiceId(JsonObject deployment)
    {
        string serviceId = ManagedProtocol.Text(deployment["service_id"]) ?? "";
        ManagedProtocol.RequireTypedIdText(serviceId, "service_id");
        return serviceId;
    }

    private static string ProtectedStateRoot()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new ManagedCaptureException(
                "UNSUPPORTED",
                "The managed .NET capture path requires a supported Linux application host.");
        }
        string? stateRoot = Environment.GetEnvironmentVariable("XDG_STATE_HOME");
        if (string.IsNullOrEmpty(stateRoot))
        {
            string? home = Environment.GetEnvironmentVariable("HOME");
            if (string.IsNullOrEmpty(home))
            {
                throw new ManagedCaptureException(
                    "CONFIG_CONFLICT",
                    "The protected managed state directory is unavailable.");
            }
            stateRoot = Path.Combine(home, ".local", "state");
        }
        if (!Path.IsPathFullyQualified(stateRoot) ||
            Path.GetFullPath(stateRoot) != stateRoot)
        {
            throw new ManagedCaptureException(
                "CONFIG_CONFLICT",
                "The protected managed state directory is invalid.");
        }
        return stateRoot;
    }
}
