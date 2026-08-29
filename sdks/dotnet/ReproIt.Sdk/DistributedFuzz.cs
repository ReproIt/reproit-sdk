using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ReproIt.Sdk;

/// <summary>Reports a rejected distributed fuzz context.</summary>
public sealed class FuzzContextException() : Exception(
    "Repro It rejected the fuzz context.");

/// <summary>Validates bounded context before native signature verification.</summary>
public sealed record FuzzContextValidator(
    string ProjectId,
    string VerificationKey)
{
    /// <summary>Validates one opaque context for an operation start.</summary>
    public FuzzCampaignContext Validate(string encoded, string now)
    {
        try
        {
            byte[] raw = DecodeBase64Url(encoded, 4_096);
            byte[] key = DecodeBase64Url(VerificationKey, 32);
            JsonObject value = JsonNode.Parse(raw) as JsonObject ?? throw Error();
            if (!CanonicalJson.Bytes(value).AsSpan().SequenceEqual(raw) ||
                value.Count != 7 || key.Length != 32)
            {
                throw Error();
            }
            string campaignId = Required(value, "campaign_id");
            string caseId = Required(value, "case_id");
            string expiresAt = Required(value, "expires_at");
            string format = Required(value, "format");
            string projectId = Required(value, "project_id");
            string serviceId = Required(value, "service_id");
            byte[] signature = DecodeBase64Url(Required(value, "signature"), 64);
            if (format != "reproit.fuzz-context.v1" ||
                !DistributedFuzz.CampaignIdPattern.IsMatch(campaignId) ||
                !DistributedFuzz.CaseIdPattern.IsMatch(caseId) ||
                !DistributedFuzz.ProjectIdPattern.IsMatch(projectId) ||
                !DistributedFuzz.ServiceIdPattern.IsMatch(serviceId) ||
                projectId != ProjectId || signature.Length != 64 ||
                !TryTimestamp(now, out DateTimeOffset current) ||
                !TryTimestamp(expiresAt, out DateTimeOffset expires) || current >= expires)
            {
                throw Error();
            }
            string digest = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(raw));
            return new FuzzCampaignContext(
                campaignId,
                caseId,
                digest,
                encoded,
                now,
                null,
                projectId,
                serviceId,
                VerificationKey);
        }
        catch (Exception error) when (error is not FuzzContextException)
        {
            throw Error();
        }
    }

    private static bool TryTimestamp(string value, out DateTimeOffset timestamp) =>
        DateTimeOffset.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);

    private static string Required(JsonObject value, string name) =>
        value[name]?.GetValue<string>() is string selected && selected.Length > 0
            ? selected
            : throw Error();

    private static byte[] DecodeBase64Url(string value, int maximumBytes)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 5_462 ||
            !DistributedFuzz.Base64UrlPattern.IsMatch(value))
        {
            throw Error();
        }
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        byte[] decoded = Convert.FromBase64String(padded);
        return decoded.Length <= maximumBytes ? decoded : throw Error();
    }

    private static FuzzContextException Error() => new();
}

/// <summary>Contains one validated campaign and case context.</summary>
public sealed class FuzzCampaignContext
{
    internal FuzzCampaignContext(
        string campaignId,
        string caseId,
        string contextDigest,
        string encoded,
        string now,
        string? parentOperationId,
        string projectId,
        string serviceId,
        string verificationKey)
    {
        CampaignId = campaignId;
        CaseId = caseId;
        ContextDigest = contextDigest;
        Encoded = encoded;
        Now = now;
        ParentOperationId = parentOperationId;
        ProjectId = projectId;
        ServiceId = serviceId;
        VerificationKey = verificationKey;
    }

    /// <summary>Gets the campaign identity.</summary>
    public string CampaignId { get; }
    /// <summary>Gets the case identity.</summary>
    public string CaseId { get; }
    /// <summary>Gets the canonical signed-context digest.</summary>
    public string ContextDigest { get; }
    /// <summary>Gets the opaque signed context.</summary>
    public string Encoded { get; }
    /// <summary>Gets the causal parent operation.</summary>
    public string? ParentOperationId { get; }
    /// <summary>Gets the campaign project identity.</summary>
    public string ProjectId { get; }
    /// <summary>Gets the campaign root-service identity.</summary>
    public string ServiceId { get; }
    internal string Now { get; }
    internal string VerificationKey { get; }

    /// <summary>Activates the context for one synchronous or asynchronous flow.</summary>
    public IDisposable Activate() => DistributedFuzz.Activate(this);

    internal FuzzCampaignContext WithParent(string operationId)
    {
        if (!DistributedFuzz.OperationIdPattern.IsMatch(operationId))
        {
            throw new FuzzContextException();
        }
        return new FuzzCampaignContext(
            CampaignId,
            CaseId,
            ContextDigest,
            Encoded,
            Now,
            operationId,
            ProjectId,
            ServiceId,
            VerificationKey);
    }

    internal JsonObject BeginIdentity() => new()
    {
        ["campaign_id"] = CampaignId,
        ["case_id"] = CaseId,
        ["context_digest"] = ContextDigest,
    };

    internal JsonObject NativeInput() => new()
    {
        ["encoded"] = Encoded,
        ["now"] = Now,
        ["project_id"] = ProjectId,
        ["service_id"] = ServiceId,
        ["verification_key"] = VerificationKey,
    };
}

/// <summary>Extracts and propagates distributed fuzz context.</summary>
public static partial class DistributedFuzz
{
    /// <summary>The inbound and outbound HTTP context header.</summary>
    public const string ContextHttpHeader = "ReproIt-Fuzz-Context";
    /// <summary>The inbound and outbound HTTP parent header.</summary>
    public const string ParentHttpHeader = "ReproIt-Parent-Operation";
    /// <summary>The delivered-work context metadata field.</summary>
    public const string ContextQueueMetadata = "reproit.fuzz.context";
    /// <summary>The delivered-work parent metadata field.</summary>
    public const string ParentQueueMetadata = "reproit.parent.operation";

    private static readonly AsyncLocal<FuzzCampaignContext?> Current = new();

    [GeneratedRegex(
        "^fc_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    internal static partial Regex CampaignIdRegex();
    [GeneratedRegex(
        "^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    internal static partial Regex CaseIdRegex();
    [GeneratedRegex(
        "^prj_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    internal static partial Regex ProjectIdRegex();
    [GeneratedRegex(
        "^svc_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    internal static partial Regex ServiceIdRegex();
    [GeneratedRegex(
        "^op_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    internal static partial Regex OperationIdRegex();
    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    internal static partial Regex Base64UrlRegex();

    internal static Regex CampaignIdPattern => CampaignIdRegex();
    internal static Regex CaseIdPattern => CaseIdRegex();
    internal static Regex ProjectIdPattern => ProjectIdRegex();
    internal static Regex ServiceIdPattern => ServiceIdRegex();
    internal static Regex OperationIdPattern => OperationIdRegex();
    internal static Regex Base64UrlPattern => Base64UrlRegex();

    /// <summary>Validates inbound HTTP metadata.</summary>
    public static FuzzCampaignContext? ExtractHttp(
        IReadOnlyDictionary<string, string> headers,
        FuzzContextValidator validator,
        string now)
    {
        string? encoded = Header(headers, ContextHttpHeader);
        string? parent = Header(headers, ParentHttpHeader);
        if (encoded is null)
        {
            return parent is null ? null : throw new FuzzContextException();
        }
        FuzzCampaignContext context = validator.Validate(encoded, now);
        return parent is null ? context : context.WithParent(parent);
    }

    /// <summary>Validates inbound delivered-work metadata.</summary>
    public static FuzzCampaignContext? ExtractQueue(
        IReadOnlyDictionary<string, string> metadata,
        FuzzContextValidator validator,
        string now)
    {
        Dictionary<string, string> headers = [];
        if (metadata.TryGetValue(ContextQueueMetadata, out string? encoded))
        {
            headers[ContextHttpHeader] = encoded;
        }
        if (metadata.TryGetValue(ParentQueueMetadata, out string? parent))
        {
            headers[ParentHttpHeader] = parent;
        }
        return ExtractHttp(headers, validator, now);
    }

    /// <summary>Adds active context to outbound delivered-work metadata.</summary>
    public static void PropagateQueue(IDictionary<string, string> metadata)
    {
        FuzzCampaignContext? context = Active();
        if (context is null)
        {
            return;
        }
        metadata[ContextQueueMetadata] = context.Encoded;
        if (context.ParentOperationId is not null)
        {
            metadata[ParentQueueMetadata] = context.ParentOperationId;
        }
    }

    internal static FuzzCampaignContext? Active() =>
        AutomaticOperationContext.ActiveOperation()?.FuzzContext ?? Current.Value;

    internal static IDisposable Activate(FuzzCampaignContext context)
    {
        FuzzCampaignContext? parent = Current.Value;
        Current.Value = context;
        return new Activation(context, parent);
    }

    private static string? Header(
        IReadOnlyDictionary<string, string> headers,
        string expected)
    {
        List<string> values = headers
            .Where(pair => string.Equals(pair.Key, expected, StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair.Value)
            .ToList();
        return values.Count switch
        {
            0 => null,
            1 when !string.IsNullOrEmpty(values[0]) => values[0],
            _ => throw new FuzzContextException(),
        };
    }

    private sealed class Activation(
        FuzzCampaignContext context,
        FuzzCampaignContext? parent) : IDisposable
    {
        private bool disposed;

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            if (ReferenceEquals(Current.Value, context))
            {
                Current.Value = parent;
            }
        }
    }
}
