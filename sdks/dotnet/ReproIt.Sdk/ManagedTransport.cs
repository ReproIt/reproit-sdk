using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Holds one managed candidate key and its signed capture grant.</summary>
public sealed record EncryptionResponse(byte[] CandidateKey, JsonObject CaptureGrant);

/// <summary>Holds one bounded managed service HTTP response.</summary>
public sealed record ManagedHttpResponse(byte[] Body, int Status);

/// <summary>Registers managed workload keys with the key service.</summary>
public interface IManagedRegistrationDelivery
{
    /// <summary>Registers one signed managed deployment and workload key.</summary>
    JsonObject RegisterWorkloadKey(
        ManagedProjectToken projectToken,
        JsonObject request,
        TimeSpan timeout);
}

/// <summary>Restricts a project token to first workload registration.</summary>
public sealed class ManagedProjectToken
{
    private const int MaxProjectTokenBytes = 1_024;
    private readonly string value;

    /// <summary>Validates and wraps one managed project token.</summary>
    public ManagedProjectToken(string value)
    {
        if (value.Length is 0 or > MaxProjectTokenBytes ||
            value.Any(character => character is < '!' or > '~'))
        {
            throw ManagedProtocol.SchemaInvalid("The managed project token is invalid.");
        }
        this.value = value;
    }

    /// <summary>Returns the Authorization header value.</summary>
    public string Authorization() => $"Bearer {value}";
}

/// <summary>Connects to one TLS 1.3 managed key service or ingress origin.</summary>
/// <remarks>
/// Mirrors crates/reproit-sdk-rust/src/managed_transport.rs: TLS 1.3 only,
/// HTTP/1.1 with Connection: close, bounded request and response sizes, and
/// typed rejection of every invalid response. The protected constructor
/// exists only so unit tests can substitute a loopback connection.
/// </remarks>
public class ManagedTlsEndpoint
{
    internal const int MaxCaBytes = 1_048_576;
    internal const int MaxHeaderBytes = 8_192;
    internal const int MaxJsonResponseBytes = 8_388_608;

    private readonly string authority;
    private readonly string host;
    private readonly int port;
    private readonly string serverName;
    private readonly X509Certificate2? rootCertificate;
    private readonly bool plaintextTest;

    /// <summary>Creates one TLS 1.3 endpoint that uses the platform trust store.</summary>
    public ManagedTlsEndpoint(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || !parsed.IsDefaultPort ||
            parsed.PathAndQuery != "/" || parsed.Fragment.Length != 0 ||
            parsed.UserInfo.Length != 0 || parsed.Host.Length == 0)
        {
            throw EndpointInvalid();
        }
        host = parsed.Host;
        port = 443;
        serverName = parsed.Host;
        authority = parsed.Host;
        Origin = $"https://{parsed.Host}";
        rootCertificate = null;
        plaintextTest = false;
    }

    /// <summary>Creates one TLS 1.3 endpoint pinned to a CA certificate file.</summary>
    public ManagedTlsEndpoint(
        string host, int port, string serverName, string authority,
        string caCertificatePath)
    {
        if (host.Length is 0 or > 253 || port is < 1 or > 65_535 ||
            serverName.Length is 0 or > 253)
        {
            throw EndpointInvalid();
        }
        ValidateAuthority(authority);
        this.host = host;
        this.port = port;
        this.serverName = serverName;
        this.authority = authority;
        Origin = $"https://{authority}";
        rootCertificate = LoadRootCertificate(caCertificatePath);
        plaintextTest = false;
    }

    /// <summary>Creates one plaintext loopback endpoint for tests only.</summary>
    protected ManagedTlsEndpoint(string host, int port, string authority)
    {
        ValidateAuthority(authority);
        this.host = host;
        this.port = port;
        serverName = authority;
        this.authority = authority;
        Origin = $"https://{authority}";
        rootCertificate = null;
        plaintextTest = true;
    }

    /// <summary>Gets the https origin of this endpoint.</summary>
    public string Origin { get; }

    /// <summary>Sends one bounded HTTP/1.1 request and reads the response.</summary>
    public ManagedHttpResponse Request(
        string method,
        string target,
        string? authorization,
        string? contentType,
        byte[] body,
        TimeSpan timeout)
    {
        ValidateRequestComponent(method);
        ValidateTarget(target);
        if (authorization is not null)
        {
            ValidateHeaderValue(authorization);
        }
        if (contentType is not null)
        {
            ValidateHeaderValue(contentType);
        }
        StringBuilder header = new();
        header.Append($"{method} {target} HTTP/1.1\r\n");
        header.Append($"Host: {authority}\r\nConnection: close\r\n");
        if (authorization is not null)
        {
            header.Append($"Authorization: {authorization}\r\n");
        }
        if (contentType is not null)
        {
            header.Append($"Content-Type: {contentType}\r\n");
        }
        header.Append($"Content-Length: {body.Length}\r\n\r\n");
        try
        {
            using Stream connection = Connect(timeout);
            connection.Write(Encoding.ASCII.GetBytes(header.ToString()));
            connection.Write(body);
            connection.Flush();
            return ReadResponse(connection);
        }
        catch (AuthenticationException)
        {
            throw EndpointInvalid();
        }
        catch (Exception error) when (error is IOException or SocketException or
            ObjectDisposedException)
        {
            throw ServiceUnavailable();
        }
    }

    /// <summary>Resolves one bound upload URL to a target on this origin.</summary>
    public string UploadTarget(string uploadUrl)
    {
        if (!uploadUrl.StartsWith(Origin, StringComparison.Ordinal))
        {
            throw EndpointInvalid();
        }
        string target = uploadUrl[Origin.Length..];
        ValidateTarget(target);
        return target;
    }

    /// <summary>Opens one connection with TLS 1.3 and the pinned root.</summary>
    protected virtual Stream Connect(TimeSpan timeout)
    {
        if (plaintextTest)
        {
            throw EndpointInvalid();
        }
        Socket socket = ConnectSocket(timeout);
        try
        {
            SslStream stream = new(
                new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
            SslClientAuthenticationOptions options = new()
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                TargetHost = serverName,
            };
            if (rootCertificate is not null)
            {
                X509ChainPolicy policy = new()
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                };
                policy.CustomTrustStore.Add(rootCertificate);
                options.CertificateChainPolicy = policy;
            }
            stream.AuthenticateAsClient(options);
            return stream;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Opens one bounded plaintext socket connection.</summary>
    protected Socket ConnectSocket(TimeSpan timeout)
    {
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            int milliseconds = Math.Max(1, (int)timeout.TotalMilliseconds);
            socket.SendTimeout = milliseconds;
            socket.ReceiveTimeout = milliseconds;
            Task connect = socket.ConnectAsync(host, port);
            if (!connect.Wait(timeout))
            {
                throw ServiceUnavailable();
            }
            return socket;
        }
        catch (Exception error) when (error is not ManagedCaptureException)
        {
            socket.Dispose();
            throw ServiceUnavailable();
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static X509Certificate2 LoadRootCertificate(string caCertificatePath)
    {
        FileInfo certificateFile = new(caCertificatePath);
        if (!certificateFile.Exists || certificateFile.LinkTarget is not null ||
            certificateFile.Length is <= 0 or > MaxCaBytes)
        {
            throw EndpointInvalid();
        }
        byte[] certificate;
        try
        {
            certificate = File.ReadAllBytes(caCertificatePath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw EndpointInvalid();
        }
        if (certificate.Length != certificateFile.Length ||
            certificate.Any(value => value > 0x7F))
        {
            throw EndpointInvalid();
        }
        try
        {
            return X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(certificate));
        }
        catch (Exception error) when (error is
            System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            throw EndpointInvalid();
        }
    }

    internal static ManagedHttpResponse ReadResponse(Stream connection)
    {
        byte[] header = new byte[MaxHeaderBytes];
        int headerLength = 0;
        while (headerLength < MaxHeaderBytes)
        {
            int read = connection.ReadByte();
            if (read < 0)
            {
                throw ResponseInvalid();
            }
            header[headerLength] = (byte)read;
            headerLength += 1;
            if (headerLength >= 4 &&
                header.AsSpan(headerLength - 4, 4).SequenceEqual("\r\n\r\n"u8))
            {
                break;
            }
        }
        if (headerLength < 4 ||
            !header.AsSpan(headerLength - 4, 4).SequenceEqual("\r\n\r\n"u8))
        {
            throw ResponseInvalid();
        }
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(header, 0, headerLength);
        }
        catch (DecoderFallbackException)
        {
            throw ResponseInvalid();
        }
        string[] lines = text.Split("\r\n");
        string[] statusParts = lines[0].Split(' ');
        if (statusParts.Length < 2 || statusParts[1].Length == 0 ||
            !statusParts[1].All(char.IsAsciiDigit) ||
            !int.TryParse(statusParts[1], out int status))
        {
            throw ResponseInvalid();
        }
        int? contentLength = null;
        foreach (string line in lines.Skip(1))
        {
            if (line.Length == 0)
            {
                continue;
            }
            int separator = line.IndexOf(':');
            if (separator < 0)
            {
                throw ResponseInvalid();
            }
            string name = line[..separator].ToLowerInvariant();
            string value = line[(separator + 1)..].Trim();
            if (name == "transfer-encoding")
            {
                throw ResponseInvalid();
            }
            if (name == "content-length")
            {
                if (contentLength is not null || value.Length == 0 ||
                    !value.All(char.IsAsciiDigit) ||
                    !int.TryParse(value, out int parsed))
                {
                    throw ResponseInvalid();
                }
                contentLength = parsed;
            }
        }
        int bodyLength = contentLength ?? 0;
        if (bodyLength > MaxJsonResponseBytes)
        {
            throw ResponseInvalid();
        }
        byte[] body = new byte[bodyLength];
        int bodyRead = 0;
        while (bodyRead < bodyLength)
        {
            int read = connection.Read(body, bodyRead, bodyLength - bodyRead);
            if (read == 0)
            {
                throw ServiceUnavailable();
            }
            bodyRead += read;
        }
        return new ManagedHttpResponse(body, status);
    }

    private static void ValidateAuthority(string value)
    {
        if (value.Length is 0 or > 512 || value.Any(character =>
            character is < '!' or > '~' or '/' or '?' or '#' or '@'))
        {
            throw EndpointInvalid();
        }
    }

    private static void ValidateRequestComponent(string value)
    {
        if (value.Length is 0 or > 16 ||
            value.Any(character => character is < 'A' or > 'Z'))
        {
            throw EndpointInvalid();
        }
    }

    internal static void ValidateTarget(string value)
    {
        if (!value.StartsWith('/') || value.Length > 4_096 || value.Contains('#') ||
            value.Any(character => character <= ' ' || character == '\x7f'))
        {
            throw EndpointInvalid();
        }
    }

    private static void ValidateHeaderValue(string value)
    {
        if (value.Length is 0 or > 4_096 ||
            value.Any(character => character is < ' ' or > '~'))
        {
            throw EndpointInvalid();
        }
    }

    internal static ManagedCaptureException EndpointInvalid() => new(
        "SCHEMA_INVALID", "The managed TLS endpoint configuration is invalid.");

    internal static ManagedCaptureException ResponseInvalid() => new(
        "SCHEMA_INVALID", "The managed service response is invalid.");

    internal static ManagedCaptureException ServiceUnavailable() => new(
        "SERVICE_UNAVAILABLE", "The managed capture service is unavailable.");
}

/// <summary>Implements the SDK client for the key service and managed ingress.</summary>
public sealed class ManagedTlsClient :
    IManagedRegistrationDelivery, IManagedGrantDelivery, IManagedIngressDelivery
{
    private static readonly HashSet<string> UploadStates =
        ["CANCELLED", "COMMITTED", "COMMITTING", "EXPIRED", "OPEN", "UPLOADING"];
    private static readonly HashSet<string> DurabilityStates =
        ["CLOUD_PROTECTED", "LOCAL_ONLY"];
    private static readonly string[] LimitKeys =
    [
        "max_candidate_bytes", "max_object_bytes", "max_objects",
        "max_total_ciphertext_bytes", "missing_page_size", "object_attempts",
        "upload_lifetime_ms",
    ];

    private readonly ManagedTlsEndpoint ingress;
    private readonly ManagedTlsEndpoint keyService;
    /// <summary>Creates one client over the key service and ingress origins.</summary>
    public ManagedTlsClient(
        ManagedTlsEndpoint keyService,
        ManagedTlsEndpoint ingress)
    {
        this.keyService = keyService;
        this.ingress = ingress;
    }

    /// <inheritdoc />
    public JsonObject RegisterWorkloadKey(
        ManagedProjectToken projectToken,
        JsonObject request,
        TimeSpan timeout)
    {
        if (!ManagedProtocol.HasExactly(
                request, "algorithm", "deployment", "public_key", "service_id") ||
            ManagedProtocol.Text(request["algorithm"]) != "Ed25519" ||
            request["deployment"] is not JsonObject deployment ||
            ManagedProtocol.Text(request["service_id"]) is not string serviceId ||
            ManagedProtocol.Text(deployment["service_id"]) != serviceId)
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        ManagedProtocol.RequireTypedIdText(serviceId, "service_id");
        byte[] publicKey = ManagedProtocol.DecodeBase64Url(
            ManagedProtocol.Text(request["public_key"]), 32);
        ManagedCandidateSink.ValidateDeployment(deployment);
        if (ManagedProtocol.Text(deployment["signer_key_id"]) !=
                ManagedProtocol.WorkloadKeyId(publicKey))
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        ManagedProtocol.VerifySignedValue(deployment, publicKey);
        ManagedHttpResponse response = keyService.Request(
            "POST", "/v1/workload-keys", projectToken.Authorization(),
            "application/json", CanonicalJson.Bytes(request), timeout);
        JsonNode registrationNode = DecodeJson(response, 200);
        string? keyId = ManagedProtocol.Text((registrationNode as JsonObject)?["key_id"]);
        if (registrationNode is not JsonObject registration ||
            !ManagedProtocol.HasExactly(
                registration, "deployment_digest", "key_id", "service_id") ||
            ManagedProtocol.Text(registration["service_id"]) != serviceId ||
            ManagedProtocol.Text(registration["deployment_digest"]) !=
                ManagedProtocol.CanonicalDigest(deployment) ||
            keyId != ManagedProtocol.WorkloadKeyId(publicKey))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        return registration;
    }

    /// <inheritdoc />
    public EncryptionResponse RequestEncryptionGrant(JsonObject request, TimeSpan timeout)
    {
        ValidateGrantRequest(request);
        ManagedHttpResponse response = keyService.Request(
            "POST", "/v1/managed-candidate-encryption-grants",
            null, "application/json",
            CanonicalJson.Bytes(request), timeout);
        JsonNode valueNode = DecodeJson(response, 200);
        if (valueNode is not JsonObject value ||
            !ManagedProtocol.HasExactly(value, "candidate_key", "capture_grant"))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        byte[] candidateKey =
            ManagedProtocol.DecodeBase64Url(ManagedProtocol.Text(value["candidate_key"]), 32);
        ManagedProtocol.ValidateCaptureGrant(value["capture_grant"]);
        return new EncryptionResponse(candidateKey, (JsonObject)value["capture_grant"]!);
    }

    /// <inheritdoc />
    public JsonObject Start(JsonObject request, TimeSpan timeout)
    {
        ManagedProtocol.ValidateUploadRequest(request);
        ManagedHttpResponse response = ingress.Request(
            "POST", "/v1/managed-candidates", null, "application/json",
            CanonicalJson.Bytes(request), timeout);
        return ValidateStart(DecodeJson(response, 200));
    }

    /// <inheritdoc />
    public JsonObject Missing(
        string uploadId, string uploadToken, string? cursor, TimeSpan timeout)
    {
        ManagedProtocol.RequireTypedIdText(uploadId, "upload_id");
        ValidateToken(uploadToken);
        if (cursor is not null)
        {
            ValidateToken(cursor);
        }
        string target = $"/v1/managed-candidates/{uploadId}/missing?limit=100";
        if (cursor is not null)
        {
            target += $"&cursor={cursor}";
        }
        ManagedHttpResponse response = ingress.Request(
            "GET", target, $"Bearer {uploadToken}", null, [], timeout);
        return ValidateMissingPage(DecodeJson(response, 200));
    }

    /// <inheritdoc />
    public void UploadObject(string uploadUrl, string digest, byte[] value, TimeSpan timeout)
    {
        if (ManagedProtocol.DigestBytes(value) != digest)
        {
            throw ManagedProtocol.ObjectDigestMismatch();
        }
        string target = ingress.UploadTarget(uploadUrl);
        ManagedHttpResponse response = ingress.Request(
            "PUT", target, null, "application/octet-stream", value, timeout);
        ExpectEmpty(response, 204);
    }

    /// <inheritdoc />
    public JsonObject Commit(string uploadId, string uploadToken, TimeSpan timeout)
    {
        ManagedProtocol.RequireTypedIdText(uploadId, "upload_id");
        ValidateToken(uploadToken);
        ManagedHttpResponse response = ingress.Request(
            "POST", $"/v1/managed-candidates/{uploadId}/commit",
            $"Bearer {uploadToken}", null, [], timeout);
        return ValidateCommit(DecodeJson(response, 200));
    }

    /// <inheritdoc />
    public JsonObject Cancel(string uploadId, string uploadToken, TimeSpan timeout)
    {
        ManagedProtocol.RequireTypedIdText(uploadId, "upload_id");
        ValidateToken(uploadToken);
        ManagedHttpResponse response = ingress.Request(
            "DELETE", $"/v1/managed-candidates/{uploadId}",
            $"Bearer {uploadToken}", null, [], timeout);
        return ValidateStatus(DecodeJson(response, 200));
    }

    /// <summary>Validates one encryption grant request body.</summary>
    public static void ValidateGrantRequest(JsonObject value)
    {
        if (!ManagedProtocol.HasExactly(
                value, "candidate_identity_digest", "capture_id", "cipher_suite",
                "deployment_digest", "organization_id", "processing_mode", "project_id",
                "service_id", "signature", "signer_key_id") ||
            ManagedProtocol.Text(value["processing_mode"]) != "managed" ||
            ManagedProtocol.Text(value["cipher_suite"]) != ManagedProtocol.CipherSuite ||
            !ManagedProtocol.ValidDigest(value["candidate_identity_digest"]) ||
            !ManagedProtocol.ValidDigest(value["deployment_digest"]) ||
            !ManagedProtocol.ValidTypedId(value["capture_id"], "capture_id") ||
            !ManagedProtocol.ValidTypedId(value["organization_id"], "organization_id") ||
            !ManagedProtocol.ValidTypedId(value["project_id"], "project_id") ||
            !ManagedProtocol.ValidTypedId(value["service_id"], "service_id") ||
            ManagedProtocol.Text(value["signer_key_id"]) is not string keyId ||
            !keyId.StartsWith("managed-workload-sha256:", StringComparison.Ordinal))
        {
            throw ManagedProtocol.SchemaInvalid();
        }
        ManagedProtocol.DecodeBase64Url(ManagedProtocol.Text(value["signature"]), 64);
    }

    private static void ValidateMissingObject(JsonNode? value)
    {
        string? uploadUrl = ManagedProtocol.Text((value as JsonObject)?["upload_url"]);
        if (value is not JsonObject missing ||
            !ManagedProtocol.HasExactly(missing, "cipher_digest", "expires_at", "upload_url") ||
            !ManagedProtocol.ValidDigest(missing["cipher_digest"]) ||
            !ManagedProtocol.ValidTimestamp(missing["expires_at"]) ||
            uploadUrl is null || uploadUrl.Length is 0 or > 4_096)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static void ValidateLimits(JsonNode? value)
    {
        if (value is not JsonObject limits ||
            !ManagedProtocol.HasExactly(limits, LimitKeys) ||
            LimitKeys.Any(key => ManagedProtocol.Count(limits[key]) is null or < 0))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static JsonObject ValidateStart(JsonNode value)
    {
        if (value is not JsonObject start || !ManagedProtocol.HasExactly(
                start, "expires_at", "limits", "missing_objects", "next_missing_cursor",
                "state", "upload_id", "upload_token") ||
            !ManagedProtocol.ValidTimestamp(start["expires_at"]) ||
            ManagedProtocol.Text(start["state"]) is not string state ||
            !UploadStates.Contains(state) ||
            !ManagedProtocol.ValidTypedId(start["upload_id"], "upload_id") ||
            start["missing_objects"] is not JsonArray missingObjects)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        ValidateLimits(start["limits"]);
        ValidateResponseToken(ManagedProtocol.Text(start["upload_token"]));
        if (start["next_missing_cursor"] is not null)
        {
            ValidateResponseToken(ManagedProtocol.Text(start["next_missing_cursor"]));
        }
        foreach (JsonNode? missing in missingObjects)
        {
            ValidateMissingObject(missing);
        }
        return start;
    }

    private static JsonObject ValidateMissingPage(JsonNode value)
    {
        if (value is not JsonObject page ||
            !ManagedProtocol.HasExactly(page, "missing_objects", "next_missing_cursor") ||
            page["missing_objects"] is not JsonArray missingObjects)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        if (page["next_missing_cursor"] is not null)
        {
            ValidateResponseToken(ManagedProtocol.Text(page["next_missing_cursor"]));
        }
        foreach (JsonNode? missing in missingObjects)
        {
            ValidateMissingObject(missing);
        }
        return page;
    }

    private static JsonObject ValidateCommit(JsonNode value)
    {
        if (value is not JsonObject commit || !ManagedProtocol.HasExactly(
                commit, "candidate_identity_digest", "candidate_key_reference",
                "capture_id", "encrypted_candidate_digest", "state", "upload_id") ||
            !ManagedProtocol.ValidDigest(commit["candidate_identity_digest"]) ||
            !ManagedProtocol.ValidOpaqueReference(commit["candidate_key_reference"]) ||
            !ManagedProtocol.ValidTypedId(commit["capture_id"], "capture_id") ||
            !ManagedProtocol.ValidDigest(commit["encrypted_candidate_digest"]) ||
            ManagedProtocol.Text(commit["state"]) is not string state ||
            !DurabilityStates.Contains(state) ||
            !ManagedProtocol.ValidTypedId(commit["upload_id"], "upload_id"))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        return commit;
    }

    private static JsonObject ValidateStatus(JsonNode value)
    {
        if (value is not JsonObject status || !ManagedProtocol.HasExactly(
                status, "candidate_identity_digest", "candidate_key_reference",
                "capture_id", "encrypted_candidate_digest", "expires_at",
                "missing_digests", "state", "upload_id") ||
            !ManagedProtocol.ValidDigest(status["candidate_identity_digest"]) ||
            !ManagedProtocol.ValidOpaqueReference(status["candidate_key_reference"]) ||
            !ManagedProtocol.ValidTypedId(status["capture_id"], "capture_id") ||
            !ManagedProtocol.ValidDigest(status["encrypted_candidate_digest"]) ||
            !(status["expires_at"] is null ||
                ManagedProtocol.ValidTimestamp(status["expires_at"])) ||
            status["missing_digests"] is not JsonArray missingDigests ||
            missingDigests.Any(digest => !ManagedProtocol.ValidDigest(digest)) ||
            ManagedProtocol.Text(status["state"]) is not string state ||
            !UploadStates.Contains(state) ||
            !ManagedProtocol.ValidTypedId(status["upload_id"], "upload_id"))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        return status;
    }

    private static JsonNode DecodeJson(ManagedHttpResponse response, int expectedStatus)
    {
        if (response.Status != expectedStatus)
        {
            throw DecodeServerError(response.Status, response.Body);
        }
        if (response.Body.Length == 0)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
        try
        {
            return ManagedProtocol.ParseStrictJson(
                response.Body, ManagedTlsEndpoint.MaxJsonResponseBytes);
        }
        catch (ManagedCaptureException)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static void ExpectEmpty(ManagedHttpResponse response, int expectedStatus)
    {
        if (response.Status != expectedStatus)
        {
            throw DecodeServerError(response.Status, response.Body);
        }
        if (response.Body.Length != 0)
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static ManagedCaptureException DecodeServerError(int status, byte[] body)
    {
        if (body.Length > 0)
        {
            JsonNode? value = null;
            try
            {
                value = ManagedProtocol.ParseStrictJson(
                    body, ManagedTlsEndpoint.MaxJsonResponseBytes);
            }
            catch (ManagedCaptureException)
            {
                // An unparseable error body falls through to the status rule.
            }
            if (value is JsonObject error &&
                ManagedProtocol.HasExactly(error, "code", "message", "retryable") &&
                ManagedProtocol.Text(error["code"]) is string code &&
                ManagedProtocol.ErrorCodes.Contains(code) &&
                ManagedProtocol.Text(error["message"]) is string message &&
                error["retryable"]?.GetValueKind() is System.Text.Json.JsonValueKind.True
                    or System.Text.Json.JsonValueKind.False)
            {
                return new ManagedCaptureException(
                    code, message, error["retryable"]!.GetValue<bool>());
            }
        }
        if (status is 429 or 502 or 503 or 504)
        {
            return ManagedTlsEndpoint.ServiceUnavailable();
        }
        return ManagedTlsEndpoint.ResponseInvalid();
    }

    private static void ValidateToken(string value)
    {
        if (!TokenShapeValid(value))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static void ValidateResponseToken(string? value)
    {
        if (value is null || !TokenShapeValid(value))
        {
            throw ManagedTlsEndpoint.ResponseInvalid();
        }
    }

    private static bool TokenShapeValid(string value) =>
        value.Length is > 0 and <= 256 && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}
