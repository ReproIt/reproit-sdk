using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using ReproIt.Sdk;
using static ReproIt.Sdk.Conformance.ManagedFixtures;

namespace ReproIt.Sdk.Conformance;

/// <summary>A loopback endpoint that skips TLS. Conformance double only.</summary>
internal sealed class PlainHttpEndpoint : ManagedTlsEndpoint
{
    internal PlainHttpEndpoint(string host, int port, string authority)
        : base(host, port, authority)
    {
    }

    protected override Stream Connect(TimeSpan timeout) =>
        new NetworkStream(ConnectSocket(timeout), ownsSocket: true);
}

/// <summary>Owns one private test state root.</summary>
internal sealed class ManagedTestStateRoot : IDisposable
{
    internal ManagedTestStateRoot()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new InvalidOperationException(
                "The managed state conformance requires Linux.");
        }
        Path = Directory.CreateTempSubdirectory("reproit-dotnet-managed-state-").FullName;
        File.SetUnixFileMode(Path, UnixFileMode.UserRead |
            UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    internal string Path { get; }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}

/// <summary>One loopback HTTP double for the key service and ingress.</summary>
internal sealed class LoopbackManagedService : IDisposable
{
    private const string ProjectToken = "test-project-token";
    private const string UploadToken = "managed-upload-token-1";

    private readonly TcpListener listener;
    private readonly Thread thread;
    private readonly object stateLock = new();
    private volatile bool stopping;

    internal LoopbackManagedService()
    {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Authority = $"127.0.0.1:{port}";
        Limits = CloudPositive("managed_candidate_limits");
        thread = new Thread(Serve)
        {
            IsBackground = true,
            Name = "reproit-loopback",
        };
        thread.Start();
        Endpoint = new PlainHttpEndpoint("127.0.0.1", port, Authority);
        Client = new ManagedTlsClient(Endpoint, Endpoint);
    }

    internal string Authority { get; }
    internal ManagedTlsClient Client { get; }
    internal PlainHttpEndpoint Endpoint { get; }
    internal HashSet<string> Expected { get; } = [];
    internal int GrantFailureStatus { get; set; }
    internal List<JsonObject> GrantRequests { get; } = [];
    internal List<JsonObject> IssuedGrants { get; } = [];
    internal JsonObject Limits { get; }
    internal string? RegisteredPublicKey { get; private set; }
    internal string? RegisteredWorkloadKeyId { get; private set; }
    internal string? RegisteredDeploymentDigest { get; private set; }
    internal List<(string Method, string Path)> Requests { get; } = [];
    internal HashSet<string> Uploaded { get; } = [];
    internal JsonObject? UploadRequest { get; private set; }

    internal List<(string Method, string Path)> RequestsSnapshot()
    {
        lock (stateLock)
        {
            return [.. Requests];
        }
    }

    public void Dispose()
    {
        stopping = true;
        listener.Stop();
        thread.Join(TimeSpan.FromSeconds(2));
    }

    private void Serve()
    {
        while (!stopping)
        {
            TcpClient connection;
            try
            {
                connection = listener.AcceptTcpClient();
            }
            catch (SocketException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            using (connection)
            {
                try
                {
                    Handle(connection.GetStream());
                }
                catch (Exception)
                {
                    // A broken test connection must not kill the server.
                }
            }
        }
    }

    private void Handle(NetworkStream stream)
    {
        (string method, string target, Dictionary<string, string> headers, byte[] body) =
            ReadRequest(stream);
        string path = target.Split('?')[0];
        string query = target.Contains('?') ? target.Split('?', 2)[1] : "";
        lock (stateLock)
        {
            Requests.Add((method, path));
        }
        switch (method)
        {
            case "POST" when path == "/v1/workload-keys":
                RegisterWorkloadKey(stream, headers, body);
                return;
            case "POST" when path == "/v1/managed-candidate-encryption-grants":
                IssueGrant(stream, headers, body);
                return;
            case "POST" when path == "/v1/managed-candidates":
                StartUpload(stream, body);
                return;
            case "POST" when path == $"/v1/managed-candidates/{UploadId}/commit":
                CommitUpload(stream, headers);
                return;
            case "PUT":
                PutObject(stream, path, query, body);
                return;
            case "DELETE" when path == $"/v1/managed-candidates/{UploadId}":
                CancelUpload(stream);
                return;
            default:
                Reject(stream, 404, "NOT_FOUND", "Unknown route.");
                return;
        }
    }

    private void RegisterWorkloadKey(
        NetworkStream stream, Dictionary<string, string> headers, byte[] body)
    {
        if (!Authorized(headers, $"Bearer {ProjectToken}"))
        {
            Reject(stream, 401, "AUTHENTICATION_REQUIRED", "Missing project token.");
            return;
        }
        JsonObject value = (JsonObject)JsonNode.Parse(body)!;
        if (!ManagedProtocol.HasExactly(
                value, "algorithm", "deployment", "public_key", "service_id") ||
            ManagedProtocol.Text(value["algorithm"]) != "Ed25519" ||
            ManagedProtocol.Text(value["service_id"]) != ServiceId ||
            value["deployment"] is not JsonObject deployment ||
            ManagedProtocol.Text(deployment["service_id"]) != ServiceId ||
            ManagedProtocol.DecodeBase64Url(
                ManagedProtocol.Text(value["public_key"]), 32).Length != 32)
        {
            Reject(stream, 400, "SCHEMA_INVALID", "Invalid registration.");
            return;
        }
        byte[] publicKey = ManagedProtocol.DecodeBase64Url(
            ManagedProtocol.Text(value["public_key"]), 32);
        string deploymentDigest = ManagedProtocol.CanonicalDigest(deployment);
        try
        {
            ManagedProtocol.VerifySignedValue(deployment, publicKey);
        }
        catch (ManagedCaptureException)
        {
            Reject(stream, 403, "ATTESTATION_SCOPE", "Invalid deployment signature.");
            return;
        }
        lock (stateLock)
        {
            RegisteredPublicKey = ManagedProtocol.Text(value["public_key"]);
            RegisteredDeploymentDigest = deploymentDigest;
            RegisteredWorkloadKeyId = ManagedProtocol.WorkloadKeyId(publicKey);
        }
        Reply(stream, 200, new JsonObject
        {
            ["deployment_digest"] = deploymentDigest,
            ["key_id"] = ManagedProtocol.WorkloadKeyId(publicKey),
            ["service_id"] = ServiceId,
        });
    }

    private void IssueGrant(
        NetworkStream stream, Dictionary<string, string> headers, byte[] body)
    {
        if (headers.ContainsKey("authorization"))
        {
            Reject(stream, 401, "AUTHENTICATION_REQUIRED", "Unexpected authorization.");
            return;
        }
        int failureStatus;
        lock (stateLock)
        {
            failureStatus = GrantFailureStatus;
        }
        if (failureStatus != 0)
        {
            Reject(stream, failureStatus, "SERVICE_UNAVAILABLE", "Grant unavailable.");
            return;
        }
        JsonObject request = (JsonObject)JsonNode.Parse(body)!;
        try
        {
            ManagedTlsClient.ValidateGrantRequest(request);
            string? publicKeyText;
            string? deploymentDigest;
            string? workloadKeyId;
            lock (stateLock)
            {
                publicKeyText = RegisteredPublicKey;
                deploymentDigest = RegisteredDeploymentDigest;
                workloadKeyId = RegisteredWorkloadKeyId;
            }
            byte[] publicKey = ManagedProtocol.DecodeBase64Url(publicKeyText, 32);
            if (ManagedProtocol.Text(request["deployment_digest"]) != deploymentDigest ||
                ManagedProtocol.Text(request["signer_key_id"]) != workloadKeyId)
            {
                throw ManagedProtocol.AttestationError();
            }
            ManagedProtocol.VerifySignedValue(request, publicKey);
        }
        catch (ManagedCaptureException)
        {
            Reject(stream, 400, "SCHEMA_INVALID", "Invalid grant request.");
            return;
        }
        DateTime now = DateTime.UtcNow;
        JsonObject grant = SignedCaptureGrant(
            request,
            notBefore: Timestamp(now.AddMinutes(-5)),
            expiresAt: Timestamp(now.AddMinutes(5)));
        lock (stateLock)
        {
            GrantRequests.Add((JsonObject)request.DeepClone());
            IssuedGrants.Add((JsonObject)grant.DeepClone());
        }
        Reply(stream, 200, new JsonObject
        {
            ["candidate_key"] = ManagedProtocol.EncodeBase64Url(CandidateKey),
            ["capture_grant"] = grant,
        });
    }

    private void StartUpload(NetworkStream stream, byte[] body)
    {
        JsonObject request = (JsonObject)JsonNode.Parse(body)!;
        try
        {
            ManagedProtocol.ValidateUploadRequest(request);
        }
        catch (ManagedCaptureException)
        {
            Reject(stream, 400, "SCHEMA_INVALID", "Invalid upload request.");
            return;
        }
        byte[] grantBytes = CanonicalJson.Bytes(request["capture_grant"]!);
        lock (stateLock)
        {
            if (!IssuedGrants.Any(issued =>
                CanonicalJson.Bytes(issued).AsSpan().SequenceEqual(grantBytes)))
            {
                Reject(stream, 403, "ATTESTATION_SCOPE", "Unknown capture grant.");
                return;
            }
            UploadRequest = (JsonObject)request.DeepClone();
            Expected.Clear();
            Uploaded.Clear();
            JsonObject identity = (JsonObject)request["ciphertext_identity"]!;
            Expected.Add(
                ManagedProtocol.Text(identity["manifest_object"]!["cipher_digest"])!);
            foreach (JsonNode? entry in (JsonArray)identity["objects"]!)
            {
                foreach (JsonNode? chunk in (JsonArray)entry!["chunks"]!)
                {
                    Expected.Add(ManagedProtocol.Text(chunk!["cipher_digest"])!);
                }
            }
        }
        JsonArray missing = [];
        foreach (string digest in Expected
            .OrderBy(value => value, StringComparer.Ordinal))
        {
            missing.Add(new JsonObject
            {
                ["cipher_digest"] = digest,
                ["expires_at"] = Timestamp(DateTime.UtcNow.AddMinutes(1)),
                ["upload_url"] =
                    $"https://{Authority}/v1/managed-candidates/{UploadId}" +
                    $"/objects/{digest}?token=up",
            });
        }
        Reply(stream, 200, new JsonObject
        {
            ["expires_at"] = Timestamp(DateTime.UtcNow.AddMinutes(1)),
            ["limits"] = Limits.DeepClone(),
            ["missing_objects"] = missing,
            ["next_missing_cursor"] = null,
            ["state"] = "OPEN",
            ["upload_id"] = UploadId,
            ["upload_token"] = UploadToken,
        });
    }

    private void PutObject(NetworkStream stream, string path, string query, byte[] body)
    {
        string prefix = $"/v1/managed-candidates/{UploadId}/objects/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal) || query != "token=up")
        {
            Reject(stream, 404, "NOT_FOUND", "Unknown object route.");
            return;
        }
        string digest = path[prefix.Length..];
        lock (stateLock)
        {
            if (!Expected.Contains(digest) ||
                ManagedProtocol.DigestBytes(body) != digest)
            {
                Reject(stream, 400, "OBJECT_DIGEST_MISMATCH", "Digest mismatch.");
                return;
            }
            Uploaded.Add(digest);
        }
        Reply(stream, 204, null);
    }

    private void CommitUpload(NetworkStream stream, Dictionary<string, string> headers)
    {
        if (!Authorized(headers, $"Bearer {UploadToken}"))
        {
            Reject(stream, 401, "AUTHENTICATION_REQUIRED", "Missing upload token.");
            return;
        }
        JsonObject? request;
        lock (stateLock)
        {
            if (!Expected.SetEquals(Uploaded))
            {
                Reject(stream, 409, "UPLOAD_INCOMPLETE", "Objects are missing.");
                return;
            }
            request = UploadRequest;
        }
        JsonObject identity = (JsonObject)request!["ciphertext_identity"]!;
        Reply(stream, 200, new JsonObject
        {
            ["candidate_identity_digest"] =
                identity["candidate_identity_digest"]!.DeepClone(),
            ["candidate_key_reference"] =
                identity["candidate_key_reference"]!.DeepClone(),
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["encrypted_candidate_digest"] =
                request["encrypted_candidate_digest"]!.DeepClone(),
            ["state"] = "CLOUD_PROTECTED",
            ["upload_id"] = UploadId,
        });
    }

    private void CancelUpload(NetworkStream stream)
    {
        JsonObject? request;
        lock (stateLock)
        {
            request = UploadRequest;
        }
        if (request is null)
        {
            Reject(stream, 404, "NOT_FOUND", "Unknown upload.");
            return;
        }
        JsonObject identity = (JsonObject)request["ciphertext_identity"]!;
        Reply(stream, 200, new JsonObject
        {
            ["candidate_identity_digest"] =
                identity["candidate_identity_digest"]!.DeepClone(),
            ["candidate_key_reference"] =
                identity["candidate_key_reference"]!.DeepClone(),
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["encrypted_candidate_digest"] =
                request["encrypted_candidate_digest"]!.DeepClone(),
            ["expires_at"] = null,
            ["missing_digests"] = new JsonArray(),
            ["state"] = "CANCELLED",
            ["upload_id"] = UploadId,
        });
    }

    private static bool Authorized(Dictionary<string, string> headers, string expected) =>
        headers.TryGetValue("authorization", out string? value) && value == expected;

    private static string Timestamp(DateTime value) => value.ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static (string Method, string Target, Dictionary<string, string> Headers,
        byte[] Body) ReadRequest(NetworkStream stream)
    {
        MemoryStream header = new();
        while (true)
        {
            int read = stream.ReadByte();
            if (read < 0)
            {
                throw new IOException("The request ended before its header.");
            }
            header.WriteByte((byte)read);
            byte[] soFar = header.GetBuffer();
            if (header.Length >= 4 &&
                soFar.AsSpan((int)header.Length - 4, 4).SequenceEqual("\r\n\r\n"u8))
            {
                break;
            }
            if (header.Length > 65_536)
            {
                throw new IOException("The request header is unbounded.");
            }
        }
        string text = Encoding.ASCII.GetString(header.ToArray());
        string[] lines = text.Split("\r\n");
        string[] requestLine = lines[0].Split(' ');
        Dictionary<string, string> headers = [];
        foreach (string line in lines.Skip(1))
        {
            int separator = line.IndexOf(':');
            if (separator > 0)
            {
                headers[line[..separator].ToLowerInvariant()] =
                    line[(separator + 1)..].Trim();
            }
        }
        int contentLength = headers.TryGetValue("content-length", out string? length)
            ? int.Parse(length)
            : 0;
        byte[] body = new byte[contentLength];
        int bodyRead = 0;
        while (bodyRead < contentLength)
        {
            int read = stream.Read(body, bodyRead, contentLength - bodyRead);
            if (read == 0)
            {
                throw new IOException("The request ended before its body.");
            }
            bodyRead += read;
        }
        return (requestLine[0], requestLine[1], headers, body);
    }

    private void Reply(NetworkStream stream, int status, JsonObject? value)
    {
        byte[] body = value is null ? [] : CanonicalJson.Bytes(value);
        StringBuilder header = new();
        header.Append($"HTTP/1.1 {status} X\r\n");
        if (body.Length > 0)
        {
            header.Append("Content-Type: application/json\r\n");
        }
        header.Append($"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        stream.Write(Encoding.ASCII.GetBytes(header.ToString()));
        stream.Write(body);
        stream.Flush();
    }

    private void Reject(NetworkStream stream, int status, string code, string message) =>
        Reply(stream, status, new JsonObject
        {
            ["code"] = code,
            ["message"] = message,
            ["retryable"] = status is 429 or 503,
        });
}

/// <summary>Registers, then blocks grant delivery until released.</summary>
internal sealed class StubRegistrationClient :
    IManagedRegistrationDelivery, IManagedGrantDelivery, IManagedIngressDelivery
{
    internal ManualResetEventSlim Release { get; } = new(false);
    internal int GrantCalls { get; private set; }

    public JsonObject RegisterWorkloadKey(
        ManagedProjectToken projectToken,
        JsonObject request,
        TimeSpan timeout) => new()
        {
            ["deployment_digest"] = ManagedProtocol.CanonicalDigest(request["deployment"]!),
            ["key_id"] = ManagedProtocol.Text(request["deployment"]!["signer_key_id"]),
            ["service_id"] = ManagedProtocol.Text(request["service_id"]),
        };

    public EncryptionResponse RequestEncryptionGrant(JsonObject request, TimeSpan timeout)
    {
        lock (Release)
        {
            GrantCalls += 1;
        }
        Release.Wait(TimeSpan.FromSeconds(10));
        throw ManagedProtocol.SchemaInvalid("The double refuses grants.");
    }

    public JsonObject Start(JsonObject request, TimeSpan timeout) =>
        throw ManagedProtocol.SchemaInvalid("The double refuses uploads.");

    public JsonObject Missing(
        string uploadId, string uploadToken, string? cursor, TimeSpan timeout) =>
        throw ManagedProtocol.SchemaInvalid("The double refuses uploads.");

    public void UploadObject(
        string uploadUrl, string digest, byte[] value, TimeSpan timeout) =>
        throw ManagedProtocol.SchemaInvalid("The double refuses uploads.");

    public JsonObject Commit(string uploadId, string uploadToken, TimeSpan timeout) =>
        throw ManagedProtocol.SchemaInvalid("The double refuses uploads.");

    public JsonObject Cancel(string uploadId, string uploadToken, TimeSpan timeout) =>
        throw ManagedProtocol.SchemaInvalid("The double refuses uploads.");
}

/// <summary>Runs the loopback session and bounded sink checks.</summary>
internal static class ManagedLoopbackConformance
{
    internal static void Run()
    {
        SdkProcessResources.ResetForTests();
        LoopbackSession();
        SdkProcessResources.ResetForTests();
        SinkBounds();
        SdkProcessResources.ResetForTests();
        DeliveryExpiry();
        Console.WriteLine("dotnet_managed_loopback=PASS");
        Console.WriteLine("dotnet_managed_sink=PASS");
    }

    private static ManagedSinkConfiguration Configuration(
        string stateRoot,
        Func<ManagedProjectToken>? projectTokenProvider = null) => new(
        CaptureSignerId,
        ManagedProtocol.VerificationKey(CaptureSignerSeed),
        ServiceId,
        stateRoot,
        projectTokenProvider ?? (() => new ManagedProjectToken("test-project-token")));

    private static void CaptureFailure(
        ManagedCandidateSink sink, JsonObject deployment, string worldId,
        string captureId = CaptureId, string operationId = OperationId)
    {
        Sdk sdk = new(sink);
        CandidateStart start = new(
            captureId, deployment.DeepClone(), operationId, worldId);
        sdk.Begin(start, ProtocolPositive("operation_begin_payload"));
        sdk.RecordInput(operationId, ProtocolPositive("operation_input_payload"));
        sdk.Fail(operationId, ProtocolPositive("failure_payload"));
    }

    private static void LoopbackSession()
    {
        using ManagedTestStateRoot stateRoot = new();
        using LoopbackManagedService service = new();
        DotnetSubjectPackage subject = SharedSubject();
        JsonObject world = EmptyWorld();
        string worldId = ManagedProtocol.CanonicalDigest(world);
        int initialProviderCalls = 0;
        ManagedCandidateSink sink = new(
            service.Client,
            new ManagedCaptureClosure([], "return", (JsonObject)world.DeepClone()),
            Configuration(stateRoot.Path, () =>
            {
                initialProviderCalls += 1;
                return new ManagedProjectToken("test-project-token");
            }),
            subject: subject);

        Check(service.RequestsSnapshot().Count == 0,
            "The sink constructor made a managed network request.");
        JsonObject deployment = new()
        {
            ["format"] = "reproit.deployment.v1",
            ["organization_id"] = OrganizationId,
            ["processing_mode"] = "managed",
            ["project_id"] = ProjectId,
            ["repository_id"] = "source.example/acme/commerce",
            ["runtime_capabilities"] = new JsonArray("runtime.dotnet"),
            ["runtime_endpoint"] = "https://managed.reproit.example",
            ["service_id"] = ServiceId,
            ["service_path"] = "services/orders",
            ["signature"] = "",
            ["signed_at"] = "2026-01-01T00:00:00.000Z",
            ["signer_key_id"] = "",
            ["source_revision"] = "0123456789abcdef",
            ["subject"] = new JsonObject(),
        };
        sink.BindDeployment(deployment);
        Check(sink.WorkloadKeyId.StartsWith(
                "managed-workload-sha256:", StringComparison.Ordinal),
            "The managed workload key identifier is invalid.");
        Check(service.RequestsSnapshot().Count == 0,
            "Deployment binding made a managed network request.");

        Sdk localOnly = new(sink);
        CandidateStart successfulStart = new(
            "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
            deployment.DeepClone(),
            "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
            worldId);
        localOnly.Begin(successfulStart, ProtocolPositive("operation_begin_payload"));
        localOnly.Succeed(successfulStart.OperationId);
        CandidateStart incompleteStart = successfulStart with
        {
            CaptureId = "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac5",
            OperationId = "op_01890f3e-7b1c-7cc0-8a1b-123456789ac6",
        };
        localOnly.Begin(incompleteStart, ProtocolPositive("operation_begin_payload"));
        localOnly.AbandonIncomplete(incompleteStart.OperationId);
        Check(service.RequestsSnapshot().Count == 0 && initialProviderCalls == 0,
            "A successful or incomplete operation used managed registration.");
        Check(
            sink.ProcessingModes.SetEquals(new[] { "managed" }) &&
            sink.AllowsProcessingMode("managed") &&
            !sink.AllowsProcessingMode("private"),
            "The managed sink advertises a mode other than managed.");

        // A complete candidate reaches CLOUD_PROTECTED end to end.
        CaptureFailure(sink, deployment, worldId);
        Check(sink.WaitUntilIdle(TimeSpan.FromSeconds(30)),
            "The managed sink did not drain the complete candidate.");
        SdkRecallCounters counters = sink.RecallCounters;
        Check(
            counters.CandidateDurablyAccepted == 1 &&
            counters.CandidateIncomplete == 0 && counters.CandidateRejected == 0 &&
            sink.QueuedBytes == 0,
            "The complete candidate did not become durably accepted " +
            $"(accepted {counters.CandidateDurablyAccepted}, " +
            $"incomplete {counters.CandidateIncomplete}, " +
            $"rejected {counters.CandidateRejected}, " +
            $"expired {counters.CandidateDeliveryExpired}, " +
            $"queue_full {counters.CandidateQueueFull}).");
        List<(string Method, string Path)> requests = service.RequestsSnapshot();
        Check(
            requests[0] == ("POST", "/v1/workload-keys") &&
            requests[1] == ("POST", "/v1/managed-candidate-encryption-grants") &&
            requests[2] == ("POST", "/v1/managed-candidate-encryption-grants") &&
            requests[3] == ("POST", "/v1/managed-candidates") &&
            requests[^1] == ("POST", $"/v1/managed-candidates/{UploadId}/commit"),
            "The managed session request order changed.");
        Check(initialProviderCalls == 1,
            "The first failed operation did not read the project token exactly once.");
        Check(
            service.RegisteredPublicKey ==
                ManagedProtocol.EncodeBase64Url(sink.WorkloadPublicKey),
            "The registered workload public key differs.");
        Check(
            requests.Count(entry => entry.Method == "PUT") == service.Expected.Count &&
            service.Expected.SetEquals(service.Uploaded),
            "The object PUT set does not match the declared ciphertext set.");
        Check(
            service.GrantRequests.Count == 2 &&
            CanonicalJson.Bytes(service.GrantRequests[0]).AsSpan()
                .SequenceEqual(CanonicalJson.Bytes(service.GrantRequests[1])) &&
            ManagedProtocol.Text(
                service.GrantRequests[0]["candidate_identity_digest"]) ==
                ManagedProtocol.Text(service.UploadRequest!["ciphertext_identity"]![
                    "candidate_identity_digest"]),
            "The grant requests do not bind the uploaded identity.");
        Check(
            service.GrantRequests.All(request =>
                ManagedProtocol.Text(request["deployment_digest"]) ==
                    service.RegisteredDeploymentDigest &&
                ManagedProtocol.Text(request["signer_key_id"]) == sink.WorkloadKeyId),
            "The grant requests do not bind the registered deployment.");

        // An incomplete candidate stops locally with a counter.
        int requestsBefore = service.RequestsSnapshot().Count;
        SdkProcessResources.ResetForTests();
        CaptureFailure(
            sink, deployment, "sha256:" + new string('a', 64),
            "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
            "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4");
        Check(sink.WaitUntilIdle(TimeSpan.FromSeconds(30)),
            "The managed sink did not drain the incomplete candidate.");
        counters = sink.RecallCounters;
        Check(
            counters.CandidateIncomplete == 1 &&
            counters.CandidateDurablyAccepted == 1 &&
            service.RequestsSnapshot().Count == requestsBefore,
            "The incomplete candidate made a network request.");

        // A non-canonical candidate is refused without an enqueue.
        JsonObject candidate = CapturedCandidate(deployment, worldId);
        byte[] raw = [.. CanonicalJson.Bytes(candidate), (byte)' '];
        Check(!sink.TrySend(CaptureId, raw),
            "A non-canonical candidate was accepted.");
        Check(sink.RecallCounters.CandidateIncomplete == 2,
            "The non-canonical candidate was not counted incomplete.");

        // A foreign workload signature is refused.
        JsonObject foreignDeployment = BoundDeployment(
            subject, workloadSeed: Repeat(0x55), signerKeyId: WorkloadKeyId);
        JsonObject foreignCandidate = CapturedCandidate(foreignDeployment, worldId);
        Check(
            !sink.TrySend(CaptureId, CanonicalJson.Bytes(foreignCandidate)),
            "A foreign workload signature was accepted.");
        Check(sink.RecallCounters.CandidateIncomplete == 3,
            "The foreign signature was not counted incomplete.");

        // A grant outage is fail-open and counted as retryable.
        service.GrantFailureStatus = 503;
        int candidatesBefore = service.RequestsSnapshot()
            .Count(entry => entry.Path == "/v1/managed-candidates");
        SdkProcessResources.ResetForTests();
        CaptureFailure(sink, deployment, worldId);
        Check(sink.WaitUntilIdle(TimeSpan.FromSeconds(30)),
            "The managed sink did not drain during the grant outage.");
        counters = sink.RecallCounters;
        Check(
            counters.CandidateDurablyAccepted == 1 &&
            counters.CandidateDeliveryExpired == 1 &&
            service.RequestsSnapshot()
                .Count(entry => entry.Path == "/v1/managed-candidates") ==
                candidatesBefore,
            "The grant outage path was not fail-open.");

        // Restart reuses the protected receipt without reading a project token.
        int providerCalls = 0;
        ManagedCandidateSink restarted = new(
            service.Client,
            new ManagedCaptureClosure([], "return", (JsonObject)world.DeepClone()),
            Configuration(stateRoot.Path, () =>
            {
                providerCalls += 1;
                throw new InvalidOperationException("The receipt must suppress token access.");
            }),
            subject: subject);
        JsonObject restartedDeployment = (JsonObject)deployment.DeepClone();
        restartedDeployment["signed_at"] = "2026-02-01T00:00:00.000Z";
        restarted.BindDeployment(restartedDeployment);
        Check(
            CanonicalJson.Bytes(restartedDeployment).AsSpan()
                .SequenceEqual(CanonicalJson.Bytes(deployment)),
            "Restart changed the exact signed Deployment.");
        service.GrantFailureStatus = 0;
        SdkProcessResources.ResetForTests();
        CaptureFailure(restarted, restartedDeployment, worldId);
        Check(restarted.WaitUntilIdle(TimeSpan.FromSeconds(30)),
            "The restarted managed sink did not drain.");
        Check(providerCalls == 0 && service.RequestsSnapshot()
                .Count(entry => entry == ("POST", "/v1/workload-keys")) == 1,
            "Restart registered again or read the project token.");
    }

    private static void SinkBounds()
    {
        using ManagedTestStateRoot stateRoot = new();
        StubRegistrationClient client = new();
        DotnetSubjectPackage subject = SharedSubject();
        JsonObject world = EmptyWorld();
        ManagedCandidateSink sink = new(
            client,
            new ManagedCaptureClosure([], "return", world),
            Configuration(stateRoot.Path),
            subject: subject);
        JsonObject deployment = BoundDeployment(subject);
        sink.BindDeployment(deployment);
        JsonObject candidate =
            CapturedCandidate(deployment, ManagedProtocol.CanonicalDigest(world));
        byte[] raw = CanonicalJson.Bytes(candidate);
        int accepted = 0;
        for (int index = 0; index < 17; index += 1)
        {
            accepted += sink.TrySend(CaptureId, raw) ? 1 : 0;
        }
        Check(accepted == 16, "The bounded queue did not admit exactly 16.");
        Check(sink.RecallCounters.CandidateQueueFull == 1,
            "The queue bound was not counted.");
        client.Release.Set();
        Check(sink.WaitUntilIdle(TimeSpan.FromSeconds(30)),
            "The bounded queue did not drain.");
        SdkRecallCounters counters = sink.RecallCounters;
        ulong terminal = counters.CandidateRejected +
            counters.CandidateDeliveryExpired + counters.CandidateIncomplete +
            counters.CandidateDurablyAccepted;
        Check(terminal == 16 && counters.CandidateDurablyAccepted == 0 &&
            sink.QueuedBytes == 0,
            "The drained queue outcomes are inconsistent.");
    }

    private static void DeliveryExpiry()
    {
        using ManagedTestStateRoot stateRoot = new();
        StubRegistrationClient client = new();
        client.Release.Set();
        DotnetSubjectPackage subject = SharedSubject();
        JsonObject world = EmptyWorld();
        ManagedCandidateSink sink = new(
            client,
            new ManagedCaptureClosure([], "return", world),
            Configuration(stateRoot.Path),
            subject: subject)
        {
            CandidateDeliveryLifetime = TimeSpan.Zero,
        };
        JsonObject deployment = BoundDeployment(subject);
        sink.BindDeployment(deployment);
        JsonObject candidate =
            CapturedCandidate(deployment, ManagedProtocol.CanonicalDigest(world));
        Check(sink.TrySend(CaptureId, CanonicalJson.Bytes(candidate)),
            "The expiring candidate was not queued.");
        Check(sink.WaitUntilIdle(TimeSpan.FromSeconds(10)),
            "The expiring candidate did not drain.");
        Check(
            sink.RecallCounters.CandidateDeliveryExpired == 1 && client.GrantCalls == 0,
            "The expired candidate was delivered instead of counted.");
    }
}
