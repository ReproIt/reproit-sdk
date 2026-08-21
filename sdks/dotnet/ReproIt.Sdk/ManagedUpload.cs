using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Holds one sealed upload request plus its private ciphertext spool.</summary>
public sealed class SealedManagedCandidate : IDisposable
{
    private readonly byte[] candidateKey;
    private readonly Dictionary<string, string> ciphertext;
    private readonly string spool;

    internal SealedManagedCandidate(
        JsonObject request,
        byte[] candidateKey,
        Dictionary<string, string> ciphertext,
        string spool)
    {
        Request = request;
        this.candidateKey = candidateKey;
        this.ciphertext = ciphertext;
        this.spool = spool;
    }

    /// <summary>Gets the validated managed candidate upload request.</summary>
    public JsonObject Request { get; }

    /// <summary>Returns the sorted sealed ciphertext digests.</summary>
    public List<string> CiphertextDigests() =>
        ciphertext.Keys.OrderBy(digest => digest, StringComparer.Ordinal).ToList();

    /// <summary>Returns the spool path of one ciphertext digest.</summary>
    public string? CiphertextPath(string digest) =>
        ciphertext.TryGetValue(digest, out string? path) ? path : null;

    /// <summary>Requests a fresh capture grant for the sealed candidate.</summary>
    public EncryptionResponse RequestCaptureGrantRenewal(
        IManagedGrantDelivery delivery,
        string deploymentDigest,
        string workloadKeyId,
        byte[] workloadSigningKey)
    {
        JsonObject identity = (JsonObject)Request["ciphertext_identity"]!;
        JsonObject request = new()
        {
            ["candidate_identity_digest"] =
                identity["candidate_identity_digest"]!.DeepClone(),
            ["capture_id"] = identity["capture_id"]!.DeepClone(),
            ["cipher_suite"] = ManagedProtocol.CipherSuite,
            ["deployment_digest"] = deploymentDigest,
            ["organization_id"] = identity["organization_id"]!.DeepClone(),
            ["processing_mode"] = "managed",
            ["project_id"] = identity["project_id"]!.DeepClone(),
            ["service_id"] = identity["service_id"]!.DeepClone(),
            ["signature"] = "",
            ["signer_key_id"] = workloadKeyId,
        };
        request["signature"] = ManagedProtocol.SignBytes(
            CanonicalJson.Bytes(request), workloadSigningKey);
        return delivery.RequestEncryptionGrant(
            request, PreparedManagedCandidate.GrantTimeout);
    }

    /// <summary>Applies a renewed grant that must keep the same key and reference.</summary>
    public void ApplyRenewedCaptureGrant(
        EncryptionResponse response,
        string now,
        string captureSignerId,
        byte[] captureSignerPublicKey)
    {
        JsonObject identity = (JsonObject)Request["ciphertext_identity"]!;
        if (!response.CandidateKey.AsSpan().SequenceEqual(candidateKey) ||
            ManagedProtocol.Text(response.CaptureGrant["candidate_key_reference"]) !=
                ManagedProtocol.Text(identity["candidate_key_reference"]))
        {
            throw new ManagedCaptureException(
                "CAPTURE_ID_CONFLICT",
                "The renewed managed capture grant does not match the live candidate key.");
        }
        ManagedProtocol.VerifyCaptureGrant(
            response.CaptureGrant,
            new JsonObject
            {
                ["candidate_identity_digest"] =
                    identity["candidate_identity_digest"]!.DeepClone(),
                ["candidate_key_reference"] =
                    identity["candidate_key_reference"]!.DeepClone(),
                ["capture_id"] = identity["capture_id"]!.DeepClone(),
                ["organization_id"] = identity["organization_id"]!.DeepClone(),
                ["project_id"] = identity["project_id"]!.DeepClone(),
                ["service_id"] = identity["service_id"]!.DeepClone(),
                ["signer_key_id"] = captureSignerId,
            },
            now,
            captureSignerPublicKey);
        Request["capture_grant"] = response.CaptureGrant.DeepClone();
        ManagedProtocol.ValidateUploadRequest(Request);
    }

    /// <summary>Drives the bounded start, missing, PUT, and commit session.</summary>
    public JsonObject Upload(IManagedIngressDelivery delivery)
    {
        JsonObject identity = (JsonObject)Request["ciphertext_identity"]!;
        TimeSpan commitTimeout = TimeSpan.FromSeconds(
            PreparedManagedCandidate.CommitTimeoutSeconds(
                ManagedProtocol.Count(identity["total_ciphertext_bytes"])!.Value));
        JsonObject start =
            delivery.Start(Request, PreparedManagedCandidate.GrantTimeout);
        string uploadId = ManagedProtocol.Text(start["upload_id"])!;
        string uploadToken = ManagedProtocol.Text(start["upload_token"])!;
        if (ManagedProtocol.Text(start["state"]) == "COMMITTED")
        {
            return VerifiedCommit(delivery.Commit(uploadId, uploadToken, commitTimeout));
        }
        if (ManagedProtocol.Text(start["state"]) is not ("OPEN" or "UPLOADING"))
        {
            throw PreparedManagedCandidate.UploadStateError();
        }
        try
        {
            UploadMissing(delivery, start);
        }
        catch (ManagedCaptureException)
        {
            CancelQuietly(delivery, uploadId, uploadToken);
            throw;
        }
        JsonObject commit;
        try
        {
            commit = delivery.Commit(uploadId, uploadToken, commitTimeout);
        }
        catch (ManagedCaptureException)
        {
            CancelQuietly(delivery, uploadId, uploadToken);
            throw;
        }
        return VerifiedCommit(commit);
    }

    /// <summary>Removes the private ciphertext spool.</summary>
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

    private JsonObject VerifiedCommit(JsonObject commit)
    {
        JsonObject identity = (JsonObject)Request["ciphertext_identity"]!;
        JsonObject grant = (JsonObject)Request["capture_grant"]!;
        if (ManagedProtocol.Text(commit["capture_id"]) !=
                ManagedProtocol.Text(grant["capture_id"]) ||
            ManagedProtocol.Text(commit["candidate_identity_digest"]) !=
                ManagedProtocol.Text(identity["candidate_identity_digest"]) ||
            ManagedProtocol.Text(commit["candidate_key_reference"]) !=
                ManagedProtocol.Text(identity["candidate_key_reference"]) ||
            ManagedProtocol.Text(commit["encrypted_candidate_digest"]) !=
                ManagedProtocol.Text(Request["encrypted_candidate_digest"]) ||
            ManagedProtocol.Text(commit["state"]) != "CLOUD_PROTECTED")
        {
            throw PreparedManagedCandidate.UploadStateError();
        }
        return (JsonObject)commit.DeepClone();
    }

    private void UploadMissing(IManagedIngressDelivery delivery, JsonObject start)
    {
        JsonObject limits = (JsonObject)start["limits"]!;
        long? attempts = ManagedProtocol.Count(limits["object_attempts"]);
        JsonArray missingObjects = (JsonArray)start["missing_objects"]!.DeepClone();
        string? cursor = ManagedProtocol.Text(start["next_missing_cursor"]);
        string uploadId = ManagedProtocol.Text(start["upload_id"])!;
        string uploadToken = ManagedProtocol.Text(start["upload_token"])!;
        HashSet<string> seen = [];
        long maximumPages = (ciphertext.Count + 99) / 100 + 1;
        for (long page = 0; page < maximumPages; page += 1)
        {
            if (missingObjects.Count > 100)
            {
                throw PreparedManagedCandidate.UploadStateError();
            }
            foreach (JsonNode? missing in missingObjects)
            {
                string digest = ManagedProtocol.Text(missing!["cipher_digest"])!;
                if (!seen.Add(digest) || !ciphertext.ContainsKey(digest))
                {
                    throw PreparedManagedCandidate.UploadStateError();
                }
            }
            foreach (JsonNode? missing in missingObjects)
            {
                UploadOne(delivery, (JsonObject)missing!, attempts);
            }
            if (cursor is null)
            {
                return;
            }
            JsonObject next = delivery.Missing(
                uploadId, uploadToken, cursor, PreparedManagedCandidate.GrantTimeout);
            missingObjects = (JsonArray)next["missing_objects"]!.DeepClone();
            cursor = ManagedProtocol.Text(next["next_missing_cursor"]);
        }
        throw PreparedManagedCandidate.UploadStateError();
    }

    private void UploadOne(
        IManagedIngressDelivery delivery, JsonObject missing, long? attempts)
    {
        if (attempts is null or 0 or > 5)
        {
            throw PreparedManagedCandidate.UploadStateError();
        }
        string digest = ManagedProtocol.Text(missing["cipher_digest"])!;
        string path = ciphertext[digest];
        byte[] value;
        try
        {
            long length = new FileInfo(path).Length;
            if (length > ManagedProtocol.MaxChunkBytes + 28)
            {
                throw PreparedManagedCandidate.LocalStorageError();
            }
            value = File.ReadAllBytes(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw PreparedManagedCandidate.LocalStorageError();
        }
        if (ManagedProtocol.DigestBytes(value) != digest)
        {
            throw ManagedProtocol.ObjectDigestMismatch();
        }
        string uploadUrl = ManagedProtocol.Text(missing["upload_url"])!;
        ManagedCaptureException? lastError = null;
        for (long attempt = 0; attempt < attempts; attempt += 1)
        {
            try
            {
                delivery.UploadObject(
                    uploadUrl, digest, value, PreparedManagedCandidate.GrantTimeout);
                return;
            }
            catch (ManagedCaptureException error)
            {
                if (!error.Retryable)
                {
                    throw;
                }
                lastError = error;
            }
        }
        throw lastError ?? PreparedManagedCandidate.UploadStateError();
    }

    private static void CancelQuietly(
        IManagedIngressDelivery delivery, string uploadId, string uploadToken)
    {
        try
        {
            delivery.Cancel(uploadId, uploadToken, PreparedManagedCandidate.GrantTimeout);
        }
        catch (ManagedCaptureException)
        {
            // The cancel is best effort after a failed session.
        }
    }
}
