using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using ReproIt.Sdk;
using static ReproIt.Sdk.Conformance.ManagedFixtures;

namespace ReproIt.Sdk.Conformance;

/// <summary>Runs the managed-mode vector, seal, and local-gate checks.</summary>
internal static class ManagedConformance
{
    internal static void Run()
    {
        VectorConformance();
        SealParity();
        // The managed workload key contract is a Unix file-mode contract, and
        // every managed execution host is a Unix host.
        if (OperatingSystem.IsLinux())
        {
            WorkloadKeyFile();
            WorkloadIdentityState();
        }
        else
        {
            throw new InvalidOperationException(
                "The managed workload key conformance requires a Unix host.");
        }
        CommitTimeout();
        OfficialManagedBindingsFailClosed();
        FrameworkNeutralOperationPreservesApplicationError();
        PrepareAndSeal();
        TransportValidation();
        Console.WriteLine("dotnet_managed_vectors=PASS");
        Console.WriteLine("dotnet_managed_seal=PASS");
        Console.WriteLine("dotnet_managed_workload_key=PASS");
        Console.WriteLine("dotnet_managed_transport=PASS");
    }

    private static void FrameworkNeutralOperationPreservesApplicationError()
    {
        ReproItCapture capture = ReproItCapture.Init();
        InvalidOperationException original = new("customer failure");
        try
        {
            _ = capture.Operation<int>(
                "todos.create", "input"u8.ToArray(), () => throw original);
            throw new InvalidOperationException(
                "The framework-neutral operation did not return the application error.");
        }
        catch (InvalidOperationException observed) when (ReferenceEquals(observed, original))
        {
        }
    }

    private static void OfficialManagedBindingsFailClosed()
    {
        RequireManagedFailure(
            () => OfficialManaged.Configuration(),
            "CONFIG_CONFLICT",
            "A workspace build accepted official managed release sentinels.");
        RequireManagedFailure(
            () => new OfficialManagedProject(new JsonObject(), "invalid", "invalid"),
            "CONFIG_CONFLICT",
            "The workspace official project reached project or capture validation.");
        int worldCalls = 0;
        RequireManagedFailure(
            () => new ReproItCapture(
                new JsonObject(), "invalid", "invalid",
                () =>
                {
                    worldCalls += 1;
                    throw new InvalidOperationException("The World provider must not run.");
                }),
            "CONFIG_CONFLICT",
            "The public integration accepted release sentinels.");
        Check(worldCalls == 0,
            "The unbound public integration called the World provider.");
        int tokenCalls = 0;
        JsonObject deployment = BoundDeployment(SharedSubject());
        deployment["runtime_endpoint"] = "unchanged";
        RequireManagedFailure(
            () => OfficialManaged.CandidateSink(
                new ManagedCaptureClosure([], "return", EmptyWorld()),
                deployment,
                () =>
                {
                    tokenCalls += 1;
                    return new ManagedProjectToken("must-not-be-read");
                },
                SharedSubject()),
            "CONFIG_CONFLICT",
            "The workspace official managed entry accepted release sentinels.");
        Check(tokenCalls == 0,
            "The unbound official managed entry read a project token.");
        Check(ManagedProtocol.Text(deployment["runtime_endpoint"]) == "unchanged",
            "The unbound official managed entry changed the caller deployment.");
    }

    private static void VectorConformance()
    {
        // The candidate identity digest matches the canonical vector.
        JsonObject identity = ProtocolPositive("managed_candidate_identity");
        ManagedProtocol.ValidateManagedCandidateIdentity(identity);
        Check(
            ManagedProtocol.CanonicalDigest(identity) ==
                CanonicalSha256("managed_candidate_identity"),
            "The managed candidate identity digest differs from the vector.");

        // The ciphertext identity digest binds the commit vector.
        JsonObject ciphertextIdentity =
            ProtocolPositive("managed_candidate_ciphertext_identity");
        ManagedProtocol.ValidateCiphertextIdentity(ciphertextIdentity);
        string ciphertextDigest = ManagedProtocol.CanonicalDigest(ciphertextIdentity);
        Check(
            ciphertextDigest ==
                CanonicalSha256("managed_candidate_ciphertext_identity"),
            "The ciphertext identity digest differs from the vector.");
        JsonObject commit = CloudPositive("managed_candidate_commit");
        Check(
            ciphertextDigest ==
                ManagedProtocol.Text(commit["encrypted_candidate_digest"]),
            "The ciphertext identity digest does not bind the commit vector.");

        // The capture grant verifies with the published key.
        JsonObject grant = ProtocolPositive("managed_candidate_capture_grant");
        byte[] publicKey = ManagedProtocol.DecodeBase64Url(
            ManagedProtocol.Text(ProtocolVectors()["verification_keys"]![
                "managed-candidate-capture-test"]), 32);
        JsonObject expectation = GrantExpectation(grant);
        ManagedProtocol.VerifyCaptureGrant(
            grant, expectation, GrantVerificationTime, publicKey);

        // Every capture grant negative vector is rejected with its code.
        List<JsonObject> mutations = ((JsonArray)ProtocolVectors()["negative"]!)
            .Where(entry => ManagedProtocol.Text(entry!["base"]) ==
                "managed_candidate_capture_grant")
            .Select(entry => (JsonObject)entry!)
            .ToList();
        Check(mutations.Count == 3,
            "The capture grant negative vector count changed.");
        foreach (JsonObject mutation in mutations)
        {
            JsonObject changed = ApplyMutation(grant, mutation);
            RequireManagedFailure(
                () => ManagedProtocol.VerifyCaptureGrant(
                    changed, expectation, GrantVerificationTime, publicKey),
                ManagedProtocol.Text(mutation["expected"])!,
                $"Negative vector {ManagedProtocol.Text(mutation["name"])} " +
                    "was not rejected correctly.");
        }

        // The upload request vector validates and its mutation is rejected.
        JsonObject uploadRequest = CloudPositive("managed_candidate_upload_request");
        ManagedProtocol.ValidateUploadRequest(uploadRequest);
        JsonObject keyMutation = ((JsonArray)CloudVectors()["negative"]!)
            .Select(entry => (JsonObject)entry!)
            .Single(entry => ManagedProtocol.Text(entry["name"]) ==
                "managed-candidate-key-reference-differs-from-capture-grant");
        RequireManagedFailure(
            () => ManagedProtocol.ValidateUploadRequest(
                ApplyMutation(uploadRequest, keyMutation)),
            "ATTESTATION_SCOPE",
            "The mismatched key reference was not rejected.");

        // The encryption response vector decodes.
        JsonObject response = CloudPositive("managed_candidate_encryption_response");
        Check(
            ManagedProtocol.HasExactly(response, "candidate_key", "capture_grant"),
            "The encryption response vector shape changed.");
        byte[] candidateKey = ManagedProtocol.DecodeBase64Url(
            ManagedProtocol.Text(response["candidate_key"]), 32);
        Check(candidateKey.Length == 32, "The candidate key must hold 32 bytes.");
        ManagedProtocol.ValidateCaptureGrant(response["capture_grant"]);
        JsonObject grantRequest =
            CloudPositive("managed_candidate_encryption_grant_request");
        Check(
            ManagedProtocol.Text(grantRequest["candidate_identity_digest"]) ==
                ManagedProtocol.Text(
                    response["capture_grant"]!["candidate_identity_digest"]),
            "The grant request does not bind the encryption response.");

        // The key context vectors match their canonical digests.
        foreach (string name in new[] { "object_key_context", "chunk_key_context" })
        {
            Check(
                ManagedProtocol.CanonicalDigest(ProtocolPositive(name)) ==
                    CanonicalSha256(name),
                $"The {name} digest differs from the vector.");
        }

        // Deterministic Ed25519 reproduces the Rust reference signature.
        Check(
            ManagedProtocol.EncodeBase64Url(
                ManagedProtocol.VerificationKey(CaptureSignerSeed)) ==
                ManagedProtocol.Text(ProtocolVectors()["verification_keys"]![
                    "managed-candidate-capture-test"]),
            "The Ed25519 verification key differs from the published key.");
        JsonObject unsigned = (JsonObject)grant.DeepClone();
        unsigned["signature"] = "";
        Check(
            ManagedProtocol.SignBytes(
                CanonicalJson.Bytes(unsigned), CaptureSignerSeed) ==
                ManagedProtocol.Text(grant["signature"]),
            "The Ed25519 signature differs from the Rust reference signature.");

        // The managed candidate manifest vector binds its identity.
        JsonObject manifest = ProtocolPositive("managed_candidate_manifest");
        ManagedProtocol.ValidateManagedCandidateIdentity(manifest["candidate_identity"]);
        Check(
            ManagedProtocol.CanonicalDigest(manifest["candidate_identity"]!) ==
                ManagedProtocol.Text(manifest["candidate_identity_digest"]) &&
            ManagedProtocol.CanonicalDigest(manifest) ==
                CanonicalSha256("managed_candidate_manifest"),
            "The managed candidate manifest vector does not bind its identity.");
    }

    private static JsonObject GrantExpectation(JsonObject grant) => new()
    {
        ["candidate_identity_digest"] = grant["candidate_identity_digest"]!.DeepClone(),
        ["candidate_key_reference"] = grant["candidate_key_reference"]!.DeepClone(),
        ["capture_id"] = grant["capture_id"]!.DeepClone(),
        ["organization_id"] = grant["organization_id"]!.DeepClone(),
        ["project_id"] = grant["project_id"]!.DeepClone(),
        ["service_id"] = grant["service_id"]!.DeepClone(),
        ["signer_key_id"] = grant["signer_key_id"]!.DeepClone(),
    };

    private static void SealParity()
    {
        // Pinned cross-implementation vector. The expected bytes were
        // produced by reproit-core (derive_object_key, derive_chunk_key,
        // encrypt_chunk) with these exact inputs, so this proves the
        // HKDF-SHA-256 and AES-256-GCM AAD contract byte for byte.
        JsonObject context = new()
        {
            ["capture_batch_format"] = "reproit.capture-batch.v1",
            ["capture_id"] = "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
            ["format"] = "reproit.object-key-context.v1",
            ["object_id"] = "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4",
            ["organization_id"] = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
            ["processing_mode"] = "managed",
            ["project_id"] = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
            ["role"] = "trigger",
            ["service_id"] = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf",
        };
        byte[] candidateKey = Repeat(0x42);
        byte[] plaintext = Encoding.ASCII.GetBytes(
            "cross-language managed seal vector");
        byte[] objectKey = ManagedProtocol.DeriveObjectKey(
            candidateKey, "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc", context);
        JsonObject chunkContext = ManagedProtocol.ChunkKeyContext(
            ManagedProtocol.CanonicalDigest(context), 1, 0, plaintext.Length);
        Check(
            ManagedProtocol.Text(chunkContext["object_context_digest"]) ==
                "sha256:06e6fa3d4a4185d0eff5cd92e01ed2d5aa3dc873f5b5cdead8313556855afa84",
            "The object context digest differs from the pinned constant.");
        byte[] chunkKey = ManagedProtocol.DeriveChunkKey(objectKey, chunkContext);
        byte[] nonce = new byte[12];
        Array.Fill(nonce, (byte)0x07);
        byte[] stored =
            ManagedProtocol.EncryptChunk(chunkKey, nonce, plaintext, chunkContext);
        Check(
            Convert.ToHexString(stored).ToLowerInvariant() ==
                "0707070707070707070707076feaeb515f76709f385b2542dff02ead97170a34" +
                "b32eba411bf935a7e778ce0dbb1b49d747d17d71f9b507a035d4647f312f",
            "The sealed chunk differs from the pinned cross-language ciphertext.");
        Check(
            ManagedProtocol.DecryptChunk(chunkKey, stored, chunkContext)
                .AsSpan().SequenceEqual(plaintext),
            "The sealed chunk did not decrypt back to the plaintext.");
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static void WorkloadKeyFile()
    {
        string directory = Directory
            .CreateTempSubdirectory("reproit-dotnet-workload-").FullName;
        try
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead |
                UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string path = Path.Combine(directory, "workload.key");

            // Create and reload round trip with mode 0600.
            byte[] key = ManagedIdentity.LoadOrCreateManagedWorkloadKey(path);
            Check(key.Length == 32, "The created workload key must hold 32 bytes.");
            Check(
                File.GetUnixFileMode(path) ==
                    (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                "The created workload key file is not mode 0600.");
            Check(
                ManagedIdentity.LoadOrCreateManagedWorkloadKey(path)
                    .AsSpan().SequenceEqual(key),
                "The reloaded workload key differs.");

            // A world-readable key is rejected.
            File.SetUnixFileMode(path, UnixFileMode.UserRead |
                UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            RequireManagedFailure(
                () => ManagedIdentity.LoadOrCreateManagedWorkloadKey(path),
                "CONFIG_CONFLICT", "The world-readable key was accepted.");
            File.Delete(path);

            // A symlink key is rejected.
            string target = Path.Combine(directory, "target.key");
            File.WriteAllBytes(target, new byte[32]);
            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.CreateSymbolicLink(path, target);
            RequireManagedFailure(
                () => ManagedIdentity.LoadOrCreateManagedWorkloadKey(path),
                "CONFIG_CONFLICT", "The symlink key was accepted.");
            File.Delete(path);

            // A wrong-size key is rejected.
            File.WriteAllBytes(path, new byte[16]);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            RequireManagedFailure(
                () => ManagedIdentity.LoadOrCreateManagedWorkloadKey(path),
                "CONFIG_CONFLICT", "The wrong-size key was accepted.");
            File.Delete(path);

            // A group-writable parent is rejected.
            File.SetUnixFileMode(directory, UnixFileMode.UserRead |
                UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute);
            RequireManagedFailure(
                () => ManagedIdentity.LoadOrCreateManagedWorkloadKey(path),
                "CONFIG_CONFLICT", "The group-writable parent was accepted.");
        }
        finally
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead |
                UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.Delete(directory, recursive: true);
        }
    }

    [SupportedOSPlatform("linux")]
    private static void WorkloadIdentityState()
    {
        string stateRoot = Directory
            .CreateTempSubdirectory("reproit-dotnet-workload-state-").FullName;
        try
        {
            File.SetUnixFileMode(stateRoot, UnixFileMode.UserRead |
                UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            JsonObject deployment = BoundDeployment(SharedSubject());
            string bindingDigest =
                ManagedCandidateSink.ManagedDeploymentBindingDigest(deployment);
            JsonObject changedSigningState = (JsonObject)deployment.DeepClone();
            changedSigningState["signed_at"] = "2026-02-01T00:00:00.000Z";
            changedSigningState["signer_key_id"] = "managed-workload-sha256:" +
                new string('a', 64);
            byte[] changedSignature = new byte[64];
            Array.Fill(changedSignature, (byte)0x55);
            changedSigningState["signature"] =
                ManagedProtocol.EncodeBase64Url(changedSignature);
            Check(
                ManagedCandidateSink.ManagedDeploymentBindingDigest(changedSigningState) ==
                    bindingDigest,
                "The stable Deployment binding includes mutable signing state.");
            changedSigningState["source_revision"] = "fedcba9876543210";
            Check(
                ManagedCandidateSink.ManagedDeploymentBindingDigest(changedSigningState) !=
                    bindingDigest,
                "The stable Deployment binding omitted the source revision.");

            ManagedWorkloadIdentityState state =
                ManagedWorkloadIdentityState.FromStateRoot(stateRoot, bindingDigest);
            byte[] key = state.LoadOrCreateKey();
            string signedAt = state.LoadOrCreateDeploymentSignedAt(
                bindingDigest, "2026-01-01T00:00:00.000Z");
            Check(
                state.LoadOrCreateKey().AsSpan().SequenceEqual(key) &&
                state.LoadOrCreateDeploymentSignedAt(
                    bindingDigest, "2026-02-01T00:00:00.000Z") == signedAt,
                "Restart changed protected workload signing state.");
            ManagedWorkloadRegistrationReceipt receipt = new(
                ManagedProtocol.CanonicalDigest(deployment),
                ServiceId,
                ManagedProtocol.WorkloadKeyId(ManagedProtocol.VerificationKey(key)));
            Check(!state.HasRegistrationReceipt(receipt),
                "A registration receipt existed before persistence.");
            state.PersistRegistrationReceipt(receipt);
            ManagedWorkloadIdentityState restarted =
                ManagedWorkloadIdentityState.FromStateRoot(stateRoot, bindingDigest);
            Check(restarted.HasRegistrationReceipt(receipt),
                "Restart did not reuse the protected registration receipt.");

            string receiptPath = Path.Combine(state.DirectoryPath, "registration.json");
            File.WriteAllBytes(receiptPath, new byte[513]);
            File.SetUnixFileMode(receiptPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
            RequireManagedFailure(
                () => restarted.HasRegistrationReceipt(receipt),
                "CONFIG_CONFLICT",
                "A registration receipt one byte above the bound was accepted.");
            File.WriteAllText(receiptPath, "{");
            File.SetUnixFileMode(receiptPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
            RequireManagedFailure(
                () => restarted.HasRegistrationReceipt(receipt),
                "CONFIG_CONFLICT",
                "A corrupt registration receipt was accepted.");
        }
        finally
        {
            Directory.Delete(stateRoot, recursive: true);
        }
    }

    private static void CommitTimeout()
    {
        Check(
            PreparedManagedCandidate.CommitTimeoutSeconds(0) == 5.0 &&
            PreparedManagedCandidate.CommitTimeoutSeconds(1) == 6.0 &&
            PreparedManagedCandidate.CommitTimeoutSeconds(4 * 1024 * 1024) == 6.0 &&
            PreparedManagedCandidate.CommitTimeoutSeconds(512L * 1024 * 1024) == 133.0 &&
            PreparedManagedCandidate.CommitTimeoutSeconds(long.MaxValue) == 180.0,
            "The commit timeout does not scale with the declared closure.");
    }

    private static void PrepareAndSeal()
    {
        DotnetSubjectPackage subject = SharedSubject();
        JsonObject world = EmptyWorld();
        string worldId = ManagedProtocol.CanonicalDigest(world);
        JsonObject deployment = BoundDeployment(subject);
        string deploymentDigest = ManagedProtocol.CanonicalDigest(deployment);
        JsonObject candidate = CapturedCandidate(deployment, worldId);

        FrozenManagedCaptureClosure Closure() => new(
            new ManagedCaptureClosure([], "return", (JsonObject)world.DeepClone()));
        PreparedManagedCandidate Prepared() => PreparedManagedCandidate.PrepareComplete(
            (JsonObject)candidate.DeepClone(), subject, Closure());
        EncryptionResponse Grant(
            PreparedManagedCandidate prepared, IManagedGrantDelivery delivery) =>
            prepared.RequestEncryptionGrant(
                delivery, deploymentDigest, WorkloadKeyId, WorkloadSeed);
        EncryptionResponse Renew(
            SealedManagedCandidate sealedCandidate, IManagedGrantDelivery delivery) =>
            sealedCandidate.RequestCaptureGrantRenewal(
                delivery, deploymentDigest, WorkloadKeyId, WorkloadSeed);
        SealedManagedCandidate Sealed(GrantDeliverySpy? delivery = null)
        {
            delivery ??= new GrantDeliverySpy();
            PreparedManagedCandidate prepared = Prepared();
            EncryptionResponse response = Grant(prepared, delivery);
            return prepared.Seal(
                response, GrantVerificationTime, CaptureSignerId,
                ManagedProtocol.VerificationKey(CaptureSignerSeed));
        }

        // The key request occurs only after the exact local closure. An
        // incomplete candidate stops before any request on the spy.
        GrantDeliverySpy spy = new();
        JsonObject incompleteWorld = (JsonObject)candidate.DeepClone();
        incompleteWorld["world_id"] = "sha256:" + new string('a', 64);
        RequireManagedFailure(
            () => PreparedManagedCandidate.PrepareComplete(
                incompleteWorld, subject, Closure()),
            "INCOMPLETE_CANDIDATE", "The mismatched world was accepted.");
        Check(spy.Calls.Count == 0,
            "An incomplete candidate reached the grant delivery.");

        JsonObject incompleteRecords = (JsonObject)candidate.DeepClone();
        ((JsonArray)incompleteRecords["records"]!).RemoveAt(
            ((JsonArray)incompleteRecords["records"]!).Count - 1);
        RequireManagedFailure(
            () => PreparedManagedCandidate.PrepareComplete(
                incompleteRecords, subject, Closure()),
            "INCOMPLETE_CANDIDATE", "The incomplete record sequence was accepted.");
        Check(spy.Calls.Count == 0,
            "An incomplete record sequence reached the grant delivery.");

        PreparedManagedCandidate prepared = Prepared();
        Grant(prepared, spy);
        Check(spy.Calls.Count == 1 &&
            ManagedProtocol.Text(spy.Calls[0]["candidate_identity_digest"]) ==
                ManagedProtocol.CanonicalDigest(prepared.Identity) &&
            ManagedProtocol.Text(spy.Calls[0]["processing_mode"]) == "managed",
            "The grant request does not bind the proved identity.");
        Check(
            ManagedProtocol.Text(spy.Calls[0]["deployment_digest"]) ==
                deploymentDigest &&
            ManagedProtocol.Text(spy.Calls[0]["signer_key_id"]) == WorkloadKeyId,
            "The grant request does not bind the signed deployment.");
        ManagedProtocol.VerifySignedValue(
            spy.Calls[0], ManagedProtocol.VerificationKey(WorkloadSeed));

        // Seal round trip and key secrecy.
        using (SealedManagedCandidate sealedCandidate = Sealed())
        {
            foreach (string digest in sealedCandidate.CiphertextDigests())
            {
                Check(
                    ManagedProtocol.DigestBytes(File.ReadAllBytes(
                        sealedCandidate.CiphertextPath(digest)!)) == digest,
                    "A sealed object does not match its bound ciphertext digest.");
            }
            Dictionary<string, byte[]> recovered =
                OpenSealedObjectBytes(sealedCandidate, CandidateKey);
            JsonObject identity =
                (JsonObject)sealedCandidate.Request["ciphertext_identity"]!;
            JsonObject candidateObject = ((JsonArray)identity["objects"]!)
                .Select(entry => (JsonObject)entry!["descriptor"]!)
                .Single(descriptor => ManagedProtocol.Text(descriptor["media_type"]) ==
                    ManagedProtocol.CandidateMediaType);
            byte[] recoveredCandidate =
                recovered[ManagedProtocol.Text(candidateObject["object_id"])!];
            Check(
                recoveredCandidate.AsSpan()
                    .SequenceEqual(CanonicalJson.Bytes(candidate)),
                "The sealed candidate record does not decrypt to the candidate.");
            JsonObject sealedManifest =
                OpenSealedManifest(sealedCandidate, CandidateKey);
            Check(
                ManagedProtocol.Text(sealedManifest["candidate_identity_digest"]) ==
                    ManagedProtocol.Text(identity["candidate_identity_digest"]) &&
                ManagedProtocol.Text(sealedManifest["candidate_key_reference"]) ==
                    ManagedProtocol.Text(identity["candidate_key_reference"]),
                "The sealed manifest does not bind the ciphertext identity.");
            string requestText =
                Encoding.UTF8.GetString(CanonicalJson.Bytes(sealedCandidate.Request));
            Check(
                !requestText.Contains(ManagedProtocol.EncodeBase64Url(CandidateKey)),
                "The upload request leaks the candidate key.");
            CheckThrows<ManagedCaptureException>(
                () => OpenSealedObjectBytes(sealedCandidate, Repeat(0x43)),
                "A wrong candidate key decrypted a sealed object.");

            // A valid renewal is accepted, then the session succeeds.
            EncryptionResponse renewal = Renew(
                sealedCandidate, new GrantDeliverySpy());
            sealedCandidate.ApplyRenewedCaptureGrant(
                renewal, GrantVerificationTime, CaptureSignerId,
                ManagedProtocol.VerificationKey(CaptureSignerSeed));
            ManagedProtocol.ValidateUploadRequest(sealedCandidate.Request);

            RecordingIngress ingress = new();
            JsonObject sessionCommit = sealedCandidate.Upload(ingress);
            Check(
                ManagedProtocol.Text(sessionCommit["state"]) == "CLOUD_PROTECTED",
                "The upload session did not reach CLOUD_PROTECTED.");
            Check(
                ingress.UploadedDigests.SetEquals(sealedCandidate.CiphertextDigests()) &&
                ingress.Sequence[0] == "start" && ingress.Sequence[^1] == "commit" &&
                ingress.Sequence.Count(step => step == "upload_object") ==
                    ingress.ExpectedDigests.Count &&
                !ingress.Sequence.Contains("cancel"),
                "The upload session order changed.");
        }

        // The seal rejects an identity digest mismatch.
        PreparedManagedCandidate tamperTarget = Prepared();
        GrantDeliverySpy grantSpy = new();
        Grant(tamperTarget, grantSpy);
        JsonObject tamperedRequest = (JsonObject)grantSpy.Calls[0].DeepClone();
        tamperedRequest["candidate_identity_digest"] = "sha256:" + new string('9', 64);
        EncryptionResponse tamperedResponse = new GrantDeliverySpy()
            .RequestEncryptionGrant(tamperedRequest, TimeSpan.FromSeconds(5));
        RequireManagedFailure(
            () => tamperTarget.Seal(
                tamperedResponse, GrantVerificationTime, CaptureSignerId,
                ManagedProtocol.VerificationKey(CaptureSignerSeed)),
            "ATTESTATION_SCOPE", "The tampered identity digest was accepted.");

        // A renewal cannot rotate the key or the key reference.
        using (SealedManagedCandidate sealedCandidate = Sealed())
        {
            RecordingIngress ingress = new();
            EncryptionResponse rotatedKey = Renew(
                sealedCandidate,
                new GrantDeliverySpy(candidateKey: Repeat(0x43)));
            RequireManagedFailure(
                () => sealedCandidate.ApplyRenewedCaptureGrant(
                    rotatedKey, GrantVerificationTime, CaptureSignerId,
                    ManagedProtocol.VerificationKey(CaptureSignerSeed)),
                "CAPTURE_ID_CONFLICT", "A rotated candidate key was accepted.");
            EncryptionResponse rotatedReference = Renew(
                sealedCandidate,
                new GrantDeliverySpy(
                    keyReference: ManagedProtocol.EncodeBase64Url(Repeat(0x96))));
            RequireManagedFailure(
                () => sealedCandidate.ApplyRenewedCaptureGrant(
                    rotatedReference, GrantVerificationTime, CaptureSignerId,
                    ManagedProtocol.VerificationKey(CaptureSignerSeed)),
                "CAPTURE_ID_CONFLICT", "A rotated key reference was accepted.");
            Check(ingress.Sequence.Count == 0,
                "A rejected renewal reached the ingress.");
        }

        // The session cancels on failure and never commits after one.
        using (SealedManagedCandidate sealedCandidate = Sealed())
        {
            RecordingIngress failingUploads = new(failObjectUploads: true);
            CheckThrows<ManagedCaptureException>(
                () => sealedCandidate.Upload(failingUploads),
                "A failed object upload did not fail the session.");
            Check(
                failingUploads.Sequence.Contains("cancel") &&
                !failingUploads.Sequence.Contains("commit"),
                "The failed upload session did not cancel before commit.");
            RecordingIngress failingCommit = new(failCommit: true);
            CheckThrows<ManagedCaptureException>(
                () => sealedCandidate.Upload(failingCommit),
                "A failed commit did not fail the session.");
            Check(failingCommit.Sequence[^1] == "cancel",
                "The failed commit was not followed by a cancel.");
        }
    }

    private static void TransportValidation()
    {
        // Project token rules.
        _ = new ManagedProjectToken("a-valid-token");
        foreach (string invalid in new[]
        {
            "", "with space", "control", new string('x', 1_025),
        })
        {
            CheckThrows<ManagedCaptureException>(
                () => _ = new ManagedProjectToken(invalid),
                "An invalid project token was accepted.");
        }

        // The endpoint accepts a valid CA and rejects invalid CA files.
        string directory = Directory
            .CreateTempSubdirectory("reproit-dotnet-transport-").FullName;
        try
        {
            string valid = Path.Combine(directory, "valid.pem");
            File.WriteAllText(valid, SelfSignedCaPem());
            _ = new ManagedTlsEndpoint(
                "127.0.0.1", 443, "managed.reproit.example",
                "managed.reproit.example", valid);
            string empty = Path.Combine(directory, "empty.pem");
            File.WriteAllBytes(empty, []);
            string garbage = Path.Combine(directory, "garbage.pem");
            File.WriteAllText(garbage, "not a certificate");
            string linked = Path.Combine(directory, "linked.pem");
            File.CreateSymbolicLink(linked, valid);
            foreach (string path in new[]
            {
                empty, garbage, linked, Path.Combine(directory, "absent"),
            })
            {
                CheckThrows<ManagedCaptureException>(
                    () => _ = new ManagedTlsEndpoint(
                        "127.0.0.1", 443, "example", "example", path),
                    $"An invalid CA file was accepted: {path}");
            }

            // Invalid authorities are rejected.
            foreach (string authority in new[]
            {
                "", "bad/authority", "user@host", "with space", new string('x', 513),
            })
            {
                CheckThrows<ManagedCaptureException>(
                    () => _ = new ManagedTlsEndpoint(
                        "127.0.0.1", 443, "example", authority, valid),
                    "An invalid authority was accepted.");
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

        // The bounded response reader rejects invalid responses.
        foreach (byte[] raw in new[]
        {
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
            Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n"),
            Encoding.ASCII.GetBytes("garbage without terminator"),
        })
        {
            using MemoryStream connection = new(raw);
            CheckThrows<ManagedCaptureException>(
                () => ManagedTlsEndpoint.ReadResponse(connection),
                "An invalid response was accepted.");
        }

        // The reader accepts a bounded empty body.
        using MemoryStream bounded = new(Encoding.ASCII.GetBytes(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"));
        ManagedHttpResponse response = ManagedTlsEndpoint.ReadResponse(bounded);
        Check(response.Status == 204 && response.Body.Length == 0,
            "The bounded empty response was not accepted.");
    }

    private static string SelfSignedCaPem()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(
            "CN=reproit-managed-test-ca", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.ExportCertificatePem();
    }
}
