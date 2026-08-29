using System.Text.Json;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class DistributedFuzzConformance
{
    internal static void Run()
    {
        using JsonDocument vector = JsonDocument.Parse(File.ReadAllBytes(VectorPath()));
        JsonElement root = vector.RootElement;
        JsonElement expected = root.GetProperty("expected");
        string encoded = root.GetProperty("encoded_context").GetString()!;
        string now = root.GetProperty("now").GetString()!;
        string parent = root.GetProperty("parent_operation_id").GetString()!;
        FuzzContextValidator validator = new(
            expected.GetProperty("project_id").GetString()!,
            root.GetProperty("verification_key").GetString()!);
        FuzzCampaignContext context = DistributedFuzz.ExtractHttp(
            new Dictionary<string, string>
            {
                [DistributedFuzz.ContextHttpHeader] = encoded,
                [DistributedFuzz.ParentHttpHeader] = parent,
            },
            validator,
            now) ?? throw Failure("The shared HTTP fuzz context was absent.");
        Require(
            context.CampaignId == expected.GetProperty("campaign_id").GetString() &&
            context.CaseId == expected.GetProperty("case_id").GetString() &&
            context.ContextDigest == expected.GetProperty("context_digest").GetString(),
            "The .NET fuzz context did not match the shared vector.");

        Dictionary<string, string> metadata = [];
        using (context.Activate())
        {
            DistributedFuzz.PropagateQueue(metadata);
        }
        Require(
            metadata[DistributedFuzz.ContextQueueMetadata] == encoded &&
            metadata[DistributedFuzz.ParentQueueMetadata] == parent,
            "The .NET queue metadata did not preserve the fuzz context.");
        FuzzCampaignContext queueContext = DistributedFuzz.ExtractQueue(
            metadata,
            validator,
            now) ?? throw Failure("The shared queue fuzz context was absent.");
        Require(
            queueContext.CampaignId == context.CampaignId &&
            queueContext.CaseId == context.CaseId &&
            queueContext.ContextDigest == context.ContextDigest &&
            queueContext.ParentOperationId == context.ParentOperationId,
            "The .NET queue context did not match the shared HTTP context.");

        FuzzContextValidator wrongScope = new(
            "prj_01890f3e-7b21-7cc0-8a1b-123456789abc",
            root.GetProperty("verification_key").GetString()!);
        RequireRejected(() => wrongScope.Validate(encoded, now));
        RequireRejected(() => validator.Validate(encoded, "2026-08-30T00:00:00.000Z"));
    }

    private static string VectorPath()
    {
        string root = Directory.GetCurrentDirectory();
        string direct = Path.Combine(
            root,
            "conformance",
            "distributed-fuzz-context-vectors.json");
        if (File.Exists(direct))
        {
            return direct;
        }
        string fromProject = Path.GetFullPath(Path.Combine(
            root,
            "..",
            "..",
            "conformance",
            "distributed-fuzz-context-vectors.json"));
        return File.Exists(fromProject)
            ? fromProject
            : throw Failure("The distributed fuzz context vector is unavailable.");
    }

    private static void RequireRejected(Action operation)
    {
        try
        {
            operation();
        }
        catch (FuzzContextException)
        {
            return;
        }
        throw Failure("The .NET SDK accepted an invalid fuzz context.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw Failure(message);
        }
    }

    private static InvalidOperationException Failure(string message) => new(message);
}
