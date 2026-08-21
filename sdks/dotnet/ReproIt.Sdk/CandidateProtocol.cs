using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal static class CandidateProtocol
{
    internal static bool UsesMode(
        ReadOnlySpan<byte> candidateBytes,
        string captureId,
        string processingMode)
    {
        try
        {
            JsonNode candidate = JsonNode.Parse(candidateBytes) ?? throw Incomplete();
            if (!CanonicalJson.Bytes(candidate).AsSpan().SequenceEqual(candidateBytes))
            {
                return false;
            }
            Validate(candidate);
            return candidate["capture_id"]!.GetValue<string>() == captureId &&
                candidate["processing_mode"]!.GetValue<string>() == processingMode;
        }
        catch (Exception error) when (error is CaptureException or JsonException or
            InvalidOperationException)
        {
            return false;
        }
    }

    internal static void Validate(JsonNode candidate)
    {
        try
        {
            JsonObject root = candidate.AsObject();
            JsonObject deployment = root["deployment"]!.AsObject();
            JsonObject failure = root["failure"]!.AsObject();
            JsonArray records = root["records"]!.AsArray();
            Require(root.Count == 8 && records.Count >= 3 &&
                root["format"]!.GetValue<string>() == "reproit.candidate.v1" &&
                ValidPrefixedUuid7(root["capture_id"]!.GetValue<string>(), "cap_") &&
                ValidPrefixedUuid7(root["operation_id"]!.GetValue<string>(), "op_") &&
                ValidDigest(root["world_id"]!.GetValue<string>()) &&
                root["processing_mode"]!.GetValue<string>() ==
                    deployment["processing_mode"]!.GetValue<string>());

            List<JsonObject> payloads = new(records.Count);
            int failures = 0;
            for (int index = 0; index < records.Count; index += 1)
            {
                JsonObject record = records[index]!.AsObject();
                Require(record.Count == 3 && record["sequence"]!.GetValue<int>() == index);
                payloads.Add(DecodePayload(record));
                failures += record["kind"]!.GetValue<string>() == "failure" ? 1 : 0;
            }
            Require(failures == 1 && records[0]!["kind"]!.GetValue<string>() == "begin" &&
                records[^2]!["kind"]!.GetValue<string>() == "failure" &&
                records[^1]!["kind"]!.GetValue<string>() == "terminal");

            JsonObject begin = payloads[0];
            JsonObject failurePayload = payloads[^2];
            JsonObject identity = failurePayload["identity"]!.AsObject();
            JsonObject terminal = payloads[^1];
            Require(ValidBegin(begin) && terminal.Count == 3 &&
                terminal["complete"]!.GetValue<bool>() &&
                terminal["event_count"]!.GetValue<int>() == records.Count - 1 &&
                terminal["format"]!.GetValue<string>() == "reproit.terminal.v1" &&
                begin["operation_kind"]!.GetValue<string>() ==
                    identity["operation_kind"]!.GetValue<string>() &&
                begin["operation_name"]!.GetValue<string>() ==
                    identity["operation_name"]!.GetValue<string>() &&
                ValidOperationKind(identity["operation_kind"]!.GetValue<string>()) &&
                ValidText(identity["operation_name"]!.GetValue<string>(), 128) &&
                failurePayload.Count == 3 &&
                failurePayload["format"]!.GetValue<string>() == "reproit.failure-payload.v1" &&
                Equal(failurePayload["failure"]!, failure) &&
                Digest(CanonicalJson.Bytes(identity)) == failure["identity"]!.GetValue<string>());

            int inputIndex = 0;
            for (int index = 0; index < records.Count; index += 1)
            {
                string kind = records[index]!["kind"]!.GetValue<string>();
                JsonObject payload = payloads[index];
                switch (kind)
                {
                    case "begin":
                        Require(index == 0);
                        break;
                    case "input":
                        Require(ValidInput(payload, inputIndex));
                        inputIndex += 1;
                        break;
                    case "dependency":
                        Require(ValidDependency(payload));
                        break;
                    case "failure":
                        Require(index == records.Count - 2);
                        break;
                    case "terminal":
                        Require(index == records.Count - 1);
                        break;
                    default:
                        throw Incomplete();
                }
            }
        }
        catch (Exception error) when (error is InvalidOperationException or
            FormatException or JsonException or KeyNotFoundException or
            NullReferenceException or ArgumentOutOfRangeException)
        {
            throw Incomplete();
        }
    }

    internal static bool ValidDigest(string value) =>
        value.Length == 71 && value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value.AsSpan(7).IndexOfAnyExcept("0123456789abcdef") < 0;

    internal static bool ValidPrefixedUuid7(string value, string prefix)
    {
        if (value.Length != prefix.Length + 36 ||
            !value.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }
        ReadOnlySpan<char> uuid = value.AsSpan(prefix.Length);
        for (int index = 0; index < uuid.Length; index += 1)
        {
            if (index is 8 or 13 or 18 or 23)
            {
                if (uuid[index] != '-') return false;
                continue;
            }
            if (index == 14 && uuid[index] != '7') return false;
            if (index == 19 && "89ab".AsSpan().IndexOf(uuid[index]) < 0) return false;
            if (index is not (14 or 19) && "0123456789abcdef".AsSpan().IndexOf(uuid[index]) < 0)
            {
                return false;
            }
        }
        return true;
    }

    private static JsonObject DecodePayload(JsonObject record)
    {
        string encoded = record["payload"]!.GetValue<string>();
        Require(encoded.Length <= 87_382 && encoded.IndexOf('=') < 0 &&
            encoded.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        string padded = encoded.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        byte[] bytes = Convert.FromBase64String(padded);
        Require(bytes.Length <= Sdk.MaxEventBytes);
        JsonObject payload = JsonNode.Parse(bytes)!.AsObject();
        Require(CanonicalJson.Bytes(payload).AsSpan().SequenceEqual(bytes));
        return payload;
    }

    private static bool ValidBegin(JsonObject value)
    {
        if (value.Count != 6 ||
            value["format"]!.GetValue<string>() != "reproit.operation-begin.v1" ||
            !ValidAdapter(value["adapter_id"]!.GetValue<string>()) ||
            !ValidText(value["adapter_version"]!.GetValue<string>(), 64) ||
            !ValidOperationKind(value["operation_kind"]!.GetValue<string>()) ||
            !ValidText(value["operation_name"]!.GetValue<string>(), 128))
        {
            return false;
        }
        JsonArray parents = value["causal_parent_ids"]!.AsArray();
        return parents.Count <= 32 &&
            parents.Select(parent => parent!.GetValue<string>()).Distinct().Count() ==
                parents.Count &&
            parents.All(parent =>
                ValidPrefixedUuid7(parent!.GetValue<string>(), "op_"));
    }

    private static bool ValidInput(JsonObject value, int expectedIndex)
    {
        if (value.Count != 6 ||
            value["format"]!.GetValue<string>() != "reproit.operation-input.v1" ||
            value["input_index"]!.GetValue<int>() != expectedIndex ||
            value["channel"]!.GetValue<string>() is not ("control" or "input" or "metadata") ||
            !ValidText(value["content_type"]!.GetValue<string>(), 128))
        {
            return false;
        }
        byte[] bytes = DecodeBase64Url(value["value"]!.GetValue<string>());
        return Digest(bytes) == value["value_digest"]!.GetValue<string>();
    }

    private static bool ValidDependency(JsonObject value)
    {
        if (value.Count != 6 ||
            value["format"]!.GetValue<string>() != "reproit.dependency-cursor.v1" ||
            !ValidAdapter(value["adapter_id"]!.GetValue<string>()) ||
            !ValidText(value["adapter_version"]!.GetValue<string>(), 64) ||
            !ValidDigest(value["cursor_digest"]!.GetValue<string>()))
        {
            return false;
        }
        string cursor = value["cursor"]!.GetValue<string>();
        _ = DecodeBase64Url(cursor);
        JsonNode? parent = value["causal_parent_id"];
        return cursor.Length is >= 1 and <= 16_384 &&
            (parent is null || ValidPrefixedUuid7(parent.GetValue<string>(), "op_"));
    }

    private static byte[] DecodeBase64Url(string value)
    {
        Require(value.IndexOf('=') < 0 &&
            value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static bool ValidAdapter(string value) => ValidText(value, 128) &&
        value[0] is >= 'a' and <= 'z' &&
        value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');

    private static bool ValidOperationKind(string value) =>
        value is "request-response" or "stream" or "delivered-work";

    private static bool ValidText(string value, int maximum) => value.Length is > 0 &&
        value.Length <= maximum;

    private static bool Equal(JsonNode left, JsonNode right) =>
        CanonicalJson.Bytes(left).AsSpan().SequenceEqual(CanonicalJson.Bytes(right));

    private static string Digest(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    private static void Require(bool condition)
    {
        if (!condition) throw Incomplete();
    }

    private static CaptureException Incomplete() =>
        new("The operation does not have complete capture state.");
}

internal sealed class DiscardCandidateSink : ICandidateSink
{
    public int QueuedBytes => 0;
    public bool AllowsProcessingMode(string mode) => mode is "managed" or "private";
    public bool TrySend(string captureId, ReadOnlyMemory<byte> candidate) => false;
}
