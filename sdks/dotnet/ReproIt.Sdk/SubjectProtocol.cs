using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal static class SubjectProtocol
{
    internal const string SubjectManifestMediaType =
        "application/vnd.reproit.subject-closure.v1+json";

    internal static string DigestBytes(ReadOnlySpan<byte> value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant()}";

    internal static string CanonicalDigest(JsonNode value) =>
        DigestBytes(CanonicalJson.Bytes(value));

    internal static bool HasExactly(JsonObject value, params string[] keys) =>
        value.Count == keys.Length && keys.All(value.ContainsKey);

    internal static string? Text(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    internal static long? Count(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.Number &&
        long.TryParse(
            value.ToJsonString(),
            NumberStyles.AllowLeadingSign,
            CultureInfo.InvariantCulture,
            out long number)
            ? number
            : null;

    internal static bool ValidCapability(JsonNode? value) =>
        Text(value) is string text && text.Length is > 0 and <= 128 &&
        text[0] is >= 'a' and <= 'z' &&
        text.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');

    internal static ManagedCaptureException SchemaInvalid(
        string message = "The value does not satisfy the schema.") =>
        new("SCHEMA_INVALID", message);
}
