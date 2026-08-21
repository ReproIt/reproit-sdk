using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Encodes deterministic protocol JSON.</summary>
public static class CanonicalJson
{
    // Canonical protocol JSON uses minimal escaping: only the quotation
    // mark, the reverse solidus, and control characters below 0x20 are
    // escaped, and other text is raw UTF-8. Utf8JsonWriter's default
    // encoder escapes '+', '&', and non-ASCII text, which breaks the
    // cross-language canonical digests, so this writer encodes directly.
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Encodes one protocol value with ordered object properties.</summary>
    public static byte[] Bytes(JsonNode value)
    {
        MemoryStream buffer = new();
        Write(buffer, value);
        return buffer.ToArray();
    }

    private static void Write(MemoryStream buffer, JsonNode? value)
    {
        switch (value)
        {
            case null:
                buffer.Write("null"u8);
                break;
            case JsonObject item:
                buffer.WriteByte((byte)'{');
                bool firstProperty = true;
                foreach ((string name, JsonNode? child) in
                    item.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                {
                    if (!firstProperty)
                    {
                        buffer.WriteByte((byte)',');
                    }
                    firstProperty = false;
                    WriteString(buffer, name);
                    buffer.WriteByte((byte)':');
                    Write(buffer, child);
                }
                buffer.WriteByte((byte)'}');
                break;
            case JsonArray items:
                buffer.WriteByte((byte)'[');
                bool firstItem = true;
                foreach (JsonNode? child in items)
                {
                    if (!firstItem)
                    {
                        buffer.WriteByte((byte)',');
                    }
                    firstItem = false;
                    Write(buffer, child);
                }
                buffer.WriteByte((byte)']');
                break;
            case JsonValue item:
                WriteValue(buffer, item);
                break;
            default:
                throw new CaptureException(
                    "The protocol value has an unsupported type.");
        }
    }

    private static void WriteValue(MemoryStream buffer, JsonValue value)
    {
        switch (value.GetValueKind())
        {
            case JsonValueKind.String:
                WriteString(buffer, value.GetValue<string>());
                break;
            case JsonValueKind.True:
                buffer.Write("true"u8);
                break;
            case JsonValueKind.False:
                buffer.Write("false"u8);
                break;
            case JsonValueKind.Number:
                if (!long.TryParse(
                    value.ToJsonString(), NumberStyles.AllowLeadingSign,
                    CultureInfo.InvariantCulture, out long number))
                {
                    throw new CaptureException(
                        "The protocol value contains an invalid number.");
                }
                buffer.Write(Encoding.ASCII.GetBytes(
                    number.ToString(CultureInfo.InvariantCulture)));
                break;
            default:
                throw new CaptureException(
                    "The protocol value contains an invalid number.");
        }
    }

    private static void WriteString(MemoryStream buffer, string value)
    {
        buffer.WriteByte((byte)'"');
        int start = 0;
        for (int index = 0; index < value.Length; index += 1)
        {
            char character = value[index];
            if (character >= 0x20 && character != '"' && character != '\\')
            {
                continue;
            }
            WriteRaw(buffer, value, start, index);
            start = index + 1;
            switch (character)
            {
                case '"':
                    buffer.Write("\\\""u8);
                    break;
                case '\\':
                    buffer.Write("\\\\"u8);
                    break;
                case '\b':
                    buffer.Write("\\b"u8);
                    break;
                case '\t':
                    buffer.Write("\\t"u8);
                    break;
                case '\n':
                    buffer.Write("\\n"u8);
                    break;
                case '\f':
                    buffer.Write("\\f"u8);
                    break;
                case '\r':
                    buffer.Write("\\r"u8);
                    break;
                default:
                    buffer.Write(Encoding.ASCII.GetBytes(
                        $"\\u{(int)character:x4}"));
                    break;
            }
        }
        WriteRaw(buffer, value, start, value.Length);
        buffer.WriteByte((byte)'"');
    }

    private static void WriteRaw(MemoryStream buffer, string value, int start, int end)
    {
        if (end <= start)
        {
            return;
        }
        try
        {
            buffer.Write(StrictUtf8.GetBytes(value.Substring(start, end - start)));
        }
        catch (EncoderFallbackException)
        {
            throw new CaptureException("The protocol value has an unsupported type.");
        }
    }
}
