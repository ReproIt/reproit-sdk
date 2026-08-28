using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal sealed record SemanticDependencyMetadata(byte[] Name, byte[] Value);

internal sealed record SemanticDependencyRequest(
    string Encoding,
    IReadOnlyList<SemanticDependencyMetadata> Metadata,
    string? Method,
    AutomaticObservationClass ObservationClass,
    string Operation,
    byte[] Payload,
    string Protocol,
    string Target);

internal sealed record SemanticDependencyResponse(
    string? ErrorCode,
    uint? ErrorNumber,
    IReadOnlyList<SemanticDependencyMetadata> Metadata,
    ObservationOutcome Outcome,
    byte[]? Payload,
    string? Status,
    ushort? StatusCode);

internal sealed record SemanticDependencyLiveResult(
    SemanticDependencyResponse Response,
    Exception? Error);

internal sealed class SdkEngineDependencyConnection(
    SdkEngineBridge bridge,
    SdkEngineDependencyStart start)
{
    internal string Action => start.Action;

    internal void Abandon()
    {
        try
        {
            bridge.AbandonObservation(new SdkEngineObservationHandle(start.Handle.Value));
        }
        catch (Exception)
        {
            // Capture cleanup must not change application behavior.
        }
    }

    internal SdkEngineObservationChunk Read() =>
        bridge.ReadObservation(new SdkEngineObservationHandle(start.Handle.Value));

    internal string Finish(JsonObject? response) =>
        bridge.FinishDependency(start.Handle, response);
}

internal static class SemanticDependencyTranslator
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static SemanticDependencyResponse Translate(
        AutomaticOperation operation,
        SemanticDependencyRequest request,
        string? causalParentId,
        Func<SemanticDependencyLiveResult> live)
    {
        JsonObject requestInput;
        try
        {
            requestInput = MakeRequest(request);
        }
        catch (Exception)
        {
            return ReturnLive(live());
        }
        SdkEngineDependencyConnection connection;
        try
        {
            connection = operation.OpenSemanticDependency(requestInput, causalParentId);
        }
        catch (Exception)
        {
            return ReturnLive(live());
        }
        bool finished = false;
        try
        {
            if (connection.Action == "capture")
            {
                SemanticDependencyLiveResult result = live();
                try
                {
                    _ = connection.Finish(MakeResponse(result.Response));
                    finished = true;
                }
                catch (Exception)
                {
                    // Capture failure must not change the live dependency result.
                }
                return ReturnLive(result);
            }
            byte[] record = ReadReplayResponse(connection);
            string validatedOutcome;
            try
            {
                validatedOutcome = connection.Finish(null);
            }
            catch (Exception)
            {
                throw AutomaticProject.CaptureError();
            }
            SemanticDependencyResponse response = ReconstructResponse(
                record, validatedOutcome);
            finished = true;
            return response;
        }
        finally
        {
            if (!finished)
            {
                connection.Abandon();
            }
        }
    }

    internal static JsonObject MakeRequest(SemanticDependencyRequest request)
    {
        int rawBytes = CheckedBytes(
            StrictUtf8.GetByteCount(request.Encoding),
            request.Payload.Length,
            StrictUtf8.GetByteCount(request.Operation),
            StrictUtf8.GetByteCount(request.Protocol),
            StrictUtf8.GetByteCount(request.Target));
        if (rawBytes > SdkEngineBridge.MaxCallBytes)
        {
            throw AutomaticProject.CaptureError();
        }
        return new JsonObject
        {
            ["encoding"] = request.Encoding,
            ["metadata"] = MakeMetadata(request.Metadata),
            ["method"] = request.Method,
            ["observation_class"] = AutomaticOperation.ObservationClass(
                request.ObservationClass),
            ["operation"] = request.Operation,
            ["payload"] = EncodeBase64Url(request.Payload),
            ["protocol"] = request.Protocol,
            ["target"] = EncodeBase64Url(StrictUtf8.GetBytes(request.Target)),
        };
    }

    internal static JsonObject MakeResponse(SemanticDependencyResponse response)
    {
        if (response.Payload is not null && response.Payload.Length > SdkEngineBridge.MaxCallBytes)
        {
            throw AutomaticProject.CaptureError();
        }
        return new JsonObject
        {
            ["error_code"] = response.ErrorCode,
            ["error_number"] = response.ErrorNumber,
            ["metadata"] = MakeMetadata(response.Metadata),
            ["outcome"] = Outcome(response.Outcome),
            ["payload"] = response.Payload is null ? null : EncodeBase64Url(response.Payload),
            ["status"] = response.Status,
            ["status_code"] = response.StatusCode,
        };
    }

    private static JsonArray MakeMetadata(IReadOnlyList<SemanticDependencyMetadata> metadata)
    {
        if (metadata.Count > SdkEngineBridge.MaxCallBytes)
        {
            throw AutomaticProject.CaptureError();
        }
        int rawBytes = 0;
        JsonArray result = [];
        foreach (SemanticDependencyMetadata field in metadata)
        {
            rawBytes = CheckedBytes(rawBytes, field.Name.Length, field.Value.Length);
            if (rawBytes > SdkEngineBridge.MaxCallBytes)
            {
                throw AutomaticProject.CaptureError();
            }
            result.Add(new JsonObject
            {
                ["name"] = EncodeBase64Url(field.Name),
                ["value"] = EncodeBase64Url(field.Value),
            });
        }
        return result;
    }

    private static byte[] ReadReplayResponse(SdkEngineDependencyConnection connection)
    {
        using MemoryStream result = new();
        while (true)
        {
            SdkEngineObservationChunk chunk;
            try
            {
                chunk = connection.Read();
            }
            catch (Exception)
            {
                throw AutomaticProject.CaptureError();
            }
            if ((!chunk.Eof && chunk.Chunk.Length == 0) ||
                result.Length > SdkEngineBridge.MaxSemanticDependencyRecordBytes -
                    chunk.Chunk.Length)
            {
                throw AutomaticProject.CaptureError();
            }
            result.Write(chunk.Chunk);
            if (chunk.Eof)
            {
                return result.Length > 0
                    ? result.ToArray()
                    : throw AutomaticProject.CaptureError();
            }
        }
    }

    private static SemanticDependencyResponse ReconstructResponse(
        byte[] record,
        string validatedOutcome)
    {
        JsonObject value;
        try
        {
            value = JsonNode.Parse(record)!.AsObject();
        }
        catch (Exception)
        {
            throw AutomaticProject.CaptureError();
        }
        List<SemanticDependencyMetadata> metadata = [];
        try
        {
            foreach (JsonNode? node in value["metadata"]!.AsArray())
            {
                JsonObject field = node!.AsObject();
                metadata.Add(new SemanticDependencyMetadata(
                    DecodeBase64Url(field["name"]), DecodeBase64Url(field["value"])));
            }
            return new SemanticDependencyResponse(
                OptionalText(value["error_code"]),
                OptionalUInt32(value["error_number"]),
                metadata,
                validatedOutcome == "response"
                    ? ObservationOutcome.Response
                    : ObservationOutcome.Error,
                value["payload"] is null ? null : DecodeBase64Url(value["payload"]),
                OptionalText(value["status"]),
                OptionalUInt16(value["status_code"]));
        }
        catch (Exception)
        {
            throw AutomaticProject.CaptureError();
        }
    }

    private static string? OptionalText(JsonNode? value) =>
        value is null ? null : value.GetValue<string>();

    private static uint? OptionalUInt32(JsonNode? value) =>
        value is null ? null : value.GetValue<uint>();

    private static ushort? OptionalUInt16(JsonNode? value) =>
        value is null ? null : value.GetValue<ushort>();

    private static string Outcome(ObservationOutcome outcome) =>
        outcome == ObservationOutcome.Response ? "response" : "error";

    private static SemanticDependencyResponse ReturnLive(SemanticDependencyLiveResult result)
    {
        if (result.Error is not null)
        {
            ExceptionDispatchInfo.Capture(result.Error).Throw();
        }
        return result.Response;
    }

    private static int CheckedBytes(params int[] values)
    {
        int result = 0;
        foreach (int value in values)
        {
            result = checked(result + value);
        }
        return result;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64Url(JsonNode? value)
    {
        string encoded = value?.GetValue<string>() ?? throw AutomaticProject.CaptureError();
        string standard = encoded.Replace('-', '+').Replace('_', '/');
        standard += new string('=', (4 - standard.Length % 4) % 4);
        return Convert.FromBase64String(standard);
    }
}
