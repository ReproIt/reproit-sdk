using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Provides fail-open operation wrapper behavior.</summary>
public static class Operations
{
    /// <summary>Contains the records available before one operation starts.</summary>
    public sealed record Preparation(
        CandidateStart Start,
        JsonNode Begin,
        IReadOnlyList<JsonNode> Inputs,
        IReadOnlyList<JsonNode> Dependencies);

    /// <summary>Runs an operation and preserves its exact return or exception.</summary>
    public static T Run<T>(
        Sdk sdk,
        CandidateStart start,
        JsonNode begin,
        IEnumerable<JsonNode> inputs,
        Func<T> operation,
        Func<Exception, JsonNode> failure
    )
        => RunPrepared(
            sdk,
            new Preparation(start, begin, inputs.ToArray(), []),
            operation,
            failure);

    /// <summary>Runs a prepared operation and preserves its exact return or exception.</summary>
    public static T RunPrepared<T>(
        Sdk sdk,
        Preparation preparation,
        Func<T> operation,
        Func<Exception, JsonNode> failure)
    {
        bool captureActive = true;
        try
        {
            sdk.Begin(preparation.Start, preparation.Begin);
            foreach (JsonNode input in preparation.Inputs)
            {
                sdk.RecordInput(preparation.Start.OperationId, input);
            }
            foreach (JsonNode dependency in preparation.Dependencies)
            {
                sdk.RecordDependency(preparation.Start.OperationId, dependency);
            }
        }
        catch (Exception)
        {
            captureActive = false;
            SafeAbandon(sdk, preparation.Start.OperationId);
        }

        try
        {
            T result = operation();
            if (captureActive)
            {
                try
                {
                    sdk.Succeed(preparation.Start.OperationId);
                }
                catch (Exception)
                {
                    SafeAbandon(sdk, preparation.Start.OperationId);
                }
            }
            return result;
        }
        catch (Exception original)
        {
            if (captureActive)
            {
                try
                {
                    sdk.Fail(preparation.Start.OperationId, failure(original));
                }
                catch (Exception)
                {
                    // Capture failure must not replace the application exception.
                    SafeAbandon(sdk, preparation.Start.OperationId);
                }
            }
            throw;
        }
    }

    /// <summary>Runs one ordered stream operation.</summary>
    public static T RunStream<T>(
        Sdk sdk,
        Preparation preparation,
        Func<T> operation,
        Func<Exception, JsonNode> failure) =>
        RunKind(sdk, preparation, "stream", operation, failure);

    /// <summary>Runs one delivered-work operation.</summary>
    public static T RunDeliveredWork<T>(
        Sdk sdk,
        Preparation preparation,
        Func<T> operation,
        Func<Exception, JsonNode> failure) =>
        RunKind(sdk, preparation, "delivered-work", operation, failure);

    private static T RunKind<T>(
        Sdk sdk,
        Preparation preparation,
        string expectedKind,
        Func<T> operation,
        Func<Exception, JsonNode> failure) =>
        preparation.Begin["operation_kind"]?.GetValue<string>() == expectedKind
            ? RunPrepared(sdk, preparation, operation, failure)
            : operation();

    private static void SafeAbandon(Sdk sdk, string operationId)
    {
        try
        {
            sdk.AbandonIncomplete(operationId);
        }
        catch (Exception)
        {
            // Capture cleanup must not change application behavior.
        }
    }
}
