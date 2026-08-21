using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;

namespace ReproIt.Sdk.AspNetCore;

/// <summary>Supplies one complete SDK-owned HTTP operation start.</summary>
public sealed record AspNetCapture(
    CandidateStart Start,
    JsonNode Begin,
    IReadOnlyList<JsonNode> Inputs,
    IReadOnlyList<JsonNode> Dependencies
);

/// <summary>Captures exceptions that cross one top-level ASP.NET Core boundary.</summary>
public sealed class ReproItMiddleware
{
    private readonly Func<Exception, JsonNode> failure;
    private readonly RequestDelegate next;
    private readonly Func<HttpContext, AspNetCapture> prepare;
    private readonly Sdk sdk;

    /// <summary>Creates the request-response boundary.</summary>
    public ReproItMiddleware(
        RequestDelegate next,
        Sdk sdk,
        Func<HttpContext, AspNetCapture> prepare,
        Func<Exception, JsonNode> failure
    )
    {
        this.next = next;
        this.sdk = sdk;
        this.prepare = prepare;
        this.failure = failure;
    }

    /// <summary>Runs one request and preserves its exact response or exception.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        AspNetCapture? capture = null;
        bool captureActive = false;
        try
        {
            capture = prepare(context);
            sdk.Begin(capture.Start, capture.Begin);
            foreach (JsonNode input in capture.Inputs)
            {
                sdk.RecordInput(capture.Start.OperationId, input);
            }
            foreach (JsonNode dependency in capture.Dependencies)
            {
                sdk.RecordDependency(capture.Start.OperationId, dependency);
            }
            captureActive = true;
        }
        catch (Exception)
        {
            SafeAbandon(capture);
        }
        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch (Exception original)
        {
            if (captureActive)
            {
                try
                {
                    sdk.Fail(capture!.Start.OperationId, failure(original));
                }
                catch (Exception)
                {
                    // Capture failure must not replace the application exception.
                    SafeAbandon(capture);
                }
            }
            throw;
        }
        if (captureActive)
        {
            try
            {
                sdk.Succeed(capture!.Start.OperationId);
            }
            catch (Exception)
            {
                SafeAbandon(capture);
            }
        }
    }

    private void SafeAbandon(AspNetCapture? capture)
    {
        if (capture is null) return;
        try
        {
            sdk.AbandonIncomplete(capture.Start.OperationId);
        }
        catch (Exception)
        {
            // Capture cleanup must not change application behavior.
        }
    }
}
