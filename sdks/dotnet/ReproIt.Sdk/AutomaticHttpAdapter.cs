using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

internal sealed class AutomaticHttpAdapterLease : IDisposable
{
    private bool released;

    public void Dispose()
    {
        if (released)
        {
            return;
        }
        released = true;
        AutomaticHttpAdapter.Release();
    }
}

internal static class AutomaticHttpAdapter
{
    private const string AdapterId = "dotnet-http-client-diagnostics";
    private const string AdapterVersion = "1.0.0";
    private const int MaxActiveRequests = 512;
    private const int MaxHeaderBytes = 8 * 1_024;
    private const int MaxHeaderFields = 64;
    private const int MaxPayloadBytes = 16 * 1_024;
    private const int MaxTargetBytes = 16 * 1_024;
    private const int MaxLeases = 64;
    private const string ListenerName = "HttpHandlerDiagnosticListener";
    private const string StartEvent = "System.Net.Http.HttpRequestOut.Start";
    private const string StopEvent = "System.Net.Http.HttpRequestOut.Stop";
    private const string ExceptionEvent = "System.Net.Http.Exception";
    private static readonly byte[] UnsupportedEvidence =
        Encoding.UTF8.GetBytes("dotnet-http-unsupported-v1");
    private static readonly HashSet<string> SensitiveRequestHeaders = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "Authorization",
        "Cookie",
        "Proxy-Authorization",
        "ReproIt-Fuzz-Context",
        "ReproIt-Parent-Operation",
    };
    private static readonly HashSet<string> SensitiveResponseHeaders = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "Proxy-Authenticate",
        "Set-Cookie",
        "WWW-Authenticate",
    };
    private static readonly object StateLock = new();
    private static HttpDiagnosticsObserver? observer;
    private static InstalledObservationAdapter? registration;
    private static IDisposable? listenerSubscription;
    private static int leases;

    internal static AutomaticHttpAdapterLease Acquire(string implementationDigest)
    {
        lock (StateLock)
        {
            if (leases >= MaxLeases)
            {
                throw AutomaticProject.CaptureError();
            }
            if (leases == 0)
            {
                Install(implementationDigest);
            }
            else if (registration?.ImplementationDigest != implementationDigest)
            {
                throw AutomaticProject.CaptureError();
            }
            leases += 1;
            return new AutomaticHttpAdapterLease();
        }
    }

    internal static void Release()
    {
        lock (StateLock)
        {
            if (leases == 0)
            {
                return;
            }
            leases -= 1;
            if (leases != 0)
            {
                return;
            }
            if (registration is InstalledObservationAdapter installed)
            {
                InstalledObservationAdapters.Remove(installed);
                registration = null;
            }
            listenerSubscription?.Dispose();
            listenerSubscription = null;
            observer?.Dispose();
            observer = null;
        }
    }

    private static void Install(string implementationDigest)
    {
        HttpDiagnosticsObserver installedObserver = new();
        IDisposable? installedSubscription = null;
        try
        {
            InstalledObservationAdapter installedRegistration = new(
                AdapterId,
                AdapterVersion,
                AutomaticObservationClass.OutboundHttp,
                implementationDigest);
            installedSubscription = DiagnosticListener.AllListeners.Subscribe(installedObserver);
            InstalledObservationAdapters.Install(installedRegistration);
            observer = installedObserver;
            registration = installedRegistration;
            listenerSubscription = installedSubscription;
        }
        catch (Exception)
        {
            installedSubscription?.Dispose();
            installedObserver.Dispose();
            throw AutomaticProject.CaptureError();
        }
    }

    private static bool TryRequest(
        HttpRequestMessage request,
        out SemanticDependencyRequest semanticRequest)
    {
        semanticRequest = null!;
        Uri? target = request.RequestUri;
        string? method = request.Method.Method;
        if (target is null || !target.IsAbsoluteUri ||
            target.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(target.UserInfo) ||
            string.IsNullOrEmpty(method) || method.Length > 32 ||
            request.Content is not null)
        {
            return false;
        }
        string targetText = target.AbsoluteUri;
        if (Encoding.UTF8.GetByteCount(targetText) > MaxTargetBytes ||
            !TryMetadata(
                request.Headers,
                SensitiveRequestHeaders,
                out var metadata,
                out _))
        {
            return false;
        }
        JsonObject payload = new()
        {
            ["method"] = method,
            ["version"] = request.Version.ToString(),
            ["version_policy"] = request.VersionPolicy.ToString(),
        };
        byte[] payloadBytes = CanonicalJson.Bytes(payload);
        if (payloadBytes.Length > MaxPayloadBytes)
        {
            return false;
        }
        semanticRequest = new SemanticDependencyRequest(
            "dotnet-http-client-v1",
            metadata,
            method,
            AutomaticObservationClass.OutboundHttp,
            "outbound-http-request",
            payloadBytes,
            target.Scheme,
            targetText);
        return true;
    }

    private static bool TryResponse(
        HttpRequestMessage request,
        HttpResponseMessage response,
        out SemanticDependencyResponse semanticResponse)
    {
        semanticResponse = null!;
        int statusCode = (int)response.StatusCode;
        bool statusHasNoBody = request.Method == HttpMethod.Head ||
            statusCode is >= 100 and < 200 or 204 or 304;
        bool declaredEmpty = response.Content.Headers.ContentLength == 0;
        if (statusCode is < 100 or > 599 || (!statusHasNoBody && !declaredEmpty) ||
            !TryMetadata(
                response.Headers,
                SensitiveResponseHeaders,
                out var responseMetadata,
                out int responseHeaderBytes) ||
            !TryMetadata(
                response.Content.Headers,
                SensitiveResponseHeaders,
                out var contentMetadata,
                out int contentHeaderBytes))
        {
            return false;
        }
        if (responseMetadata.Count > MaxHeaderFields - contentMetadata.Count ||
            responseHeaderBytes > MaxHeaderBytes - contentHeaderBytes)
        {
            return false;
        }
        responseMetadata.AddRange(contentMetadata);
        JsonObject payload = new()
        {
            ["reason_phrase"] = response.ReasonPhrase,
            ["version"] = response.Version.ToString(),
        };
        byte[] payloadBytes = CanonicalJson.Bytes(payload);
        if (payloadBytes.Length > MaxPayloadBytes)
        {
            return false;
        }
        semanticResponse = new SemanticDependencyResponse(
            null,
            null,
            responseMetadata,
            ObservationOutcome.Response,
            payloadBytes,
            null,
            checked((ushort)statusCode));
        return true;
    }

    private static bool TryMetadata(
        HttpHeaders headers,
        HashSet<string> sensitive,
        out List<SemanticDependencyMetadata> metadata,
        out int bytes)
    {
        metadata = [];
        bytes = 0;
        foreach ((string name, IEnumerable<string> values) in headers)
        {
            if (sensitive.Contains(name))
            {
                return false;
            }
            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            foreach (string value in values)
            {
                byte[] valueBytes = Encoding.UTF8.GetBytes(value);
                int nextBytes;
                try
                {
                    nextBytes = checked(bytes + nameBytes.Length + valueBytes.Length);
                }
                catch (OverflowException)
                {
                    return false;
                }
                if (metadata.Count >= MaxHeaderFields || nextBytes > MaxHeaderBytes)
                {
                    return false;
                }
                bytes = nextBytes;
                metadata.Add(new SemanticDependencyMetadata(nameBytes, valueBytes));
            }
        }
        return true;
    }

    private sealed class HttpDiagnosticsObserver :
        IObserver<DiagnosticListener>,
        IObserver<KeyValuePair<string, object?>>,
        IDisposable
    {
        private readonly Dictionary<HttpRequestMessage, SdkEngineDependencyConnection> active =
            new(ReferenceEqualityComparer.Instance);
        private readonly object observerLock = new();
        private readonly List<IDisposable> subscriptions = [];
        private bool disposed;

        public void OnNext(DiagnosticListener value)
        {
            if (value.Name != ListenerName)
            {
                return;
            }
            lock (observerLock)
            {
                if (disposed || subscriptions.Count >= 8)
                {
                    return;
                }
                subscriptions.Add(value.Subscribe(this));
            }
        }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            if (disposed)
            {
                return;
            }
            try
            {
                switch (value.Key)
                {
                    case StartEvent:
                        ObserveStart(value.Value);
                        break;
                    case StopEvent:
                        ObserveStop(value.Value);
                        break;
                    case ExceptionEvent:
                        ObserveException(value.Value);
                        break;
                }
            }
            catch (Exception)
            {
                MarkActiveUnowned();
            }
        }

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
            MarkActiveUnowned();
        }

        public void Dispose()
        {
            List<SdkEngineDependencyConnection> abandoned;
            lock (observerLock)
            {
                if (disposed)
                {
                    return;
                }
                disposed = true;
                foreach (IDisposable subscription in subscriptions)
                {
                    subscription.Dispose();
                }
                subscriptions.Clear();
                abandoned = active.Values.ToList();
                active.Clear();
            }
            foreach (SdkEngineDependencyConnection connection in abandoned)
            {
                connection.Abandon();
            }
        }

        private void ObserveStart(object? payload)
        {
            AutomaticOperation? operation = AutomaticOperationContext.ActiveOperation();
            if (operation is null)
            {
                return;
            }
            HttpRequestMessage? request = Property<HttpRequestMessage>(payload, "Request");
            if (request is null || !TryRequest(request, out SemanticDependencyRequest semantic))
            {
                MarkUnowned(operation);
                return;
            }
            if (operation.FuzzContext is FuzzCampaignContext fuzzContext &&
                !TryAddFuzzHeaders(request, fuzzContext, operation.OperationId))
            {
                MarkUnowned(operation);
                return;
            }
            JsonObject requestInput;
            try
            {
                requestInput = SemanticDependencyTranslator.MakeRequest(semantic);
            }
            catch (Exception)
            {
                MarkUnowned(operation);
                return;
            }
            SdkEngineDependencyConnection connection;
            try
            {
                connection = operation.OpenSemanticDependency(requestInput, null);
            }
            catch (Exception)
            {
                return;
            }
            if (connection.Action != "capture")
            {
                connection.Abandon();
                MarkUnowned(operation);
                return;
            }
            lock (observerLock)
            {
                if (disposed || active.Count >= MaxActiveRequests || active.ContainsKey(request))
                {
                    connection.Abandon();
                    MarkUnowned(operation);
                    return;
                }
                active.Add(request, connection);
            }
        }

        private static bool TryAddFuzzHeaders(
            HttpRequestMessage request,
            FuzzCampaignContext context,
            string operationId)
        {
            _ = request.Headers.Remove(DistributedFuzz.ContextHttpHeader);
            _ = request.Headers.Remove(DistributedFuzz.ParentHttpHeader);
            return request.Headers.TryAddWithoutValidation(
                    DistributedFuzz.ContextHttpHeader,
                    context.Encoded) &&
                request.Headers.TryAddWithoutValidation(
                    DistributedFuzz.ParentHttpHeader,
                    operationId);
        }

        private void ObserveStop(object? payload)
        {
            HttpRequestMessage? request = Property<HttpRequestMessage>(payload, "Request");
            if (request is null || !Remove(request, out SdkEngineDependencyConnection connection))
            {
                MarkActiveUnowned();
                return;
            }
            HttpResponseMessage? response = Property<HttpResponseMessage>(payload, "Response");
            if (response is null || !TryResponse(request, response, out var semanticResponse))
            {
                connection.Abandon();
                MarkActiveUnowned();
                return;
            }
            try
            {
                _ = connection.Finish(SemanticDependencyTranslator.MakeResponse(semanticResponse));
            }
            catch (Exception)
            {
                connection.Abandon();
            }
        }

        private void ObserveException(object? payload)
        {
            HttpRequestMessage? request = Property<HttpRequestMessage>(payload, "Request");
            if (request is not null &&
                Remove(request, out SdkEngineDependencyConnection connection))
            {
                connection.Abandon();
            }
            MarkActiveUnowned();
        }

        private bool Remove(
            HttpRequestMessage request,
            out SdkEngineDependencyConnection connection)
        {
            lock (observerLock)
            {
                if (active.Remove(request, out SdkEngineDependencyConnection? removed))
                {
                    connection = removed;
                    return true;
                }
                connection = null!;
                return false;
            }
        }

        private static T? Property<T>(object? payload, string name) where T : class
        {
            if (payload is null)
            {
                return null;
            }
            return payload.GetType().GetProperty(name)?.GetValue(payload) as T;
        }

        private static void MarkActiveUnowned()
        {
            AutomaticOperation? operation = AutomaticOperationContext.ActiveOperation();
            if (operation is not null)
            {
                MarkUnowned(operation);
            }
        }

        private static void MarkUnowned(AutomaticOperation operation)
        {
            try
            {
                operation.MarkUnowned(
                    AutomaticObservationClass.OutboundHttp,
                    null,
                    UnsupportedEvidence);
            }
            catch (Exception)
            {
                // Capture failure must not change the HTTP operation.
            }
        }
    }
}
