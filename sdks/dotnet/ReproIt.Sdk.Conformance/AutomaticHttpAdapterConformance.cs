using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class AutomaticHttpAdapterConformance
{
    private const string ListenerName = "HttpHandlerDiagnosticListener";
    private const string StartEvent = "System.Net.Http.HttpRequestOut.Start";
    private const string StopEvent = "System.Net.Http.HttpRequestOut.Stop";

    internal static void Run()
    {
        BindsImplementationToFrozenSubjectModule();
        RegistersOnlyWhileAProjectIsOpen();
        CapturesRealHttpClientDiagnosticsAsync().GetAwaiter().GetResult();
        CapturesSupportedBodylessHttp();
        RejectsSensitiveAndOversizedRequests();
        RejectsResponseBodiesAndExceptions();
    }

    private static void BindsImplementationToFrozenSubjectModule()
    {
        using DotnetSubjectPackage subject = ManagedSubject.PackageRunningDotnetSubject(
            typeof(AutomaticHttpAdapterConformance).Assembly.Location);
        string sdkPath = typeof(AutomaticProject).Assembly.Location;
        string digest = "sha256:" + Convert.ToHexString(
            SHA256.HashData(File.ReadAllBytes(sdkPath))).ToLowerInvariant();
        Require(
            subject.Manifest["modules"]!.AsArray().Any(module =>
                module!["module_digest"]!.GetValue<string>() == digest),
            "The .NET adapter implementation is not a frozen subject module.");
        string operatingSystem = OperatingSystem.IsWindows()
            ? "operating-system.windows"
            : OperatingSystem.IsMacOS()
                ? "operating-system.macos"
                : "operating-system.linux";
        Require(
            subject.Manifest["operating_system"]!.GetValue<string>() == operatingSystem,
            "The .NET subject operating system capability is incorrect.");
    }

    private static async Task CapturesRealHttpClientDiagnosticsAsync()
    {
        using AdapterFixture fixture = new();
        using TcpListener server = new(IPAddress.Loopback, 0);
        server.Start(1);
        int port = ((IPEndPoint)server.LocalEndpoint).Port;
        using CancellationTokenSource cancellation = new(TimeSpan.FromSeconds(5));
        Task serve = ServeBodylessResponseAsync(server, cancellation.Token);
        using SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
        };
        using HttpClient client = new(handler);
        using HttpResponseMessage response = await client.GetAsync(
            $"http://127.0.0.1:{port}/live",
            HttpCompletionOption.ResponseHeadersRead,
            cancellation.Token);
        await serve;

        Require(
            response.StatusCode == HttpStatusCode.NoContent &&
            fixture.Native.Requests.Any(value => Operation(value) == "dependency-open") &&
            fixture.Native.Requests.Any(value => Operation(value) == "dependency-finish"),
            "The .NET adapter did not capture real HttpClient diagnostic events.");
    }

    private static async Task ServeBodylessResponseAsync(
        TcpListener server,
        CancellationToken cancellation)
    {
        using TcpClient connection = await server.AcceptTcpClientAsync(cancellation);
        await using NetworkStream stream = connection.GetStream();
        byte[] request = new byte[16 * 1_024];
        int count = 0;
        while (count < request.Length)
        {
            int read = await stream.ReadAsync(request.AsMemory(count), cancellation);
            if (read == 0)
            {
                throw new InvalidOperationException("The HTTP request ended before its headers.");
            }
            count += read;
            if (HeaderEnd(request.AsSpan(0, count)))
            {
                break;
            }
        }
        if (!HeaderEnd(request.AsSpan(0, count)))
        {
            throw new InvalidOperationException("The HTTP request headers exceeded the limit.");
        }
        byte[] response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(response, cancellation);
    }

    private static bool HeaderEnd(ReadOnlySpan<byte> value)
    {
        ReadOnlySpan<byte> terminal = "\r\n\r\n"u8;
        return value.Length >= terminal.Length && value.IndexOf(terminal) >= 0;
    }

    private static void RegistersOnlyWhileAProjectIsOpen()
    {
        Require(
            InstalledObservationAdapters.Snapshot().Count == 0,
            "The .NET observation adapters were active without an open project.");
        using AdapterFixture fixture = new();
        JsonArray registrations = InstalledObservationAdapters.Snapshot();
        JsonArray engineRegistrations = fixture.Native.Requests
            .Single(value => Operation(value) == "engine-open")["observation_adapters"]!
            .AsArray();
        Require(
            registrations.Count == 7 &&
            registrations.Select(value => value!["class"]!.GetValue<string>()).SequenceEqual(
                new[]
                {
                    "clock", "database", "environment", "filesystem", "outbound-http",
                    "queue", "randomness",
                }) &&
            engineRegistrations.Count == 7 &&
            JsonNode.DeepEquals(registrations, engineRegistrations),
            "The .NET project did not register all active observation adapters.");
        fixture.Dispose();
        Require(
            InstalledObservationAdapters.Snapshot().Count == 0,
            "The .NET observation adapters remained active after project close.");
    }

    private static void CapturesSupportedBodylessHttp()
    {
        using AdapterFixture fixture = new();
        using DiagnosticListener listener = new(ListenerName);
        using HttpRequestMessage request = new(HttpMethod.Get, "https://example.test/items");
        request.Headers.Add("x-request-tag", "alpha");
        using HttpResponseMessage response = new(HttpStatusCode.NoContent)
        {
            Content = new ByteArrayContent([]),
            ReasonPhrase = "No Content",
            RequestMessage = request,
            Version = HttpVersion.Version20,
        };
        response.Headers.Add("x-response-tag", "beta");

        listener.Write(StartEvent, new { Request = request });
        listener.Write(StopEvent, new { Request = request, Response = response });

        JsonObject[] requests = fixture.Native.Requests;
        JsonObject opened = requests.Single(value => Operation(value) == "dependency-open");
        JsonObject semanticRequest = opened["request"]!.AsObject();
        JsonObject payload = JsonNode.Parse(Decode(semanticRequest["payload"]))!.AsObject();
        Require(
            semanticRequest["observation_class"]!.GetValue<string>() == "outbound-http" &&
            semanticRequest["operation"]!.GetValue<string>() == "outbound-http-request" &&
            Encoding.UTF8.GetString(Decode(semanticRequest["target"])) ==
                "https://example.test/items" &&
            payload["method"]!.GetValue<string>() == "GET",
            "The .NET HTTP adapter changed the semantic request.");
        JsonObject finished = requests.Single(value => Operation(value) == "dependency-finish");
        JsonObject semanticResponse = finished["response"]!.AsObject();
        Require(
            semanticResponse["outcome"]!.GetValue<string>() == "response" &&
            semanticResponse["status_code"]!.GetValue<int>() == 204 &&
            !requests.Any(value => Operation(value) == "operation-unowned"),
            "The .NET HTTP adapter did not finish a supported response.");
    }

    private static void RejectsSensitiveAndOversizedRequests()
    {
        foreach (Action<HttpRequestMessage> change in new Action<HttpRequestMessage>[]
        {
            request => request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", "private"),
            request => request.Headers.Add("x-large", new string('a', 8 * 1_024 + 1)),
            request => request.Content = new ByteArrayContent([1]),
        })
        {
            using AdapterFixture fixture = new();
            using DiagnosticListener listener = new(ListenerName);
            using HttpRequestMessage request = new(HttpMethod.Post, "https://example.test/write");
            change(request);

            listener.Write(StartEvent, new { Request = request });

            JsonObject[] requests = fixture.Native.Requests;
            Require(
                requests.Any(value => Operation(value) == "operation-unowned") &&
                !requests.Any(value => Operation(value) == "dependency-open"),
                "The .NET HTTP adapter accepted an unsafe or oversized request.");
        }
    }

    private static void RejectsResponseBodiesAndExceptions()
    {
        using (AdapterFixture fixture = new())
        using (DiagnosticListener listener = new(ListenerName))
        using (HttpRequestMessage request = new(HttpMethod.Get, "https://example.test/body"))
        using (HttpResponseMessage response = new(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([1]),
            RequestMessage = request,
        })
        {
            listener.Write(StartEvent, new { Request = request });
            listener.Write(StopEvent, new { Request = request, Response = response });
            string[] operations = fixture.Native.Requests.Select(Operation).ToArray();
            Require(
                operations.Contains("dependency-open") &&
                operations.Contains("observation-abandon") &&
                operations.Contains("operation-unowned") &&
                !operations.Contains("dependency-finish"),
                "The .NET HTTP adapter accepted a response body.");
        }

        using (AdapterFixture fixture = new())
        using (DiagnosticListener listener = new(ListenerName))
        using (HttpRequestMessage request = new(HttpMethod.Get, "https://example.test/error"))
        {
            listener.Write(StartEvent, new { Request = request });
            listener.Write(
                "System.Net.Http.Exception",
                new { Request = request, Exception = new HttpRequestException("private") });
            string[] operations = fixture.Native.Requests.Select(Operation).ToArray();
            Require(
                operations.Contains("observation-abandon") &&
                operations.Contains("operation-unowned") &&
                !operations.Contains("dependency-finish"),
                "The .NET HTTP adapter accepted an ambiguous HTTP error.");
        }
    }

    private static string Operation(JsonObject request) =>
        request["operation"]!.GetValue<string>();

    private static byte[] Decode(JsonNode? value)
    {
        string encoded = value!.GetValue<string>().Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '='));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class AdapterFixture : IDisposable
    {
        private readonly SdkEngineBridge bridge;
        private readonly AutomaticProject project;
        private readonly DotnetSubjectPackage subject;
        private bool disposed;

        internal AdapterFixture()
        {
            Native = new AdapterNative();
            bridge = SdkEngineBridge.Open(() => Native);
            subject = TestSubject();
            project = AutomaticProject.OpenWith(new AutomaticProjectOptions
            {
                BuildRepositoryId = "repository",
                ProjectToml = "project",
                SourceRevision = "revision",
            }, bridge, subject);
            Operation = project.StartOperation(new AutomaticOperationStart(
                "generic", "1.0.0", [], AutomaticOperationKind.RequestResponse, "operation"));
        }

        internal AdapterNative Native { get; }

        internal AutomaticOperation Operation { get; }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            Operation.Dispose();
            project.Dispose();
            subject.Dispose();
            bridge.Dispose();
        }
    }

    private static DotnetSubjectPackage TestSubject()
    {
        string spool = Directory.CreateTempSubdirectory("reproit-dotnet-http-test-").FullName;
        string digest = "sha256:" + new string('a', 64);
        return new DotnetSubjectPackage(
            new JsonObject { ["format"] = "reproit.subject-closure.v1" },
            [new PackagedSubjectObject(digest, Path.Combine(spool, "subject"), 1)],
            spool,
            digest);
    }

    private sealed class AdapterNative : INativeSdkEngine
    {
        private readonly object stateLock = new();
        private readonly List<JsonObject> requests = [];

        internal JsonObject[] Requests
        {
            get
            {
                lock (stateLock)
                {
                    return requests.Select(value => (JsonObject)value.DeepClone()).ToArray();
                }
            }
        }

        public uint AbiVersion() => SdkEngineBridge.AbiVersion;

        public nint Call(byte[] input, byte[] output)
        {
            JsonObject request = JsonNode.Parse(input)!.AsObject();
            lock (stateLock)
            {
                requests.Add((JsonObject)request.DeepClone());
            }
            JsonObject result = Operation(request) switch
            {
                "engine-open" => new() { ["engine_handle"] = 91 },
                "operation-begin" => new()
                {
                    ["operation_handle"] = 92,
                    ["operation_id"] = "op_http",
                },
                "dependency-open" => new()
                {
                    ["action"] = "capture",
                    ["dependency_handle"] = 93,
                },
                "dependency-finish" => new() { ["outcome"] = "response" },
                _ => [],
            };
            byte[] value = Encoding.UTF8.GetBytes(new JsonObject
            {
                ["error_code"] = null,
                ["format"] = "reproit.sdk-engine-response.v1",
                ["ok"] = true,
                ["result"] = result,
            }.ToJsonString());
            value.CopyTo(output, 0);
            return value.Length;
        }
    }
}
