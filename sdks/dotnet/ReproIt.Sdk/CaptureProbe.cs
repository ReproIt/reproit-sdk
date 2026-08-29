using System.Runtime.CompilerServices;

namespace ReproIt.Sdk;

internal static class CaptureProbe
{
    private const string ProbeEnvironment = "REPROIT_INTERNAL_CAPTURE_PROBE";
    private const string ProbeSdkEnvironment = "REPROIT_INTERNAL_CAPTURE_PROBE_SDK";

    // The internal startup probe must run when the application first loads the SDK.
#pragma warning disable CA2255
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Initialize()
    {
        if (Environment.GetEnvironmentVariable(ProbeSdkEnvironment) != "dotnet")
        {
            return;
        }
        string nonce = Environment.GetEnvironmentVariable(ProbeEnvironment) ?? "";
        if (!ValidNonce(nonce))
        {
            Environment.Exit(2);
        }
        try
        {
            using SdkEngineBridge bridge = SdkEngineBridge.OpenPackaged();
            if (bridge.Contract() != SdkEngineBridge.AbiVersion || !bridge.CaptureProbe())
            {
                Environment.Exit(2);
            }
            Console.Out.Write($"reproit.capture-probe.v1:dotnet:{nonce}\n");
            Console.Out.Flush();
            Environment.Exit(0);
        }
        catch (Exception)
        {
            Environment.Exit(2);
        }
    }

    private static bool ValidNonce(string value) => value.Length == 64 &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
