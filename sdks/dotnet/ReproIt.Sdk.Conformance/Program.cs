using ReproIt.Sdk;
using ReproIt.Sdk.Conformance;

if (args is ["processor-capture"])
{
    foreach (string capability in ProcessorCapture.CaptureProcessorCapabilities())
    {
        Console.WriteLine(capability);
    }
    return;
}

SdkEngineBridgeConformance.Run();
AutomaticOperationConformance.Run();
PublicSurfaceConformance.Run();

if (Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS") is not null)
{
    SemanticDependencyConformance.Run();
    ProcessorCaptureConformance.Run();
}
