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

if (args is ["automatic-native"])
{
    AutomaticNativeGuardConformance.Run();
    return;
}

SdkEngineBridgeConformance.Run();
AutomaticOperationConformance.Run();
AutomaticHttpAdapterConformance.Run();
DistributedFuzzConformance.Run();
PublicSurfaceConformance.Run();

if (Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS") is not null)
{
    SemanticDependencyConformance.Run();
    ProcessorCaptureConformance.Run();
}
