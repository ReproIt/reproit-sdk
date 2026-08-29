namespace ReproIt.Sdk.Conformance;

internal static class AutomaticNativeGuardConformance
{
    private const string Project = """
        format = 1
        organization_id = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
        profile = "backend"
        profile_format = 1
        processing_mode = "managed"
        project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
        repository_id = "source.example/acme/commerce"
        sdk = "dotnet"
        service_id = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
        service_path = "services/orders"

        [run]
        arguments = ["run"]
        program = "dotnet"
        working_directory = "services/orders"

        [source]
        remote = "origin"
        """;

    internal static void Run()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new InvalidOperationException(
                "The automatic native conformance check requires Linux.");
        }
        using AutomaticProject project = AutomaticProject.Open(new AutomaticProjectOptions
        {
            BuildRepositoryId = "source.example/acme/commerce",
            ProjectToml = Project,
            SourceRevision = "0123456789abcdef0123456789abcdef01234567",
        });
        CleanOperationCloses(project);
        UnownedFilesystemEffectStaysLocal(project);
        Console.WriteLine("automatic .NET native checks passed");
    }

    private static void CleanOperationCloses(AutomaticProject project)
    {
        using AutomaticOperation operation = Start(project);
        operation.CloseWorld(AutomaticTriggerCompletion.Return);
        operation.Succeed();
    }

    private static void UnownedFilesystemEffectStaysLocal(AutomaticProject project)
    {
        using AutomaticOperation operation = Start(project);
        _ = File.ReadAllText("/proc/version");
        try
        {
            operation.CloseWorld(AutomaticTriggerCompletion.Return);
            throw new InvalidOperationException(
                "The .NET native guard accepted an unowned filesystem effect.");
        }
        catch (AutomaticCaptureException)
        {
        }
    }

    private static AutomaticOperation Start(AutomaticProject project) => project.StartOperation(
        new AutomaticOperationStart(
            "conformance", "1.0.0", [], AutomaticOperationKind.RequestResponse, "native-check"));
}
