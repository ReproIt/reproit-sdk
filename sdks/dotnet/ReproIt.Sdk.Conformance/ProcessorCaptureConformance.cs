// Processor capture conformance against specs/v1/processor-capture.json.

using System.Text.Json.Nodes;
using ReproIt.Sdk;

namespace ReproIt.Sdk.Conformance;

internal static class ProcessorCaptureConformance
{
    private static readonly Dictionary<string, string> Machines = new()
    {
        ["architecture.x86-64"] = "x86_64",
        ["architecture.arm64"] = "aarch64",
    };

    internal static void Run()
    {
        string vectorsPath = Environment.GetEnvironmentVariable("REPROIT_PROTOCOL_VECTORS")
            ?? throw new InvalidOperationException("REPROIT_PROTOCOL_VECTORS is required.");
        string capturePath = Path.Join(
            Path.GetDirectoryName(Path.GetFullPath(vectorsPath)), "processor-capture.json");
        JsonNode contract = JsonNode.Parse(File.ReadAllText(capturePath))!;
        foreach (JsonNode? entry in contract["capture_vectors"]!.AsArray())
        {
            JsonObject vector = entry!.AsObject();
            ulong? hwcap = vector["hwcap"] is JsonValue value
                && value.TryGetValue(out ulong parsed) ? parsed : null;
            List<string> derived = ProcessorCapture.DeriveProcessorCapabilities(
                Machines[vector["architecture"]!.GetValue<string>()],
                vector["cpuinfo"]!.GetValue<string>(),
                hwcap);
            List<string> expected = [.. vector["expected_capabilities"]!.AsArray()
                .Select(item => item!.GetValue<string>())];
            Require(derived.SequenceEqual(expected),
                $"Capture vector {vector["name"]} diverged: [{string.Join(", ", derived)}]");
        }

        byte[] auxv = new byte[48];
        BitConverter.GetBytes(6UL).CopyTo(auxv, 0);
        BitConverter.GetBytes(4096UL).CopyTo(auxv, 8);
        BitConverter.GetBytes(16UL).CopyTo(auxv, 16);
        BitConverter.GetBytes(10UL).CopyTo(auxv, 24);
        Require(ProcessorCapture.ParseAuxvHwcap(auxv) == 10UL,
            "AT_HWCAP was not read from the auxiliary vector.");
        Require(ProcessorCapture.ParseAuxvHwcap(auxv[..16]) is null,
            "A truncated auxiliary vector must yield nothing.");
        Require(ProcessorCapture.ParseAuxvHwcap([]) is null
            && ProcessorCapture.ParseAuxvHwcap([1, 2, 3]) is null,
            "A malformed auxiliary vector must yield nothing.");

        List<string> unknown = ProcessorCapture.DeriveProcessorCapabilities(
            "x86_64", "flags\t: futureflag avx2 avx2 unknownflag\n", null);
        Require(unknown.Count == 1 && unknown[0] == "processor.feature.avx2",
            "Unknown flags must be ignored and output must stay sorted unique.");

        List<string> live = ProcessorCapture.CaptureProcessorCapabilities();
        Require(live.SequenceEqual(live.Distinct().OrderBy(v => v, StringComparer.Ordinal)),
            "Live capture must be sorted and unique.");
        Require(live.All(value => value.StartsWith("processor.", StringComparison.Ordinal)),
            "Live capture must contain only processor capabilities.");
        Require(live.Count <= 64, "Live capture exceeds the capability bound.");
        if (OperatingSystem.IsLinux())
        {
            Require(live.Count > 0,
                "A Linux host must capture at least one processor capability.");
        }
        Console.WriteLine("dotnet_processor_capture=PASS");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
