extern alias production;

using System.Reflection;
using System.Runtime.CompilerServices;
using ReproIt.Sdk;
using ProductionAutomaticOperation = production::ReproIt.Sdk.AutomaticOperation;
using ProductionAutomaticProject = production::ReproIt.Sdk.AutomaticProject;

namespace ReproIt.Sdk.Conformance;

internal static class PublicSurfaceConformance
{
    internal static void Run()
    {
        Assembly assembly = typeof(ProductionAutomaticProject).Assembly;
        Require(
            !assembly.GetCustomAttributes<InternalsVisibleToAttribute>().Any(),
            "The production .NET SDK grants another assembly access to its internals.");
        foreach (Type type in assembly.GetExportedTypes()
            .Where(value => value.Namespace == "ReproIt.Sdk"))
        {
            foreach (string forbidden in new[]
            {
                "SdkEngine",
                "ObservationAdapter",
                "ObservationSession",
                "InstalledObservation",
                "NativeHandle",
            })
            {
                Require(
                    !type.Name.Contains(forbidden, StringComparison.Ordinal),
                    $"The .NET SDK exports shared-engine internal {type.Name}.");
            }
        }
        RequireMethods(
            typeof(ProductionAutomaticProject),
            ["Dispose", "Open", "StartOperation"]);
        RequireMethods(
            typeof(ProductionAutomaticOperation),
            ["Cancel", "Dispose", "Fail", "get_OperationId", "RecordInput", "Succeed"]);
        Require(
            typeof(ProductionAutomaticOperation).GetConstructors().Length == 0,
            "The .NET SDK exposes direct operation construction.");
    }

    private static void RequireMethods(Type type, string[] expected)
    {
        string[] actual = type.GetMethods(
                BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance |
                BindingFlags.DeclaredOnly)
            .Select(method => method.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Array.Sort(expected, StringComparer.Ordinal);
        Require(
            actual.SequenceEqual(expected),
            $"The public {type.Name} method set changed.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
