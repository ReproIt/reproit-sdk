// SDK-side processor capture.
//
// The canonical Linux capture rule is pinned by
// specs/v1/processor-capture.json. Every SDK derives the same sorted
// capability list from the same host. Capture maps raw views through
// curated tables and never removes a captured value. A non-Linux host
// captures nothing. A read or parse failure captures nothing, because
// capture may only add real information and a failed SDK must never change
// application behavior.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace ReproIt.Sdk;

/// <summary>Captures the process-visible processor view of this host.</summary>
public static class ProcessorCapture
{
    private const string FeaturePrefix = "processor.feature.";
    private const string OsStatePrefix = "processor.os-state.";
    private const string IdentityPrefix = "processor.identity.";
    private const ulong AtHwcap = 16;

    private static readonly Dictionary<string, string> X86FlagGroups = new()
    {
        ["aes"] = "aes",
        ["avx"] = "avx",
        ["avx2"] = "avx2",
        ["avx512bw"] = "avx512bw",
        ["avx512dq"] = "avx512dq",
        ["avx512f"] = "avx512f",
        ["avx512vl"] = "avx512vl",
        ["bmi1"] = "bmi1",
        ["bmi2"] = "bmi2",
        ["fma"] = "fma",
        ["pclmulqdq"] = "pclmulqdq",
        ["pni"] = "sse3",
        ["sse2"] = "sse2",
        ["sse4_1"] = "sse4-1",
        ["sse4_2"] = "sse4-2",
        ["ssse3"] = "ssse3",
    };

    private static readonly Dictionary<int, string> Arm64HwcapGroups = new()
    {
        [1] = "asimd",
        [3] = "aes",
        [6] = "sha2",
        [7] = "crc32",
        [22] = "sve",
    };

    private static readonly string[] X86IdentityFields =
        ["vendor_id", "cpu family", "model", "stepping", "microcode"];

    private static readonly string[] ArmIdentityFields =
        ["CPU implementer", "CPU variant", "CPU part", "CPU revision"];

    /// <summary>Captures sorted processor.* capability strings.</summary>
    public static List<string> CaptureProcessorCapabilities()
    {
        if (!OperatingSystem.IsLinux())
        {
            return [];
        }
        string machine = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x86_64",
            Architecture.Arm64 => "aarch64",
            _ => "",
        };
        if (machine.Length == 0)
        {
            return [];
        }
        string cpuinfo;
        try
        {
            cpuinfo = File.ReadAllText("/proc/cpuinfo");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            cpuinfo = "";
        }
        ulong? hwcap = null;
        try
        {
            hwcap = ParseAuxvHwcap(File.ReadAllBytes("/proc/self/auxv"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            hwcap = null;
        }
        return DeriveProcessorCapabilities(machine, cpuinfo, hwcap);
    }

    /// <summary>Pure derivation over raw views, shared with the capture
    /// vectors.</summary>
    public static List<string> DeriveProcessorCapabilities(
        string machine, string cpuinfo, ulong? hwcap)
    {
        SortedSet<string> unique = new(StringComparer.Ordinal);
        string? identity;
        if (machine == "x86_64")
        {
            HashSet<string> flags = X86Flags(cpuinfo);
            foreach ((string flag, string group) in X86FlagGroups)
            {
                if (flags.Contains(flag))
                {
                    unique.Add(FeaturePrefix + group);
                }
            }
            if (flags.Contains("osxsave"))
            {
                unique.Add(OsStatePrefix + "osxsave");
            }
            if (flags.Contains("avx"))
            {
                unique.Add(OsStatePrefix + "xcr0.avx");
            }
            if (flags.Contains("avx512f"))
            {
                unique.Add(OsStatePrefix + "xcr0.avx512");
            }
            identity = IdentityToken(cpuinfo, X86IdentityFields, "x86", [1, 2, 3]);
        }
        else if (machine == "aarch64")
        {
            if (hwcap is ulong value)
            {
                foreach ((int bit, string group) in Arm64HwcapGroups)
                {
                    if ((value & (1UL << bit)) != 0)
                    {
                        unique.Add(FeaturePrefix + group);
                    }
                }
                unique.Add(OsStatePrefix + "auxv.hwcaps");
            }
            identity = IdentityToken(cpuinfo, ArmIdentityFields, "arm", []);
        }
        else
        {
            return [];
        }
        if (identity is not null)
        {
            unique.Add(IdentityPrefix + identity);
        }
        return [.. unique];
    }

    /// <summary>Extracts AT_HWCAP from raw /proc/self/auxv bytes:
    /// little-endian 16-byte entries of key then value, terminated by a
    /// zero key.</summary>
    public static ulong? ParseAuxvHwcap(byte[] auxv)
    {
        for (int offset = 0; offset + 16 <= auxv.Length; offset += 16)
        {
            ulong key = BinaryPrimitives.ReadUInt64LittleEndian(auxv.AsSpan(offset, 8));
            if (key == 0)
            {
                return null;
            }
            if (key == AtHwcap)
            {
                return BinaryPrimitives.ReadUInt64LittleEndian(auxv.AsSpan(offset + 8, 8));
            }
        }
        return null;
    }

    private static HashSet<string> X86Flags(string cpuinfo)
    {
        HashSet<string> flags = new(StringComparer.Ordinal);
        foreach (string line in cpuinfo.Split('\n'))
        {
            int separator = line.IndexOf(':', StringComparison.Ordinal);
            if (separator < 0 || line[..separator].Trim() != "flags")
            {
                continue;
            }
            foreach (string flag in line[(separator + 1)..]
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                flags.Add(flag);
            }
        }
        return flags;
    }

    /// <summary>Encodes the canonical lowercase identity token, or null
    /// when a field is missing, malformed, or disagrees between processor
    /// blocks.</summary>
    private static string? IdentityToken(
        string cpuinfo, string[] fields, string prefix, int[] numeric)
    {
        List<List<string>> blocks = [];
        foreach (string block in cpuinfo.Split("\n\n"))
        {
            if (block.Trim().Length == 0)
            {
                continue;
            }
            List<string> values = [];
            foreach (string field in fields)
            {
                string? found = null;
                foreach (string line in block.Split('\n'))
                {
                    int separator = line.IndexOf(':', StringComparison.Ordinal);
                    if (separator >= 0 && line[..separator].Trim() == field)
                    {
                        found = line[(separator + 1)..].Trim();
                        break;
                    }
                }
                if (string.IsNullOrEmpty(found))
                {
                    return null;
                }
                values.Add(found);
            }
            blocks.Add(values);
        }
        if (blocks.Count == 0 || blocks.Any(block => !block.SequenceEqual(blocks[0])))
        {
            return null;
        }
        List<string> lowered = [.. blocks[0].Select(value => value.ToLowerInvariant())];
        if (lowered.Any(value =>
            value.Any(character => character is not ((>= 'a' and <= 'z')
                or (>= '0' and <= '9') or '-'))))
        {
            return null;
        }
        foreach (int index in numeric)
        {
            if (!uint.TryParse(lowered[index], NumberStyles.None, CultureInfo.InvariantCulture,
                out _))
            {
                return null;
            }
        }
        return string.Join('.', lowered.Prepend(prefix));
    }
}
