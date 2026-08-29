namespace ReproIt.Sdk;

internal sealed class AutomaticNativeGuardLease : IDisposable
{
    private bool disposed;

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        AutomaticNativeGuard.Release();
    }
}

internal static class AutomaticNativeGuard
{
    private const string AdapterId = "dotnet-native-coverage-sentinel";
    private const string AdapterVersion = "1.0.0";
    private const int MaxLeases = 64;
    private static readonly object StateLock = new();
    private static readonly AutomaticObservationClass[] GuardedClasses =
    [
        AutomaticObservationClass.Clock,
        AutomaticObservationClass.Database,
        AutomaticObservationClass.Environment,
        AutomaticObservationClass.Filesystem,
        AutomaticObservationClass.Queue,
        AutomaticObservationClass.Randomness,
    ];
    private static readonly List<InstalledObservationAdapter> Installed = [];
    private static string implementationDigest = "";
    private static int references;

    internal static AutomaticNativeGuardLease Acquire(string digest)
    {
        lock (StateLock)
        {
            if (string.IsNullOrEmpty(digest) || references >= MaxLeases ||
                (references > 0 && implementationDigest != digest))
            {
                throw AutomaticProject.CaptureError();
            }
            if (references == 0)
            {
                Install(digest);
            }
            references += 1;
            return new AutomaticNativeGuardLease();
        }
    }

    internal static void Release()
    {
        lock (StateLock)
        {
            if (references == 0)
            {
                return;
            }
            references -= 1;
            if (references != 0)
            {
                return;
            }
            foreach (InstalledObservationAdapter adapter in Installed)
            {
                InstalledObservationAdapters.Remove(adapter);
            }
            Installed.Clear();
            implementationDigest = "";
        }
    }

    private static void Install(string digest)
    {
        try
        {
            foreach (AutomaticObservationClass observationClass in GuardedClasses)
            {
                InstalledObservationAdapter adapter = new(
                    AdapterId, AdapterVersion, observationClass, digest);
                InstalledObservationAdapters.Install(adapter);
                Installed.Add(adapter);
            }
            implementationDigest = digest;
        }
        catch (Exception)
        {
            foreach (InstalledObservationAdapter adapter in Installed)
            {
                InstalledObservationAdapters.Remove(adapter);
            }
            Installed.Clear();
            implementationDigest = "";
            throw AutomaticProject.CaptureError();
        }
    }
}
