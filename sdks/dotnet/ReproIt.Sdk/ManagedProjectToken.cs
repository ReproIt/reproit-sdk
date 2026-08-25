namespace ReproIt.Sdk;

/// <summary>Restricts a project token to managed workload registration.</summary>
public sealed class ManagedProjectToken
{
    private const int MaxProjectTokenBytes = 1_024;
    private readonly string value;

    /// <summary>Validates and wraps one managed project token.</summary>
    public ManagedProjectToken(string value)
    {
        if (value.Length is 0 or > MaxProjectTokenBytes ||
            value.Any(character => character is < '!' or > '~'))
        {
            throw new ManagedCaptureException(
                "SCHEMA_INVALID", "The managed project token is invalid.");
        }
        this.value = value;
    }

    internal string SdkEngineValue => value;
}
