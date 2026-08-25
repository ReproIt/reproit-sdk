namespace ReproIt.Sdk;

/// <summary>Reports a managed capture step failure with a stable protocol code.</summary>
public sealed class ManagedCaptureException : Exception
{
    /// <summary>Creates one managed failure with a stable protocol error code.</summary>
    public ManagedCaptureException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>Gets the stable protocol error code.</summary>
    public string Code { get; }

}
