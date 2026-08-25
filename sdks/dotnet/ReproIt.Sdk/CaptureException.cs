namespace ReproIt.Sdk;

/// <summary>Reports a local capture that is incomplete or exceeds a fixed bound.</summary>
public sealed class CaptureException(string message) : Exception(message);
