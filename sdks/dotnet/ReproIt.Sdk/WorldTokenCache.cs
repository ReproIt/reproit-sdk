using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ReproIt.Sdk;

/// <summary>Fetches a bounded World token from an authenticated Runtime.</summary>
internal interface IWorldTokenTransport
{
    /// <summary>Fetches one current World identity.</summary>
    Task<string?> FetchWorldIdAsync(
        string serviceId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

/// <summary>Refreshes one Runtime World token outside the operation path.</summary>
internal sealed class WorldTokenCache : IAsyncDisposable
{
    private static readonly byte[] RefreshSeed = RandomNumberGenerator.GetBytes(32);
    private static readonly SemaphoreSlim RequestSlot = new(1, 1);

    private readonly CancellationTokenSource shutdown = new();
    private readonly string serviceId;
    private readonly object stateLock = new();
    private readonly IWorldTokenTransport transport;
    private readonly Task worker;
    private readonly double refreshFraction;
    private long received;
    private string? worldId;

    /// <summary>Starts one bounded background refresh worker.</summary>
    public WorldTokenCache(IWorldTokenTransport transport, string serviceId)
    {
        this.transport = transport;
        this.serviceId = serviceId;
        byte[] identity = System.Text.Encoding.UTF8.GetBytes(serviceId);
        byte[] digest = SHA256.HashData([.. RefreshSeed, .. identity]);
        refreshFraction = (50 + digest[0] % 21) / 100.0;
        worker = Task.Run(RefreshAsync);
    }

    /// <summary>Starts an operation only when a current World token exists.</summary>
    public CandidateStart CandidateStart(
        string captureId,
        JsonNode deployment,
        string operationId)
    {
        if (deployment["service_id"]?.GetValue<string>() != serviceId)
        {
            throw new CaptureException("The World token does not match the deployment service.");
        }
        lock (stateLock)
        {
            if (worldId is null || Stopwatch.GetElapsedTime(received) >= TimeSpan.FromSeconds(5))
            {
                throw new CaptureException(
                    "The operation started without a current Runtime World token.");
            }
            return new CandidateStart(captureId, deployment, operationId, worldId);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        using CancellationTokenSource deadline = new(TimeSpan.FromMilliseconds(1_100));
        try
        {
            await worker.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new CaptureException("The World-token refresh worker did not stop.");
        }
        shutdown.Dispose();
    }

    private async Task RefreshAsync()
    {
        int[] backoffMilliseconds = [100, 200, 400, 800, 1_600, 3_200];
        int attempt = 0;
        while (!shutdown.IsCancellationRequested)
        {
            string? next = await FetchAsync().ConfigureAwait(false);
            if (next is not null)
            {
                lock (stateLock)
                {
                    worldId = next;
                    received = Stopwatch.GetTimestamp();
                }
                attempt = 0;
                if (await WaitAsync(
                    TimeSpan.FromSeconds(5 * refreshFraction)).ConfigureAwait(false))
                {
                    return;
                }
                continue;
            }
            TimeSpan delay = TimeSpan.FromMilliseconds(
                backoffMilliseconds[Math.Min(attempt, backoffMilliseconds.Length - 1)]);
            attempt = Math.Min(attempt + 1, backoffMilliseconds.Length - 1);
            lock (stateLock)
            {
                if (worldId is not null)
                {
                    delay = TimeSpan.FromTicks(Math.Min(
                        delay.Ticks,
                        Math.Max(0, (TimeSpan.FromSeconds(5) -
                            Stopwatch.GetElapsedTime(received)).Ticks)));
                }
            }
            if (await WaitAsync(delay).ConfigureAwait(false))
            {
                return;
            }
        }
    }

    private async Task<string?> FetchAsync()
    {
        try
        {
            await RequestSlot.WaitAsync(shutdown.Token).ConfigureAwait(false);
            try
            {
                return await transport.FetchWorldIdAsync(
                    serviceId,
                    TimeSpan.FromSeconds(1),
                    shutdown.Token).ConfigureAwait(false);
            }
            finally
            {
                RequestSlot.Release();
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async Task<bool> WaitAsync(TimeSpan delay)
    {
        try
        {
            await Task.Delay(delay, shutdown.Token).ConfigureAwait(false);
            return false;
        }
        catch (OperationCanceledException)
        {
            return true;
        }
    }
}
