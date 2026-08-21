using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ReproIt.Sdk;

internal static class RuntimeTransportFactory
{
    internal static Func<CancellationToken, Task<Stream>> Unix(string socketPath) =>
        async token =>
        {
            Socket socket = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), token)
                    .ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

    internal static Func<CancellationToken, Task<Stream>> Tls(
        string host,
        int port,
        string serverName,
        string caCertificatePath)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253 || port is < 1 or > 65_535 ||
            string.IsNullOrEmpty(serverName) || serverName.Length > 253)
        {
            throw new ArgumentException("The shared Runtime TLS endpoint is invalid.");
        }
        FileInfo certificateFile = new(caCertificatePath);
        if (!certificateFile.Exists || certificateFile.LinkTarget is not null ||
            certificateFile.Length is <= 0 or > 1_048_576)
        {
            throw new ArgumentException("The shared Runtime CA certificate is invalid.");
        }
        byte[] certificate = File.ReadAllBytes(caCertificatePath);
        if (certificate.Length != certificateFile.Length)
        {
            throw new ArgumentException(
                "The shared Runtime CA certificate changed during validation.");
        }
        X509Certificate2 root = X509Certificate2.CreateFromPem(
            Encoding.ASCII.GetString(certificate));
        return async token =>
        {
            TcpClient client = new();
            try
            {
                await client.ConnectAsync(host, port, token).ConfigureAwait(false);
                SslStream stream = new(client.GetStream(), leaveInnerStreamOpen: false);
                X509ChainPolicy policy = new()
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                };
                policy.CustomTrustStore.Add(root);
                await stream.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions
                    {
                        CertificateChainPolicy = policy,
                        EnabledSslProtocols = SslProtocols.Tls13,
                        TargetHost = serverName,
                    }, token).ConfigureAwait(false);
                if (stream.NegotiatedCipherSuite != TlsCipherSuite.TLS_AES_256_GCM_SHA384)
                {
                    throw new AuthenticationException(
                        "The Runtime selected an unsupported TLS cipher suite.");
                }
                return stream;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        };
    }
}
