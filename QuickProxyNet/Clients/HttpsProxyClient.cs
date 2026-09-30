using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

/// <summary>
/// Provides functionality for connecting to a server using an HTTPS proxy.
/// Supports secure tunneling over SSL/TLS through the proxy.
/// </summary>
public class HttpsProxyClient : ProxyClient
{
    public HttpsProxyClient(string host, int port) : base("https", host, port)
    {
    }

    public HttpsProxyClient(string host, int port, NetworkCredential credentials) : base("https", host, port,
        credentials)
    {
    }

    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    public bool CheckCertificateRevocation { get; set; }

    public X509CertificateCollection? ClientCertificates { get; set; }

    public CipherSuitesPolicy? SslCipherSuitesPolicy { get; set; }

    public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    public override ProxyType Type => ProxyType.Https;

    // SslStream only reads this list, so one instance serves every connection.
    private static readonly List<SslApplicationProtocol> Http11Only = [SslApplicationProtocol.Http11];

    // The TLS session is with the proxy, not with the target the tunnel leads to, so the proxy's
    // name is the one SNI carries and the certificate is checked against.
    private SslClientAuthenticationOptions GetSslClientAuthenticationOptions()
    {
        return new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode =
                CheckCertificateRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
            ApplicationProtocols = Http11Only,
            // Null unless the caller set one. SslStream then applies the same rule the old default
            // callback did — no policy errors — and its failure names the actual problem, where a
            // callback's refusal only says a callback refused.
            RemoteCertificateValidationCallback = ServerCertificateValidationCallback,
            CipherSuitesPolicy = SslCipherSuitesPolicy,
            ClientCertificates = ClientCertificates,
            EnabledSslProtocols = SslProtocols,
            TargetHost = ProxyHost
        };
    }

    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        // Before the TLS handshake: a target that is refused anyway should cost no round trip.
        ValidateArguments(host, port);

        var ssl = new SslStream(stream, false);
        try
        {
            await TlsHandshake.AuthenticateAsync(
                ssl, GetSslClientAuthenticationOptions(), $"{ProxyHost}:{ProxyPort}", cancellationToken);
        }
        catch
        {
            ssl.Dispose();
            throw;
        }

        return await HttpHelper.EstablishHttpTunnelAsync(ssl, host, port, ProxyCredentials,
            cancellationToken);
    }
}
