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

    private SslClientAuthenticationOptions GetSslClientAuthenticationOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode =
                CheckCertificateRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            RemoteCertificateValidationCallback = ServerCertificateValidationCallback ?? DefaultValidation,
            CipherSuitesPolicy = SslCipherSuitesPolicy,
            ClientCertificates = ClientCertificates,
            EnabledSslProtocols = SslProtocols,
            TargetHost = host
        };
    }

    private static bool DefaultValidation(object sender, X509Certificate? certificate, X509Chain? chain,
        SslPolicyErrors sslPolicyErrors) => sslPolicyErrors == SslPolicyErrors.None;

    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var ssl = new SslStream(stream, false);
        try
        {
            await TlsHandshake.AuthenticateAsync(
                ssl, GetSslClientAuthenticationOptions(host), $"{ProxyHost}:{ProxyPort}", cancellationToken);
        }
        catch
        {
            ssl.Dispose();
            throw;
        }

        return await HttpHelper.EstablishHttpTunnelAsync(ssl, ProxyUri, host, port, ProxyCredentials,
            cancellationToken);
    }
}
