using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class HttpsProxyClientTest
{
    /// <summary>
    /// The TLS session is with the proxy, so the proxy's name is what SNI carries and what its
    /// certificate is checked against. Both used to be the CONNECT target's, which failed every
    /// HTTPS proxy under the default validation unless its certificate named the site being
    /// tunnelled to.
    /// </summary>
    [Fact]
    public async Task Handshake_NamesTheProxy_NotTheTarget()
    {
        using X509Certificate2 certificate = CreateSelfSignedCertificate("localhost");
        using var proxy = new LoopbackConnectProxy(IPAddress.Loopback, certificate);

        SslPolicyErrors? errors = null;
        var client = new HttpsProxyClient("localhost", proxy.Port)
        {
            ServerCertificateValidationCallback = (_, _, _, policyErrors) =>
            {
                errors = policyErrors;
                return true;
            }
        };

        // Connected by hand so "localhost" never goes to DNS: the client is only told the proxy
        // is called that, and the name is all this test is about.
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, proxy.Port);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await using Stream stream = await client.ConnectAsync(socket.GetStream(), "example.com", 443, cts.Token);

        Assert.StartsWith("CONNECT example.com:443 HTTP/1.1\r\n", await proxy.Request);
        Assert.Equal("localhost", proxy.ServerName);
        // Self-signed, so the chain is untrusted; the name, though, has to match.
        Assert.NotNull(errors);
        Assert.False(errors.Value.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch), $"Policy errors: {errors}");
    }

    /// <summary>
    /// Without a callback of the caller's, an untrusted certificate is refused by SslStream's own
    /// check, whose message names the policy error. The library's former default callback made
    /// every such failure read "rejected by the provided RemoteCertificateValidationCallback".
    /// </summary>
    [Fact]
    public async Task UntrustedCertificate_WithoutACallback_IsRefused_NamingTheReason()
    {
        using X509Certificate2 certificate = CreateSelfSignedCertificate("localhost");
        using var proxy = new LoopbackConnectProxy(IPAddress.Loopback, certificate);
        var client = new HttpsProxyClient("localhost", proxy.Port);

        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, proxy.Port);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => await client.ConnectAsync(socket.GetStream(), "example.com", 443, cts.Token));

        Assert.Equal(ProxyErrorCode.TlsHandshakeFailed, ex.ErrorCode);
        for (Exception? e = ex; e is not null; e = e.InnerException)
            Assert.DoesNotContain("RemoteCertificateValidationCallback", e.Message);
    }

    private static X509Certificate2 CreateSelfSignedCertificate(string dnsName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dnsName);
        request.CertificateExtensions.Add(names.Build());

        using X509Certificate2 ephemeral = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        // Schannel refuses a private key that exists only in memory; a PKCS#12 round trip gives
        // the certificate a key it can use.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), password: null);
    }
}
