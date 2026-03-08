using System.Text;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class HttpHelperTest
{
    private static readonly Uri ProxyUri = new("http://proxy.example.com:8080");

    [Fact]
    public async Task EstablishTunnel_200_ReturnsStream()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);

        var result = await HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "example.com", 443, null,
            CancellationToken.None);

        // Should return the same stream (no overread)
        Assert.Same(stream, result);
    }

    [Fact]
    public async Task EstablishTunnel_200_WithOverread_ReturnsPrefixedStream()
    {
        // Simulate proxy sending extra bytes after headers (overread)
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\nHELLO");
        var stream = new FakeProxyStream(response);

        var result = await HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "example.com", 443, null,
            CancellationToken.None);

        // Should NOT be the same stream — it's a PrefixedStream wrapping the overread bytes
        Assert.NotSame(stream, result);

        // Read the overread bytes from the PrefixedStream
        var buf = new byte[10];
        int read = await result.ReadAsync(buf);
        Assert.Equal("HELLO", Encoding.UTF8.GetString(buf, 0, read));
    }

    [Fact]
    public async Task EstablishTunnel_407_ThrowsAuthRequired()
    {
        var response = Encoding.UTF8.GetBytes(
            "HTTP/1.1 407 Proxy Authentication Required\r\n" +
            "Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "example.com", 443, null,
                CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.AuthRequired, ex.ErrorCode);
    }

    [Fact]
    public async Task EstablishTunnel_403_ThrowsConnectionFailed()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 403 Forbidden\r\n\r\n");
        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "example.com", 443, null,
                CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task EstablishTunnel_SendsCorrectCommand_NoAuth()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);

        await HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "target.com", 8080, null,
            CancellationToken.None);

        var sent = Encoding.UTF8.GetString(stream.WrittenBytes);
        Assert.Contains("CONNECT target.com:8080 HTTP/1.1\r\n", sent);
        Assert.Contains("Host: target.com:8080\r\n", sent);
        Assert.DoesNotContain("Proxy-Authorization", sent);
    }

    [Fact]
    public async Task EstablishTunnel_SendsCorrectCommand_WithAuth()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);
        var creds = new System.Net.NetworkCredential("user", "pass");

        await HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "target.com", 443, creds,
            CancellationToken.None);

        var sent = Encoding.UTF8.GetString(stream.WrittenBytes);
        Assert.Contains("CONNECT target.com:443 HTTP/1.1\r\n", sent);
        Assert.Contains("Proxy-Authorization: Basic ", sent);

        // Verify Base64 of "user:pass"
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
        Assert.Contains(expected, sent);
    }

    [Fact]
    public async Task EstablishTunnel_ProxyClosed_ThrowsProxyProtocolException()
    {
        // Empty response = proxy closed connection
        var stream = new FakeProxyStream([]);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => HttpHelper.EstablishHttpTunnelAsync(stream, ProxyUri, "example.com", 443, null,
                CancellationToken.None).AsTask());
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }
}
