using System.Net;
using System.Text;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class HttpHelperTest
{
    private static byte[] Established => Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");

    /// <summary>
    /// The target host is written into the request line and the Host header as it is. This host,
    /// given to the one-call API, made the proxy read an injected header and then a second request
    /// of the caller's writing, and ConnectAsync returned a stream. Every overload now refuses it
    /// before anything is sent.
    /// </summary>
    [Fact]
    public async Task Client_HeaderInjectionThroughTheTargetHost_IsRefusedByEveryOverload()
    {
        const string host =
            "example.com HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal.local\r\nX-Pad: x";

        using var proxy = new LoopbackConnectProxy(IPAddress.Loopback);
        IProxyClient client = Proxy.Create($"http://127.0.0.1:{proxy.Port}");

        await Assert.ThrowsAsync<ArgumentException>(() => client.ConnectAsync(host, 443).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ConnectAsync(host, 443, TimeSpan.FromSeconds(10)).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => client.ConnectAsync(new DnsEndPoint(host, 443)).AsTask());

        var stream = new FakeProxyStream(Established);
        await Assert.ThrowsAsync<ArgumentException>(() => client.ConnectAsync(stream, host, 443).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ConnectAsync(stream, new DnsEndPoint(host, 443)).AsTask());
        Assert.Empty(stream.WrittenBytes);
    }

    /// <summary>
    /// Each of these ends or splits a line of the request, or ends a NUL-terminated field, and none
    /// is ever part of a host name.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x09)]
    [InlineData(0x0A)]
    [InlineData(0x0D)]
    [InlineData(0x1F)]
    [InlineData(0x20)]
    [InlineData(0x7F)]
    public async Task Client_TargetHostWithSpaceOrControlCharacter_IsRefusedBeforeWriting(int character)
    {
        var stream = new FakeProxyStream(Established);
        var client = new HttpProxyClient("proxy.example", 8080);

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ConnectAsync(stream, $"example{(char)character}com", 443).AsTask());

        Assert.Equal("host", ex.ParamName);
        Assert.Contains($"U+{character:X4} at index 7", ex.Message);
        Assert.Empty(stream.WrittenBytes);
    }

    [Fact]
    public async Task Client_InternationalisedTargetHost_IsStillSentAsUtf8()
    {
        var stream = new FakeProxyStream(Established);

        await new HttpProxyClient("proxy.example", 8080).ConnectAsync(stream, "пример.рф", 443);

        Assert.StartsWith("CONNECT пример.рф:443 HTTP/1.1\r\nHost: пример.рф:443\r\n",
            Encoding.UTF8.GetString(stream.WrittenBytes));
    }

    [Fact]
    public async Task EstablishTunnel_200_ReturnsStream()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);

        var result = await HttpHelper.EstablishHttpTunnelAsync(stream,"example.com", 443, null,
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

        var result = await HttpHelper.EstablishHttpTunnelAsync(stream,"example.com", 443, null,
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
            () => HttpHelper.EstablishHttpTunnelAsync(stream,"example.com", 443, null,
                CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.AuthRequired, ex.ErrorCode);
    }

    [Fact]
    public async Task EstablishTunnel_403_ThrowsConnectionFailed()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 403 Forbidden\r\n\r\n");
        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => HttpHelper.EstablishHttpTunnelAsync(stream,"example.com", 443, null,
                CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task EstablishTunnel_SendsCorrectCommand_NoAuth()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);

        await HttpHelper.EstablishHttpTunnelAsync(stream,"target.com", 8080, null,
            CancellationToken.None);

        var sent = Encoding.UTF8.GetString(stream.WrittenBytes);
        Assert.Contains("CONNECT target.com:8080 HTTP/1.1\r\n", sent);
        Assert.Contains("Host: target.com:8080\r\n", sent);
        Assert.DoesNotContain("Proxy-Authorization", sent);
    }

    [Theory]
    [InlineData("2001:db8::1", "[2001:db8::1]")]
    [InlineData("[2001:db8::1]", "[2001:db8::1]")]
    [InlineData("::ffff:192.0.2.1", "[::ffff:192.0.2.1]")]
    [InlineData("192.0.2.1", "192.0.2.1")]
    [InlineData("target.com", "target.com")]
    public async Task EstablishTunnel_BracketsIPv6LiteralTarget(string host, string authorityHost)
    {
        // "CONNECT 2001:db8::1:443" cannot be parsed: the address's colons run into the port.
        // RFC 9112 §3.2.3 takes the authority from RFC 3986, where an IPv6 literal is bracketed.
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);

        await HttpHelper.EstablishHttpTunnelAsync(stream,host, 443, null,
            CancellationToken.None);

        var sent = Encoding.UTF8.GetString(stream.WrittenBytes);
        Assert.StartsWith($"CONNECT {authorityHost}:443 HTTP/1.1\r\nHost: {authorityHost}:443\r\n", sent);
    }

    [Fact]
    public async Task EstablishTunnel_SendsCorrectCommand_WithAuth()
    {
        var response = Encoding.UTF8.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        var stream = new FakeProxyStream(response);
        var creds = new System.Net.NetworkCredential("user", "pass");

        await HttpHelper.EstablishHttpTunnelAsync(stream,"target.com", 443, creds,
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
            () => HttpHelper.EstablishHttpTunnelAsync(stream,"example.com", 443, null,
                CancellationToken.None).AsTask());
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }
}
