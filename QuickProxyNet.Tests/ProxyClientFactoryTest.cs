using System.Net;
using System.Text;

namespace QuickProxyNet.Tests;

/// <summary>
/// The string entry point: one call that takes a link of any supported scheme.
/// </summary>
/// <remarks>
/// The reason it exists rather than being a thin wrapper over <see cref="Uri"/> is the vmess
/// case below — those links are base64 JSON that <see cref="Uri"/> cannot represent at all — so
/// that test is the one that matters most here.
/// </remarks>
public class ProxyClientFactoryTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";

    private static IProxyClient Create(string link) => ProxyClientFactory.Instance.Create(link);

    [Fact]
    public void Create_Vless_ReturnsAVlessClient()
    {
        var client = Assert.IsType<VlessClient>(
            Create($"vless://{Uuid}@example.com:443?type=tcp&security=tls&sni=cdn.example.com#node"));

        Assert.Equal("example.com", client.Options.Host);
        Assert.Equal(443, client.Options.Port);
        Assert.Equal("cdn.example.com", client.Options.Sni);
    }

    [Fact]
    public void Create_VlessReality_ReturnsAClientThatWillSpeakReality()
    {
        var client = Assert.IsType<VlessClient>(Create(
            $"vless://{Uuid}@example.com:443?security=reality&pbk=BhsV4NiigG9rrk98hJnJHPJ7TQ6Iy1WqUykGF0z9I2g" +
            "&sid=ab12&sni=www.example.org&flow=xtls-rprx-vision&fp=chrome"));

        Assert.Equal(VlessSecurity.Reality, client.Options.Security);
        Assert.Equal("xtls-rprx-vision", client.Options.Flow);
    }

    [Fact]
    public void Create_Trojan_ReturnsATrojanClient()
    {
        var client = Assert.IsType<TrojanClient>(Create("trojan://secret@example.com:443?sni=cdn.example.com"));
        Assert.Equal("example.com", client.Options.Host);
    }

    /// <summary>
    /// A realistic vmess link — base64 JSON, padded, far longer than a host may be. The
    /// <see cref="Uri"/> overload cannot take this, which is the whole reason for the string one.
    /// </summary>
    [Fact]
    public void Create_Vmess_HandlesLinksThatCannotBecomeAUri()
    {
        string json =
            $$"""
              {"v":"2","ps":"a node with a long enough remark to matter","add":"example.com","port":"443",
               "id":"{{Uuid}}","aid":"0","net":"ws","host":"cdn.example.com","path":"/websocket-path","tls":"tls"}
              """;
        string link = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

        Assert.False(Uri.TryCreate(link, UriKind.Absolute, out _), "the link should be beyond Uri, or this test proves nothing");

        var client = Assert.IsType<VmessClient>(Create(link));
        Assert.Equal("example.com", client.Options.Host);
        Assert.Equal("ws", client.Options.Transport);
    }

    [Theory]
    [InlineData("socks5://127.0.0.1:1080", typeof(Socks5Client))]
    [InlineData("socks4://127.0.0.1:1080", typeof(Socks4Client))]
    [InlineData("socks4a://127.0.0.1:1080", typeof(Socks4aClient))]
    [InlineData("http://127.0.0.1:8080", typeof(HttpProxyClient))]
    [InlineData("https://127.0.0.1:8443", typeof(HttpsProxyClient))]
    public void Create_ClassicSchemes_MatchTheUriOverload(string link, Type expected)
    {
        Assert.IsType(expected, Create(link));
        Assert.IsType(expected, ProxyClientFactory.Instance.Create(new Uri(link)));
    }

    [Fact]
    public void Create_ClassicScheme_KeepsCredentials()
    {
        var client = Create("socks5://user:pass@127.0.0.1:1080");

        Assert.Equal("user", client.ProxyCredentials?.UserName);
        Assert.Equal("pass", client.ProxyCredentials?.Password);
    }

    [Fact]
    public void Create_IsCaseInsensitiveAndIgnoresSurroundingWhitespace()
    {
        Assert.IsType<Socks5Client>(Create("  SOCKS5://127.0.0.1:1080\n"));
        Assert.IsType<VlessClient>(Create($" VLESS://{Uuid}@example.com:443?security=none "));
    }

    /// <summary>
    /// An unsupported protocol must name itself in the error. "Unsupported proxy scheme" with no
    /// scheme in it is the kind of message that sends someone reading library source.
    /// </summary>
    [Fact]
    public void Create_UnsupportedScheme_SaysWhichOne()
    {
        var ex = Assert.Throws<NotSupportedException>(() => Create("hysteria2://pass@example.com:443"));

        Assert.Contains("hysteria2", ex.Message);
        Assert.Contains("vless", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("example.com:1080")]
    [InlineData("://example.com")]
    public void Create_WithoutAScheme_ThrowsArgumentException(string link)
    {
        Assert.ThrowsAny<ArgumentException>(() => Create(link));
    }

    /// <summary>An error message must not carry the credential that was in the link.</summary>
    [Fact]
    public void Create_UnsupportedScheme_DoesNotEchoTheWholeLink()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => Create("ss://verySecretPasswordThatMustNotLeak@example.com:8388"));

        Assert.DoesNotContain("verySecretPasswordThatMustNotLeak", ex.Message);
    }

    [Fact]
    public void Create_MalformedKnownScheme_ThrowsFormat()
    {
        Assert.ThrowsAny<Exception>(() => Create("socks5://"));
        Assert.ThrowsAny<FormatException>(() => Create("vless://not-a-valid-link"));
    }

    // === Proxy.ConnectAsync(string, ...) ===

    [Fact]
    public async Task ProxyConnect_WithAnUnsupportedScheme_FailsBeforeTouchingTheNetwork()
    {
        await Assert.ThrowsAsync<NotSupportedException>(async () =>
            await Proxy.ConnectAsync("tuic://example.com:443", "example.com", 443));
    }

    /// <summary>
    /// The static entry point accepts what the factory accepts — the point of adding it. A
    /// connection is attempted against a port nothing listens on, so reaching a connection
    /// failure proves the link itself was understood.
    /// </summary>
    [Fact]
    public async Task ProxyConnect_WithAVlessLink_GetsPastParsingIntoTheNetwork()
    {
        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await Proxy.ConnectAsync(
                $"vless://{Uuid}@127.0.0.1:{UnusedPort()}?security=none",
                "example.com", 443, TimeSpan.FromSeconds(5)));

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    /// <summary>A port that was bound and immediately released — nothing is listening on it.</summary>
    private static int UnusedPort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
