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
public class ProxyFactoryTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";

    private static IProxyClient Create(string link) => Proxy.Create(link);

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
        Assert.IsType(expected, Proxy.Create(new Uri(link)));
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
            () => Create("hysteria2://verySecretPasswordThatMustNotLeak@example.com:443"));

        Assert.DoesNotContain("verySecretPasswordThatMustNotLeak", ex.Message);
    }

    // === Shadowsocks ===

    [Fact]
    public void Create_Shadowsocks_ReturnsAShadowsocksClient_AndKeepsTheLink()
    {
        // base64url("aes-256-gcm:password")
        const string link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#node";

        var client = Assert.IsType<ShadowsocksClient>(Create(link));

        Assert.Equal(ProxyType.Shadowsocks, client.Type);
        Assert.Equal("example.com", client.Options.Host);
        Assert.Equal(8388, client.Options.Port);
        Assert.Equal("aes-256-gcm", client.Options.Method);
        Assert.Equal("password", client.Options.Password);
        Assert.Equal(link, client.SourceLink);
        Assert.Equal("ss://example.com:8388/", client.ProxyUri.ToString());
    }

    [Fact]
    public void Create_Shadowsocks_FromUri_MatchesTheStringOverload()
    {
        const string link = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388/?plugin=#node";

        var client = Assert.IsType<ShadowsocksClient>(Proxy.Create(new Uri(link)));

        Assert.Equal(link, client.SourceLink);
        Assert.Equal("password", client.Options.Password);
    }

    [Fact]
    public void Create_Shadowsocks_LegacyGrammar()
    {
        // base64("aes-256-gcm:p@ss:w0rd@example.com:8388")
        var client = Assert.IsType<ShadowsocksClient>(Create("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODg=#legacy"));
        Assert.Equal("p@ss:w0rd", client.Options.Password);
    }

    /// <summary>
    /// AEAD-2022 wears the same scheme but is a different protocol. Walking a subscription must
    /// see the cipher name in the reason, not a generic "unsupported".
    /// </summary>
    [Fact]
    public void TryCreate_Shadowsocks2022_IsRejectedWithTheCipherName()
    {
        Assert.False(Proxy.TryCreate(
            "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3",
            out IProxyClient? client, out string? error));

        Assert.Null(client);
        Assert.NotNull(error);
        Assert.StartsWith("NotSupportedException:", error);
        Assert.Contains("2022-blake3-aes-256-gcm", error);
        Assert.DoesNotContain("YctPZ6U7", error); // the PSK is a credential
    }

    [Fact]
    public void TryCreate_ShadowsocksWithPlugin_IsRejectedWithThePluginName()
    {
        Assert.False(Proxy.TryCreate(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket",
            out _, out string? error));

        Assert.Contains("NotSupportedException", error);
        Assert.Contains("v2ray-plugin", error);
    }

    [Fact]
    public async Task ProxyConnect_WithAShadowsocksLink_GetsPastParsingIntoTheNetwork()
    {
        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await Proxy.ConnectAsync(
                $"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:{UnusedPort()}",
                "example.com", 443, TimeSpan.FromSeconds(5)));

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
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

    /// <summary>
    /// A proxy that accepts and then says nothing must end in <see cref="ProxyErrorCode.Timeout"/>
    /// through the string entry point — distinguishable from "could not connect", because the
    /// caller's remedy differs (wait longer vs. give up on the node).
    /// </summary>
    [Fact]
    public async Task ProxyConnect_WithASilentProxy_TimesOutWithTheTimeoutCode()
    {
        // SOCKS5 is the right protocol for this: the client must read the server's method
        // selection before it can do anything, so a silent server hangs the handshake. (VLESS
        // would not — it writes its header and reads nothing until the first payload read.)
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        try
        {
            // Accept and then hold the socket open and silent. The accepted client is kept
            // referenced until the end: discarded, it would be finalized under GC pressure and
            // the close would reach our side as a reset — a different failure than the one
            // this test is about.
            Task<System.Net.Sockets.TcpClient> accepted = listener.AcceptTcpClientAsync();

            var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
                await Proxy.ConnectAsync($"socks5://127.0.0.1:{port}", "example.com", 80, TimeSpan.FromMilliseconds(500)));

            Assert.Equal(ProxyErrorCode.Timeout, ex.ErrorCode);
            (await accepted).Dispose();
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Whatever a malformed link throws — from the factory, from a parser, from the client
    /// constructor — the credential in it must not be in the message or any inner message.
    /// </summary>
    [Theory]
    [InlineData("vless://SECRETSECRETSECRETSECRETSECRETSECRETSECRET1@example.com:443?security=none")] // 44-char id: rejected
    [InlineData("trojan://SECRETPASSWORD@:443")]                                                  // no host
    [InlineData("socks5://user:SECRETPASSWORD@[not an address")]                                 // not a URI
    [InlineData("vmess://SECRETPASSWORD-this-is-not-base64-json")]                               // not base64 JSON
    public void Create_MalformedLink_NeverEchoesTheCredential(string link)
    {
        Exception ex = Assert.ThrowsAny<Exception>(() => Create(link));

        for (Exception? e = ex; e is not null; e = e.InnerException)
            Assert.DoesNotContain("SECRET", e.Message);
    }

    // --- TryCreate: walking a subscription without exception-driven control flow.

    [Theory]
    [InlineData("socks5://example.com:1080")]
    [InlineData("http://user:pass@example.com:8080")]
    [InlineData("vless://11223344-5566-7788-99aa-bbccddeeff00@example.com:443?type=tcp&security=tls")]
    public void TryCreate_GoodLink_ReturnsTrueAndNoError(string link)
    {
        Assert.True(Proxy.TryCreate(link, out IProxyClient? client, out string? error));

        Assert.NotNull(client);
        Assert.Null(error);
    }

    [Theory]
    [InlineData("")]                                        // empty
    [InlineData("   ")]                                     // whitespace only
    [InlineData("example.com:1080")]                        // no scheme
    [InlineData("hysteria2://not-a-scheme-we-speak@host:443")] // unsupported scheme
    [InlineData("ss://not!base64!@host:443")]                  // known scheme, broken userinfo
    [InlineData("ss://rc4-md5:pw@host:8388")]                  // known scheme, cipher we refuse
    [InlineData("vmess://this-is-not-base64-json")]         // known scheme, broken payload
    [InlineData("vless://" + "a-31-character-id-aaaaaaaaaaaaa" + "@example.com:443")] // id length 31: too long to derive, too short to be hex
    public void TryCreate_BadLink_ReturnsFalseWithAReason(string link)
    {
        Assert.False(Proxy.TryCreate(link, out IProxyClient? client, out string? error));

        Assert.Null(client);
        Assert.NotNull(error);
        // The reason has to name the exception type: that is what separates "this link is junk"
        // from "a parser threw something nobody planned for", which is a library bug.
        Assert.Contains("Exception", error);
    }

    /// <summary>
    /// The whole point of TryCreate: a list from the wild is other people's text, and one bad
    /// line in a thousand must not end the run.
    /// </summary>
    [Fact]
    public void TryCreate_NeverThrows_WhateverTheInput()
    {
        string[] hostile =
        [
            "://", "vless://", "vmess://", "trojan://", "socks5://",
            "vless://@:", "vmess://" + new string('A', 5000), "http://[::",
            "\0", "�", new string('/', 200), "vless://%%%@%%%:%%%",
        ];

        foreach (string link in hostile)
        {
            // Assert.False is not the claim here — some of these could conceivably parse one day.
            // The claim is that the call returns rather than throwing.
            Proxy.TryCreate(link, out _, out _);
        }
    }

    // --- SourceLink: the text a client came from, which ProxyUri cannot reconstruct.

    [Fact]
    public void SourceLink_FromShareLink_KeepsTheWholeLink()
    {
        const string link =
            "vless://11223344-5566-7788-99aa-bbccddeeff00@example.com:443?type=tcp&security=tls&sni=cdn.example.com#node";

        IProxyClient client = Proxy.Create(link);

        Assert.Equal(link, client.SourceLink);
        // And the reason SourceLink has to exist: ProxyUri has dropped everything that makes the
        // node reachable — the uuid, the sni, the transport.
        Assert.Equal("vless://example.com:443/", client.ProxyUri.ToString());
        Assert.DoesNotContain("cdn.example.com", client.ProxyUri.ToString());
    }

    [Fact]
    public void SourceLink_FromUri_KeepsTheOriginalText()
    {
        const string link = "socks5://user:pass@example.com:1080";

        IProxyClient client = Proxy.Create(new Uri(link));

        Assert.Equal(link, client.SourceLink);
    }

    [Fact]
    public void SourceLink_FromExplicitSettings_IsNull()
    {
        IProxyClient client = Proxy.Create(ProxyType.Socks5, "example.com", 1080, credentials: null);

        Assert.Null(client.SourceLink);
    }

    [Theory]
    [InlineData(ProxyType.Vless)]
    [InlineData(ProxyType.Vmess)]
    [InlineData(ProxyType.Trojan)]
    [InlineData(ProxyType.Shadowsocks)]
    public void Create_ShareLinkFamilyFromHostAndPort_IsRejected(ProxyType type)
    {
        // These carry a uuid, a security mode, a cipher and a transport. Host and port cannot
        // express them, and silently building a client that cannot connect would be worse than
        // saying so. With credentials too: Shadowsocks looks like user/password, and is not.
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => Proxy.Create(type, "example.com", 443, credentials: null));
        Assert.Contains("Shadowsocks", ex.Message);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => Proxy.Create(type, "example.com", 443, new NetworkCredential("aes-256-gcm", "password")));
    }

    [Fact]
    public void ProxyType_Shadowsocks_IsAppendedNotInserted()
    {
        // The enum has no explicit values: inserting a member renumbers everything after it, a
        // silent breaking change for anything that persisted the number.
        Assert.Equal(8, (int)ProxyType.Shadowsocks);
        Assert.Equal(7, (int)ProxyType.Trojan);
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
