using System.Text;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class TrojanTest
{
    private const string Password = "mysecretpassword";

    // hex(SHA224("mysecretpassword")), computed independently with Python hashlib.
    private const string ExpectedHashHex = "aec5b55fda5d423724436969d6d318d5f2a2ea8891872fbaa2ee4fcf";

    // === TrojanShareLink.Parse ===

    [Fact]
    public void Parse_BasicPassword()
    {
        var o = TrojanShareLink.Parse("trojan://secret@example.com:443#node1");
        Assert.Equal("secret", o.Password);
        Assert.Equal("example.com", o.Host);
        Assert.Equal(443, o.Port);
        Assert.Equal("tcp", o.Transport);
        Assert.Equal(TransportKind.RawTcp, o.TransportKind);
        Assert.Equal("node1", o.Remark);
        Assert.False(o.AllowInsecure);
    }

    [Fact]
    public void Parse_UrlEncodedPassword()
    {
        // "p@ss w0rd/1" percent-encoded in the userinfo.
        var o = TrojanShareLink.Parse("trojan://p%40ss%20w0rd%2F1@example.com:443");
        Assert.Equal("p@ss w0rd/1", o.Password);
    }

    [Fact]
    public void Parse_SniAlpnAllowInsecureType()
    {
        var o = TrojanShareLink.Parse(
            "trojan://pw@cdn.example.com:8443?sni=real.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1&type=tcp#t");
        Assert.Equal("real.example.com", o.Sni);
        Assert.NotNull(o.Alpn);
        Assert.Equal(["h2", "http/1.1"], o.Alpn);
        Assert.True(o.AllowInsecure);
        Assert.Equal("tcp", o.Transport);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("1")]
    public void Parse_AllowInsecure_Truthy(string value)
    {
        var o = TrojanShareLink.Parse($"trojan://pw@example.com:443?allowInsecure={value}");
        Assert.True(o.AllowInsecure);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("false")]
    [InlineData("no")]
    public void Parse_AllowInsecure_Falsy(string value)
    {
        var o = TrojanShareLink.Parse($"trojan://pw@example.com:443?insecure={value}");
        Assert.False(o.AllowInsecure);
    }

    [Fact]
    public void Parse_PeerAlias_MapsToSni()
    {
        var o = TrojanShareLink.Parse("trojan://pw@example.com:443?peer=real.example.com");
        Assert.Equal("real.example.com", o.Sni);
    }

    [Fact]
    public void Parse_IPv6Host_StripsBrackets()
    {
        var o = TrojanShareLink.Parse("trojan://pw@[2001:db8::1]:443");
        Assert.Equal("2001:db8::1", o.Host);
    }

    [Theory]
    [InlineData("")]
    [InlineData("vless://pw@example.com:443")]
    [InlineData("trojan://@example.com:443")]
    [InlineData("trojan://pw@example.com")]
    public void TryParse_RejectsInvalid(string link)
    {
        Assert.False(TrojanShareLink.TryParse(link, out _));
    }

    // === TrojanHelper.BuildRequest ===

    [Fact]
    public void BuildRequest_ProducesExactWireBytes()
    {
        Span<byte> buf = stackalloc byte[512];
        int n = TrojanHelper.BuildRequest(buf, Password, "mc.example.com", 25565);

        // The full expected request: 56 hex bytes | CRLF | CMD | ATYP+addr | port | CRLF.
        var expected = new List<byte>();
        expected.AddRange(Encoding.ASCII.GetBytes(ExpectedHashHex)); // 56 lowercase-hex ASCII bytes
        expected.Add(0x0D);                                          // CR
        expected.Add(0x0A);                                          // LF
        expected.Add(0x01);                                          // CMD CONNECT
        expected.Add(0x03);                                          // ATYP domain (SOCKS5-style)
        expected.Add(0x0E);                                          // domain length 14
        expected.AddRange(Encoding.ASCII.GetBytes("mc.example.com"));
        expected.Add(0x63);                                          // port 25565 hi
        expected.Add(0xDD);                                          // port 25565 lo
        expected.Add(0x0D);                                          // CR
        expected.Add(0x0A);                                          // LF

        Assert.Equal(expected.ToArray(), buf.Slice(0, n).ToArray());
    }

    [Fact]
    public void BuildRequest_HashIs56LowercaseHexBytes()
    {
        Span<byte> buf = stackalloc byte[512];
        TrojanHelper.BuildRequest(buf, Password, "1.2.3.4", 80);

        string hash = Encoding.ASCII.GetString(buf.Slice(0, 56).ToArray());
        Assert.Equal(ExpectedHashHex, hash);
        Assert.Equal(0x0D, buf[56]);
        Assert.Equal(0x0A, buf[57]);
    }

    [Fact]
    public void BuildRequest_IPv4_UsesSocks5AddressType()
    {
        Span<byte> buf = stackalloc byte[512];
        int n = TrojanHelper.BuildRequest(buf, Password, "1.2.3.4", 443);

        // After hash(56) + CRLF(2) + CMD(1) = offset 59.
        Assert.Equal(0x01, buf[58]);              // CMD
        Assert.Equal(0x01, buf[59]);              // ATYP IPv4
        Assert.Equal([1, 2, 3, 4], buf.Slice(60, 4).ToArray());
        Assert.Equal(0x01, buf[64]);              // port 443 hi
        Assert.Equal(0xBB, buf[65]);              // port 443 lo
        Assert.Equal(0x0D, buf[66]);
        Assert.Equal(0x0A, buf[67]);
        Assert.Equal(68, n);
    }

    // === TrojanClient construction / gating ===

    [Fact]
    public void Client_NullOptions_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new TrojanClient(null!));
    }

    [Fact]
    public void Client_EmptyPassword_ThrowsAtConstruction()
    {
        var bad = new TrojanOptions { Password = "", Host = "example.com", Port = 443 };
        Assert.Throws<ArgumentException>(() => new TrojanClient(bad));
    }

    [Fact]
    public void Client_IPv6Host_ConstructsWithoutThrowing()
    {
        // The base ProxyClient ctor must bracket the IPv6 literal when composing ProxyUri.
        var client = new TrojanClient(TrojanShareLink.Parse("trojan://secret@[2001:db8::1]:443"));
        Assert.Equal("2001:db8::1", client.ProxyHost);
        Assert.Equal(443, client.ProxyPort);
    }

    [Fact]
    public async Task Client_UnsupportedTransport_ThrowsNotSupported_BeforeTls()
    {
        // A FakeProxyStream that is NOT a TLS endpoint: if EnsureSupported did not run first,
        // AuthenticateAsClientAsync would fail with a different exception.
        var stream = new FakeProxyStream([]);
        var client = new TrojanClient(
            TrojanShareLink.Parse("trojan://pw@example.com:443?type=grpc"));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
    }

    // === Factory ===

    [Fact]
    public void Factory_CreatesTrojanClient()
    {
        var client = Proxy.Create(
            new Uri("trojan://pw@example.com:443?sni=a.com&allowInsecure=1"));
        var trojan = Assert.IsType<TrojanClient>(client);
        Assert.Equal(ProxyType.Trojan, trojan.Type);
        Assert.Equal("pw", trojan.Options.Password);
        Assert.True(trojan.Options.AllowInsecure);
    }

    [Fact]
    public void FromShareLink_CreatesClient()
    {
        var client = TrojanClient.FromShareLink("trojan://pw@example.com:443");
        Assert.Equal("example.com", client.Options.Host);
        Assert.Equal(443, client.Options.Port);
    }
}
