using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class VlessTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";

    // Big-endian bytes are exactly the hex digits of the canonical string, in order.
    private static readonly byte[] UuidBigEndian =
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    ];

    // === UuidCodec ===

    [Fact]
    public void UuidCodec_WritesBigEndian_NotMixedEndian()
    {
        Span<byte> dest = stackalloc byte[16];
        UuidCodec.WriteBigEndian(Uuid, dest);
        Assert.Equal(UuidBigEndian, dest.ToArray());
    }

    [Fact]
    public void UuidCodec_RejectsGarbage()
    {
        Span<byte> dest = stackalloc byte[16];
        Assert.False(UuidCodec.TryWriteBigEndian("not-a-uuid", dest));
    }

    [Fact]
    public void UuidCodec_RejectsSmallDestination()
    {
        Span<byte> dest = stackalloc byte[8];
        Assert.False(UuidCodec.TryWriteBigEndian(Uuid, dest));
    }

    // === ProxyAddress (VLESS type codes: 01 IPv4, 02 domain, 03 IPv6) ===

    [Fact]
    public void ProxyAddress_IPv4()
    {
        Span<byte> buf = stackalloc byte[ProxyAddress.MaxLength];
        int n = ProxyAddress.WriteTypeAndAddress("1.2.3.4", buf, 0x01, 0x02, 0x03);
        Assert.Equal(5, n);
        Assert.Equal([0x01, 1, 2, 3, 4], buf.Slice(0, n).ToArray());
    }

    [Fact]
    public void ProxyAddress_Domain()
    {
        Span<byte> buf = stackalloc byte[ProxyAddress.MaxLength];
        int n = ProxyAddress.WriteTypeAndAddress("mc.example.com", buf, 0x01, 0x02, 0x03);
        Assert.Equal(0x02, buf[0]);        // domain type
        Assert.Equal(14, buf[1]);          // length
        Assert.Equal("mc.example.com"u8.ToArray(), buf.Slice(2, 14).ToArray());
        Assert.Equal(2 + 14, n);
    }

    [Fact]
    public void ProxyAddress_IPv6()
    {
        Span<byte> buf = stackalloc byte[ProxyAddress.MaxLength];
        int n = ProxyAddress.WriteTypeAndAddress("2001:db8::1", buf, 0x01, 0x02, 0x03);
        Assert.Equal(0x03, buf[0]);        // IPv6 type
        Assert.Equal(1 + 16, n);
    }

    // === VlessHelper.BuildRequest ===

    [Fact]
    public void BuildRequest_ProducesExactWireBytes()
    {
        Span<byte> buf = stackalloc byte[512];
        int n = VlessHelper.BuildRequest(buf, Uuid, "mc.example.com", 25565);

        byte[] expected =
        [
            0x00,                                           // version
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // uuid
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x00,                                           // addons length
            0x01,                                           // command TCP
            0x63, 0xDD,                                     // port 25565
            0x02,                                           // domain address type
            0x0E,                                           // domain length 14
            0x6D, 0x63, 0x2E, 0x65, 0x78, 0x61, 0x6D, // "mc.example.com"
            0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D
        ];
        Assert.Equal(expected, buf.Slice(0, n).ToArray());
    }

    // === VlessShareLink.Parse ===

    [Fact]
    public void Parse_SecurityNone_Defaults()
    {
        var o = VlessShareLink.Parse($"vless://{Uuid}@example.com:443?type=tcp&security=none#node1");
        Assert.Equal(Uuid, o.Id);
        Assert.Equal("example.com", o.Host);
        Assert.Equal(443, o.Port);
        Assert.Equal(VlessSecurity.None, o.Security);
        Assert.True(o.IsRawTcp);
        Assert.Equal("node1", o.Remark);
    }

    [Fact]
    public void Parse_Tls_WithSniAndAlpn()
    {
        var o = VlessShareLink.Parse(
            $"vless://{Uuid}@1.2.3.4:8443?type=tcp&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#tls-node");
        Assert.Equal(VlessSecurity.Tls, o.Security);
        Assert.Equal("cdn.example.com", o.Sni);
        Assert.NotNull(o.Alpn);
        Assert.Equal(["h2", "http/1.1"], o.Alpn);
    }

    [Fact]
    public void Parse_Reality_KeepsKeys()
    {
        var o = VlessShareLink.Parse(
            $"vless://{Uuid}@example.com:443?security=reality&pbk=PUBKEY&sid=ab12&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#r");
        Assert.Equal(VlessSecurity.Reality, o.Security);
        Assert.Equal("PUBKEY", o.RealityPublicKey);
        Assert.Equal("ab12", o.RealityShortId);
        Assert.Equal("chrome", o.Fingerprint);
        Assert.Equal("xtls-rprx-vision", o.Flow);
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://example.com:443")]
    [InlineData("vless://not-a-uuid@example.com:443")]
    [InlineData("vless://@example.com:443")]
    public void TryParse_RejectsInvalid(string link)
    {
        Assert.False(VlessShareLink.TryParse(link, out _));
    }

    [Fact]
    public void Parse_UnknownSecurity_Rejected_NoSilentPlaintextDowngrade()
    {
        // A typo like security=tsl must NOT silently fall back to plaintext.
        Assert.False(VlessShareLink.TryParse($"vless://{Uuid}@example.com:443?security=tsl", out _));
    }

    [Fact]
    public void Parse_IPv6Host_StripsBrackets()
    {
        var o = VlessShareLink.Parse($"vless://{Uuid}@[2001:db8::1]:443?security=none");
        Assert.Equal("2001:db8::1", o.Host);
    }

    // === VlessClient construction ===

    [Fact]
    public void Client_NullOptions_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new VlessClient(null!));
    }

    [Fact]
    public void Client_IPv6Host_ConstructsWithoutThrowing()
    {
        // The base ProxyClient ctor must bracket the IPv6 literal when composing ProxyUri.
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@[2001:db8::1]:443?security=none"));
        Assert.Equal("2001:db8::1", client.ProxyHost);
        Assert.Equal(443, client.ProxyPort);
    }

    [Fact]
    public void Client_InvalidUuid_ThrowsAtConstruction()
    {
        var bad = new VlessOptions { Id = "not-a-uuid", Host = "example.com", Port = 443 };
        Assert.Throws<ArgumentException>(() => new VlessClient(bad));
    }

    [Fact]
    public async Task Client_ServerClosesEarly_WrapsAsProxyProtocolException()
    {
        // Server sends only 1 byte then EOF (typical wrong-UUID drop).
        var stream = new FakeProxyStream([0x00]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    // === VlessClient (none path via FakeProxyStream) ===

    [Fact]
    public async Task Client_None_WritesRequest_And_ReturnsStream()
    {
        // Server response: ver=00, addonsLen=00.
        var stream = new FakeProxyStream([0x00, 0x00]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443?security=none"));

        var result = await client.ConnectAsync(stream, "mc.example.com", 25565, CancellationToken.None);

        Assert.Same(stream, result);
        var written = stream.WrittenBytes;
        Assert.Equal(0x00, written[0]);                        // version
        Assert.Equal(UuidBigEndian, written[1..17]);          // uuid big-endian
        Assert.Equal(0x01, written[18]);                       // TCP command
    }

    [Fact]
    public async Task Client_None_DrainsAddons()
    {
        // ver=00, addonsLen=03, then 3 addon bytes.
        var stream = new FakeProxyStream([0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var result = await client.ConnectAsync(stream, "example.org", 443, CancellationToken.None);
        Assert.Same(stream, result);
    }

    [Fact]
    public async Task Client_BadResponseVersion_Throws()
    {
        var stream = new FakeProxyStream([0x01, 0x00]); // wrong version
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task Client_Reality_ThrowsNotSupported()
    {
        var stream = new FakeProxyStream([0x00, 0x00]);
        var client = new VlessClient(
            VlessShareLink.Parse($"vless://{Uuid}@example.com:443?security=reality&pbk=x"));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Client_UnsupportedTransport_Throws()
    {
        var stream = new FakeProxyStream([0x00, 0x00]);
        var client = new VlessClient(
            VlessShareLink.Parse($"vless://{Uuid}@example.com:443?type=ws&security=none"));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
    }

    // === Factory ===

    [Fact]
    public void Factory_CreatesVlessClient()
    {
        var client = ProxyClientFactory.Instance.Create(
            new Uri($"vless://{Uuid}@example.com:443?security=tls&sni=a.com"));
        var vless = Assert.IsType<VlessClient>(client);
        Assert.Equal(ProxyType.Vless, vless.Type);
        Assert.Equal(VlessSecurity.Tls, vless.Options.Security);
    }
}
