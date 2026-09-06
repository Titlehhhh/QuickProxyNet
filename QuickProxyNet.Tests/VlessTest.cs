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
    public void UuidCodec_RejectsSmallDestination()
    {
        Span<byte> dest = stackalloc byte[8];
        Assert.False(UuidCodec.TryWriteBigEndian(Uuid, dest));
    }

    // === Non-UUID ids ===
    //
    // Xray's common/uuid.ParseString does NOT reject a short non-UUID id: for length 1..30
    // it derives UUIDv5(nil-namespace, utf8(id)). Both endpoints derive the same value, so
    // such ids work end to end and ~0.3% of real-world VLESS links use one.
    //
    // The vectors below come from an independent UUIDv5 implementation that was first
    // validated against the published RFC 4122 vector
    // uuid5(NAMESPACE_DNS, "python.org") == 886313e1-3b8a-5372-9b90-0c9aee199e5d.
    // DockerProtocolTests.Vless_NonUuidId_DerivesSameIdAsXray proves it against real Xray.

    [Theory]
    [InlineData("not-a-uuid", "9b70e619-d7b3-55b1-b743-756ebd573b4e")]
    [InlineData("a", "35b65f33-a679-5e76-af3c-273ea349ede4")]
    [InlineData("password", "750db9b2-386a-5d2f-a2ea-64504781c566")]
    [InlineData("MyUser123", "dec19763-791a-5f34-9a6b-a09c0630022c")]
    public void UuidCodec_DerivesUuidV5_ForShortNonUuidId(string id, string expected)
    {
        Span<byte> dest = stackalloc byte[16];
        Assert.True(UuidCodec.TryWriteBigEndian(id, dest));

        // The derived value is a canonical UUIDv5: version nibble 5, RFC 4122 variant.
        Assert.Equal(0x50, dest[6] & 0xF0);
        Assert.Equal(0x80, dest[8] & 0xC0);

        Span<byte> expectedBytes = stackalloc byte[16];
        Guid.Parse(expected).TryWriteBytes(expectedBytes, bigEndian: true, out _);
        Assert.Equal(expectedBytes.ToArray(), dest.ToArray());
    }

    [Fact]
    public void UuidCodec_Derivation_IsDeterministic()
    {
        Span<byte> a = stackalloc byte[16];
        Span<byte> b = stackalloc byte[16];
        Assert.True(UuidCodec.TryWriteBigEndian("stable-id", a));
        Assert.True(UuidCodec.TryWriteBigEndian("stable-id", b));
        Assert.Equal(a.ToArray(), b.ToArray());
    }

    [Theory]
    [InlineData(0)]   // empty: upstream errors
    [InlineData(31)]  // too long to derive, too short to be canonical: upstream errors
    [InlineData(37)]  // longer than any canonical form: upstream errors
    [InlineData(40)]
    public void UuidCodec_RejectsLengthsUpstreamRejects(int length)
    {
        Span<byte> dest = stackalloc byte[16];
        Assert.False(UuidCodec.TryWriteBigEndian(new string('x', length), dest));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(30)]  // longest id upstream will derive from
    public void UuidCodec_AcceptsDerivableLengths(int length)
    {
        Span<byte> dest = stackalloc byte[16];
        Assert.True(UuidCodec.TryWriteBigEndian(new string('x', length), dest));
    }

    [Fact]
    public void UuidCodec_Rejects32To36CharsThatAreNotHex()
    {
        // Inside the canonical length window there is no derivation fallback: upstream
        // parses these as hex and fails, and so must we.
        Span<byte> dest = stackalloc byte[16];
        Assert.False(UuidCodec.TryWriteBigEndian(new string('z', 32), dest));
        Assert.False(UuidCodec.TryWriteBigEndian(new string('z', 36), dest));
    }

    [Fact]
    public void UuidCodec_CanonicalUuid_IsNotDerived()
    {
        // A real UUID must still round-trip to its own bytes, not to a hash of its text.
        Span<byte> dest = stackalloc byte[16];
        Assert.True(UuidCodec.TryWriteBigEndian(Uuid, dest));
        Assert.Equal(UuidBigEndian, dest.ToArray());
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
        Assert.Equal(TransportKind.RawTcp, o.TransportKind);
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
    [InlineData("vless://@example.com:443")]
    public void TryParse_RejectsInvalid(string link)
    {
        Assert.False(VlessShareLink.TryParse(link, out _));
    }

    [Fact]
    public void TryParse_ShortNonUuidId_IsAccepted_AndKeptVerbatim()
    {
        // Xray maps a 1..30 character id to UUIDv5(nil, id) rather than rejecting it.
        // The options keep the id as written; the derivation happens at the wire encoder.
        Assert.True(VlessShareLink.TryParse("vless://not-a-uuid@example.com:443", out var o));
        Assert.Equal("not-a-uuid", o.Id);
    }

    [Fact]
    public void TryParse_MalformedUri_ReportsTheRealProblem_NotTheScheme()
    {
        // Broken generators leave "&key=value" in the authority, before the first '?'.
        // The old message blamed the scheme, which sends the reader hunting in the wrong
        // place; 87 of 15031 real-world vless links hit exactly this path.
        var ex = Assert.Throws<FormatException>(() =>
            VlessShareLink.Parse("vless://11223344-5566-7788-99aa-bbccddeeff00@1.2.3.4:443&type=raw?type=tcp"));
        Assert.Contains("not a well-formed URI", ex.Message);
        Assert.DoesNotContain("must start with", ex.Message);
    }

    [Fact]
    public void Parse_UnknownSecurity_Rejected_NoSilentPlaintextDowngrade()
    {
        // A typo like security=tsl must NOT silently fall back to plaintext.
        Assert.False(VlessShareLink.TryParse($"vless://{Uuid}@example.com:443?security=tsl", out _));
    }

    // === HTML-escaped links (&amp; as the separator) ===
    //
    // 68 vless and 10 trojan links in a 17k real-world corpus are published HTML-escaped,
    // 51 of them REALITY. Splitting on '&' leaves keys named "amp;security", "amp;flow".
    // Treating those as unknown keys is NOT harmless: the node then looks like plain
    // security=none with no flow, passes EnsureSupported, and the client connects in
    // cleartext — sending the UUID unencrypted to a REALITY server.

    [Fact]
    public void Parse_HtmlEscapedSeparators_DoNotSilentlyDowngradeRealityToPlaintext()
    {
        var o = VlessShareLink.Parse(
            $"vless://{Uuid}@example.com:443?type=tcp&amp;security=reality&amp;pbk=PUBKEY" +
            "&amp;sid=ab12&amp;flow=xtls-rprx-vision");

        Assert.Equal(VlessSecurity.Reality, o.Security);
        Assert.Equal("PUBKEY", o.RealityPublicKey);
        Assert.Equal("ab12", o.RealityShortId);
        Assert.Equal("xtls-rprx-vision", o.Flow);
    }

    /// <summary>
    /// The escaped link having parsed as REALITY is only half the guarantee. The other half is
    /// that connecting actually starts a TLS handshake — the failure this guards against is the
    /// UUID going out in cleartext to a server expecting REALITY.
    /// </summary>
    [Fact]
    public void HtmlEscapedRealityLink_StartsATlsHandshake_NotACleartextRequest()
    {
        // A syntactically real key, so the handshake gets as far as writing a ClientHello.
        const string PublicKey = "BhsV4NiigG9rrk98hJnJHPJ7TQ6Iy1WqUykGF0z9I2g";
        var o = VlessShareLink.Parse(
            $"vless://{Uuid}@example.com:443?type=tcp&amp;security=reality&amp;pbk={PublicKey}" +
            "&amp;sid=ab12&amp;sni=www.example.org");

        Assert.Equal(VlessSecurity.Reality, o.Security);

        // A MemoryStream answers every read with "end of stream", so the handshake cannot
        // complete — but what was written before it failed is the point.
        var transport = new MemoryStream();
        Assert.ThrowsAny<Exception>(() =>
            new VlessClient(o).ConnectAsync(transport, "example.com", 443).AsTask().GetAwaiter().GetResult());

        byte[] written = transport.ToArray();
        Assert.NotEmpty(written);
        Assert.Equal(0x16, written[0]);                              // TLS handshake record
        Assert.Equal(0x03, written[1]);
        Assert.DoesNotContain(UuidBigEndian, IndexesOf(written));    // and no cleartext credential

        static IEnumerable<byte[]> IndexesOf(byte[] haystack) =>
            Enumerable.Range(0, Math.Max(haystack.Length - UuidBigEndian.Length + 1, 0))
                .Select(i => haystack.AsSpan(i, UuidBigEndian.Length).ToArray());
    }

    [Fact]
    public void Parse_HtmlEscapedSeparators_TlsIsNotLostEither()
    {
        var o = VlessShareLink.Parse(
            $"vless://{Uuid}@example.com:443?type=tcp&amp;security=tls&amp;sni=cdn.example.com");
        Assert.Equal(VlessSecurity.Tls, o.Security);
        Assert.Equal("cdn.example.com", o.Sni);
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
    public void Client_UnusableUuid_ThrowsAtConstruction()
    {
        // 31 chars: outside Xray's 1..30 derivation window and not a canonical UUID.
        var bad = new VlessOptions { Id = new string('x', 31), Host = "example.com", Port = 443 };
        Assert.Throws<ArgumentException>(() => new VlessClient(bad));
    }

    [Fact]
    public void Client_ShortNonUuidId_ConstructsWithoutThrowing()
    {
        // The client must accept exactly what the share-link parser accepts; validating
        // with Guid.TryParse here would reject links that parsed fine a moment earlier.
        var o = new VlessOptions { Id = "not-a-uuid", Host = "example.com", Port = 443 };
        var client = new VlessClient(o);
        Assert.Equal("example.com", client.ProxyHost);
    }

    // === VlessClient response header (via FakeProxyStream) ===
    //
    // The response header is validated on the FIRST READ, not inside ConnectAsync. Neither
    // Xray nor sing-box flushes `ver + addonsLen` until the target has produced data, so an
    // eager read deadlocks every client-speaks-first protocol (HTTP, TLS, Minecraft) — the
    // same trap VmessResponseStream already documents. That was measured against both servers
    // and is pinned end to end by DockerProtocolTests.
    //
    // The assertions below therefore drive a read; the exceptions and error codes they expect
    // are unchanged.

    [Fact]
    public async Task Client_ServerClosesEarly_WrapsAsProxyProtocolException()
    {
        // Server sends only 1 byte then EOF (typical wrong-UUID drop).
        var stream = new FakeProxyStream([0x00]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var tunnel = await client.ConnectAsync(stream, "example.org", 443, CancellationToken.None);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => Assert.Equal(0, await tunnel.ReadAsync(new byte[16])));
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task Client_None_WritesRequest_AndDefersResponseHeader()
    {
        // Server response: ver=00, addonsLen=00, then the target's payload.
        var stream = new FakeProxyStream([0x00, 0x00, 0x41, 0x42]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443?security=none"));

        var tunnel = await client.ConnectAsync(stream, "mc.example.com", 25565, CancellationToken.None);

        // The request must already be on the wire when ConnectAsync returns...
        var written = stream.WrittenBytes;
        Assert.Equal(0x00, written[0]);                        // version
        Assert.Equal(UuidBigEndian, written[1..17]);           // uuid big-endian
        Assert.Equal(0x01, written[18]);                       // TCP command

        // ...while the response header has not been touched yet.
        Assert.NotSame(stream, tunnel);

        // The first read consumes the header and hands back only the target's bytes.
        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal(2, read);
        Assert.Equal([0x41, 0x42], buffer[..read]);
    }

    [Fact]
    public async Task Client_None_DrainsAddons()
    {
        // ver=00, addonsLen=03, then 3 addon bytes, then the target's payload.
        var stream = new FakeProxyStream([0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x5A]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var tunnel = await client.ConnectAsync(stream, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal(1, read);
        Assert.Equal(0x5A, buffer[0]);   // addons were drained, not returned as payload
    }

    [Fact]
    public async Task Client_BadResponseVersion_Throws()
    {
        var stream = new FakeProxyStream([0x01, 0x00]); // wrong version
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443"));

        var tunnel = await client.ConnectAsync(stream, "example.org", 443, CancellationToken.None);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => Assert.Equal(0, await tunnel.ReadAsync(new byte[16])));
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task Client_None_DoesNotReadResponseHeaderDuringConnect()
    {
        // The regression guard for the deadlock: a server that sends NOTHING must still let
        // ConnectAsync complete, because a real VLESS server sends nothing until the client's
        // request has reached the target.
        var stream = new FakeProxyStream([]);
        var client = new VlessClient(VlessShareLink.Parse($"vless://{Uuid}@example.com:443?security=none"));

        var tunnel = await client.ConnectAsync(stream, "example.org", 443, CancellationToken.None);

        Assert.NotNull(tunnel);
        Assert.NotEmpty(stream.WrittenBytes);
    }

    /// <summary>
    /// A <c>pbk</c> that is not a key is a configuration error and must be reported as one —
    /// naming the value, before anything is written — rather than as "REALITY not supported"
    /// (which it is) or as an ArgumentException from inside the handshake.
    /// </summary>
    [Theory]
    [InlineData("x")]                                        // not base64url at all
    [InlineData("AAAA")]                                     // decodes to 3 bytes, not 32
    public async Task Client_Reality_MalformedPublicKey_ThrowsFormatBeforeWriting(string pbk)
    {
        var stream = new FakeProxyStream([0x00, 0x00]);
        var client = new VlessClient(
            VlessShareLink.Parse($"vless://{Uuid}@example.com:443?security=reality&pbk={pbk}"));

        var ex = await Assert.ThrowsAsync<FormatException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());

        Assert.Contains(pbk, ex.Message);
    }

    /// <summary>
    /// REALITY failures are proxy errors like any other: the type carries a code a caller can
    /// branch on, and the two codes it uses mean different things to act on.
    /// </summary>
    [Fact]
    public void RealityHandshakeException_IsAProxyProtocolExceptionWithACode()
    {
        Assert.IsAssignableFrom<ProxyProtocolException>(new RealityHandshakeException("x"));
        Assert.Equal(ProxyErrorCode.InvalidResponse, new RealityHandshakeException("x").ErrorCode);
        Assert.Equal(ProxyErrorCode.AuthFailed,
            new RealityHandshakeException(ProxyErrorCode.AuthFailed, "x").ErrorCode);
    }

    /// <summary>
    /// The user id is the credential. A mistyped real one lands in the same error as garbage
    /// does, and the error text ends up in logs — so the text must not contain the id.
    /// </summary>
    [Fact]
    public void Client_BadUserId_DoesNotEchoTheIdInTheError()
    {
        const string almostAUuid = "11223344-5566-7788-99aa-bbccddeeff00-SECRETTAIL";

        var ex = Assert.Throws<ArgumentException>(() =>
            new VlessClient(new VlessOptions { Id = almostAUuid, Host = "example.com", Port = 443 }));

        Assert.DoesNotContain("SECRETTAIL", ex.Message);
        Assert.DoesNotContain("11223344", ex.Message);
        Assert.Contains("user id", ex.Message);
    }

    [Fact]
    public async Task Client_UnsupportedTransport_Throws()
    {
        var stream = new FakeProxyStream([0x00, 0x00]);
        var client = new VlessClient(
            VlessShareLink.Parse($"vless://{Uuid}@example.com:443?type=grpc&security=none"));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync(stream, "example.org", 443, CancellationToken.None).AsTask());
    }

    // === Factory ===

    [Fact]
    public void Factory_CreatesVlessClient()
    {
        var client = Proxy.Create(
            new Uri($"vless://{Uuid}@example.com:443?security=tls&sni=a.com"));
        var vless = Assert.IsType<VlessClient>(client);
        Assert.Equal(ProxyType.Vless, vless.Type);
        Assert.Equal(VlessSecurity.Tls, vless.Options.Security);
    }
}
