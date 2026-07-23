using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using QuickProxyNet.Tests.Helpers;

// CA2022 ("avoid inexact reads") warns whenever a single ReadAsync is expected to fill a
// buffer. Chunk-at-a-time delivery is exactly what these tests assert, so the analyzer is
// off for this file.
#pragma warning disable CA2022

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the VMess configuration layer (<see cref="VmessShareLink"/>,
/// <see cref="VmessOptions"/>) and the client that ties the wire pieces together
/// (<see cref="VmessClient"/>).
///
/// The handshake is exercised END-TO-END against the real <see cref="VmessClient"/>: the
/// test acts as the SERVER. It opens the sealed request header the client wrote — using
/// only the shared UUID, exactly as a v2ray inbound would — recovers the randomly
/// generated session keys from it, and seals a response header plus body chunks with
/// those recovered keys. That works despite <see cref="VmessClient"/> having no seam for
/// injecting fixed randomness, so no production API was weakened to make it testable.
///
/// All UUIDs, hosts and payloads are synthetic.
/// </summary>
public class VmessClientTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";
    private const string ProxyHost = "proxy.example.com";
    private const int ProxyPort = 443;

    // ================================ share-link fixtures ================================

    private static string Link(string json)
        => "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

    private static string LinkUrlSafeUnpadded(string json)
        => "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>A complete, realistic v2rayN payload with the port encoded as a string.</summary>
    private const string FullJson = """
        {"v":"2","ps":"my node","add":"cdn.example.com","port":"8443",
         "id":"11223344-5566-7788-99aa-bbccddeeff00","aid":"0","scy":"aes-128-gcm",
         "net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"real.example.com"}
        """;

    /// <summary>
    /// Chosen so its standard base64 contains BOTH '+' and '/' and two '=' pad characters:
    /// stripping the padding and translating to the URL-safe alphabet therefore exercises
    /// every branch of the decoder at once.
    /// </summary>
    private const string UrlSafeJson = """
        {"v":"2","ps":"?~?~?~","add":"a.example.com","port":"443","id":"11223344-5566-7788-99aa-bbccddeeff00","aid":"0","scy":"aes-128-gcm","net":"tcp","tls":"tls","sni":"real.example.com"}
        """;

    private static string MinimalJson(
        string id = Uuid, string add = ProxyHost, string port = "\"443\"", string extra = "")
        => $$"""{"add":"{{add}}","port":{{port}},"id":"{{id}}"{{extra}}}""";

    // ================================ share-link: accepts ================================

    [Fact]
    public void Parse_FullLink_PortAsString()
    {
        var o = VmessShareLink.Parse(Link(FullJson));

        Assert.Equal(Uuid, o.Id);
        Assert.Equal("cdn.example.com", o.Host);
        Assert.Equal(8443, o.Port);
        Assert.Equal(0, o.AlterId);
        Assert.Equal(VmessSecurityKind.Aes128Gcm, o.Security);
        Assert.Equal("tcp", o.Transport);
        Assert.True(o.IsRawTcp);
        Assert.True(o.UseTls);
        Assert.Equal("real.example.com", o.Sni);
        Assert.Equal("my node", o.Remark);
        Assert.False(o.AllowInsecure);
    }

    [Fact]
    public void Parse_PortAsJsonNumber()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(port: "8080")));
        Assert.Equal(8080, o.Port);
    }

    [Fact]
    public void Parse_UrlSafeBase64_WithoutPadding()
    {
        // Guard the fixture: if this ever stops holding, the test would silently stop
        // covering the URL-safe alphabet and the padding restoration.
        string standard = Convert.ToBase64String(Encoding.UTF8.GetBytes(UrlSafeJson));
        Assert.Contains('+', standard);
        Assert.Contains('/', standard);
        Assert.EndsWith("==", standard);

        var o = VmessShareLink.Parse(LinkUrlSafeUnpadded(UrlSafeJson));

        Assert.Equal("a.example.com", o.Host);
        Assert.Equal(443, o.Port);
        Assert.Equal("?~?~?~", o.Remark);
        Assert.Equal("real.example.com", o.Sni);
    }

    [Fact]
    public void Parse_StandardAndUrlSafe_AgreeExactly()
    {
        var standard = VmessShareLink.Parse(Link(UrlSafeJson));
        var urlSafe = VmessShareLink.Parse(LinkUrlSafeUnpadded(UrlSafeJson));

        Assert.Equal(standard.Id, urlSafe.Id);
        Assert.Equal(standard.Host, urlSafe.Host);
        Assert.Equal(standard.Port, urlSafe.Port);
        Assert.Equal(standard.Remark, urlSafe.Remark);
        Assert.Equal(standard.Security, urlSafe.Security);
    }

    [Fact]
    public void Parse_IgnoresWhitespaceInsideThePayload()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(MinimalJson()));
        string spaced = "vmess://" + encoded[..10] + "\r\n  " + encoded[10..];

        var o = VmessShareLink.Parse(spaced);
        Assert.Equal(ProxyHost, o.Host);
    }

    [Theory]
    [InlineData("\"auto\"", VmessSecurityKind.Auto)]
    [InlineData("\"AUTO\"", VmessSecurityKind.Auto)]
    [InlineData("\"\"", VmessSecurityKind.Auto)]
    [InlineData("\"aes-128-gcm\"", VmessSecurityKind.Aes128Gcm)]
    [InlineData("\"AES-128-GCM\"", VmessSecurityKind.Aes128Gcm)]
    [InlineData("\"chacha20-poly1305\"", VmessSecurityKind.ChaCha20Poly1305)]
    public void Parse_ScyVariants(string scy, VmessSecurityKind expected)
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: $",\"scy\":{scy}")));
        Assert.Equal(expected, o.Security);
    }

    [Fact]
    public void Parse_MissingScy_DefaultsToAuto()
    {
        Assert.Equal(VmessSecurityKind.Auto, VmessShareLink.Parse(Link(MinimalJson())).Security);
    }

    [Fact]
    public void Parse_SecurityFieldIsAnAliasForScy()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"security\":\"chacha20-poly1305\"")));
        Assert.Equal(VmessSecurityKind.ChaCha20Poly1305, o.Security);
    }

    [Theory]
    [InlineData(",\"tls\":\"tls\"", true)]
    [InlineData(",\"tls\":\"TLS\"", true)]
    [InlineData(",\"tls\":\"\"", false)]
    [InlineData(",\"tls\":\"none\"", false)]
    [InlineData("", false)]
    public void Parse_TlsFlag(string extra, bool expected)
    {
        Assert.Equal(expected, VmessShareLink.Parse(Link(MinimalJson(extra: extra))).UseTls);
    }

    [Fact]
    public void Parse_Sni_PrefersExplicitValue()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(
            extra: ",\"sni\":\"sni.example.com\",\"host\":\"host.example.com\"")));
        Assert.Equal("sni.example.com", o.Sni);
    }

    [Fact]
    public void Parse_Sni_FallsBackToHostField()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"host\":\"host.example.com\"")));
        Assert.Equal("host.example.com", o.Sni);
    }

    [Fact]
    public void Parse_Sni_FallsBackToAddress()
    {
        // Neither 'sni' nor 'host' present, and empty strings must not win either.
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"sni\":\"\",\"host\":\"\"")));
        Assert.Equal(ProxyHost, o.Sni);
    }

    [Fact]
    public void Parse_Alpn_CommaSeparatedString()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"alpn\":\"h2, http/1.1\"")));
        Assert.Equal(["h2", "http/1.1"], o.Alpn);
    }

    [Fact]
    public void Parse_Alpn_JsonArray()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"alpn\":[\"h2\",\"http/1.1\"]")));
        Assert.Equal(["h2", "http/1.1"], o.Alpn);
    }

    [Fact]
    public void Parse_Alpn_MissingOrEmpty_IsNull()
    {
        Assert.Null(VmessShareLink.Parse(Link(MinimalJson())).Alpn);
        Assert.Null(VmessShareLink.Parse(Link(MinimalJson(extra: ",\"alpn\":\"\""))).Alpn);
    }

    [Theory]
    [InlineData(",\"allowInsecure\":true")]
    [InlineData(",\"allowInsecure\":\"1\"")]
    [InlineData(",\"allowInsecure\":1")]
    [InlineData(",\"skip-cert-verify\":true")]
    public void Parse_AllowInsecure_Truthy(string extra)
    {
        Assert.True(VmessShareLink.Parse(Link(MinimalJson(extra: extra))).AllowInsecure);
    }

    [Theory]
    [InlineData("")]
    [InlineData(",\"allowInsecure\":false")]
    [InlineData(",\"allowInsecure\":\"0\"")]
    public void Parse_AllowInsecure_Falsy(string extra)
    {
        Assert.False(VmessShareLink.Parse(Link(MinimalJson(extra: extra))).AllowInsecure);
    }

    [Fact]
    public void Parse_IPv6Host_StripsBrackets()
    {
        var o = VmessShareLink.Parse(Link(MinimalJson(add: "[2001:db8::1]")));
        Assert.Equal("2001:db8::1", o.Host);
    }

    [Theory]
    [InlineData(",\"aid\":\"0\"")]
    [InlineData(",\"aid\":0")]
    [InlineData(",\"aid\":\"\"")]
    [InlineData(",\"alterId\":0")]
    [InlineData("")]
    public void Parse_AlterIdZero_IsAccepted(string extra)
    {
        Assert.Equal(0, VmessShareLink.Parse(Link(MinimalJson(extra: extra))).AlterId);
    }

    [Fact]
    public void Parse_NonTcpTransport_ParsesButIsNotRawTcp()
    {
        // Parsed so callers can inspect it; rejected at connect time, not here.
        var o = VmessShareLink.Parse(Link(MinimalJson(extra: ",\"net\":\"ws\"")));
        Assert.Equal("ws", o.Transport);
        Assert.False(o.IsRawTcp);
    }

    [Theory]
    [InlineData("tcp")]
    [InlineData("raw")]
    public void Parse_RawTcpTransports(string net)
    {
        Assert.True(VmessShareLink.Parse(Link(MinimalJson(extra: $",\"net\":\"{net}\""))).IsRawTcp);
    }

    // ================================ share-link: rejects ================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("vless://11223344-5566-7788-99aa-bbccddeeff00@example.com:443")]
    [InlineData("trojan://pw@example.com:443")]
    [InlineData("vmess://")]
    [InlineData("vmess://!!!not-base64!!!")]
    [InlineData("vmess://a")]
    public void TryParse_RejectsMalformedLinks(string link)
    {
        Assert.False(VmessShareLink.TryParse(link, out _));
    }

    [Fact]
    public void TryParse_RejectsInvalidJson()
    {
        Assert.False(VmessShareLink.TryParse(Link("{\"add\":\"a.com\","), out _));
        Assert.False(VmessShareLink.TryParse(Link("not json at all"), out _));
    }

    [Fact]
    public void TryParse_RejectsNonObjectJson()
    {
        Assert.False(VmessShareLink.TryParse(Link("[1,2,3]"), out _));
        Assert.False(VmessShareLink.TryParse(Link("\"a string\""), out _));
    }

    [Fact]
    public void TryParse_RejectsMissingOrInvalidId()
    {
        Assert.False(VmessShareLink.TryParse(
            Link("""{"add":"a.example.com","port":"443"}"""), out _));
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(id: "")), out _));
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(id: "not-a-uuid")), out _));
        Assert.False(VmessShareLink.TryParse(
            Link(MinimalJson(id: "11223344-5566-7788-99aa-bbccddeeff")), out _));
    }

    [Theory]
    [InlineData("")]                  // missing entirely
    [InlineData("\"\"")]              // empty string
    [InlineData("\"abc\"")]           // not a number
    [InlineData("0")]                 // out of range
    [InlineData("-1")]
    [InlineData("65536")]
    [InlineData("null")]
    public void TryParse_RejectsMissingOrInvalidPort(string port)
    {
        string json = port.Length == 0
            ? $$"""{"add":"{{ProxyHost}}","id":"{{Uuid}}"}"""
            : MinimalJson(port: port);

        Assert.False(VmessShareLink.TryParse(Link(json), out _));
    }

    [Fact]
    public void TryParse_RejectsMissingAddress()
    {
        Assert.False(VmessShareLink.TryParse(
            Link($$"""{"port":"443","id":"{{Uuid}}"}"""), out _));
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(add: "")), out _));
    }

    [Theory]
    [InlineData(",\"aid\":\"1\"")]
    [InlineData(",\"aid\":1")]
    [InlineData(",\"aid\":64")]
    [InlineData(",\"alterId\":16")]
    public void TryParse_RejectsNonZeroAlterId(string extra)
    {
        // AEAD-only: a non-zero alterId means legacy MD5 auth, which is NOT implemented.
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(extra: extra)), out _));

        var ex = Assert.Throws<FormatException>(() =>
            VmessShareLink.Parse(Link(MinimalJson(extra: extra))));
        Assert.Contains("alterId", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryParse_RejectsUnparseableAlterId()
    {
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(extra: ",\"aid\":\"abc\"")), out _));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("zero")]
    [InlineData("aes-128-cfb")]
    [InlineData("bogus")]
    public void TryParse_RejectsUnknownScy(string scy)
    {
        // Silently defaulting would change how the body is protected without telling anyone.
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(extra: $",\"scy\":\"{scy}\"")), out _));
    }

    [Fact]
    public void TryParse_RejectsRealityAndHeaderObfuscation()
    {
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(extra: ",\"tls\":\"reality\"")), out _));
        Assert.False(VmessShareLink.TryParse(Link(MinimalJson(extra: ",\"type\":\"http\"")), out _));

        // "none" and an absent value are the supported header types.
        Assert.True(VmessShareLink.TryParse(Link(MinimalJson(extra: ",\"type\":\"none\"")), out _));
    }

    [Fact]
    public void Parse_ThrowsFormatExceptionWithAReason()
    {
        var ex = Assert.Throws<FormatException>(() => VmessShareLink.Parse("vmess://%%%"));
        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }

    // ================================ options ================================

    [Fact]
    public void ResolveSecurity_MapsExplicitKinds()
    {
        Assert.Equal(VmessSecurity.Aes128Gcm, Options(VmessSecurityKind.Aes128Gcm).ResolveSecurity());
        Assert.Equal(VmessSecurity.ChaCha20Poly1305,
            Options(VmessSecurityKind.ChaCha20Poly1305).ResolveSecurity());
    }

    [Fact]
    public void ResolveSecurity_AutoPicksAnAvailableAeadCipher()
    {
        VmessSecurity resolved = Options(VmessSecurityKind.Auto).ResolveSecurity();

        Assert.True(resolved is VmessSecurity.Aes128Gcm or VmessSecurity.ChaCha20Poly1305);
        Assert.True(resolved == VmessSecurity.Aes128Gcm
            ? AesGcm.IsSupported
            : ChaCha20Poly1305.IsSupported);

        // Auto must never reach the wire as security type 2.
        Assert.NotEqual(2, (byte)resolved);
    }

    private static VmessOptions Options(
        VmessSecurityKind security = VmessSecurityKind.Aes128Gcm,
        string transport = "tcp",
        int alterId = 0,
        string id = Uuid)
        => new()
        {
            Id = id,
            Host = ProxyHost,
            Port = ProxyPort,
            Security = security,
            AlterId = alterId,
            Transport = transport
        };

    // ================================ client construction ================================

    [Fact]
    public void Client_NullOptions_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new VmessClient(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-uuid")]
    [InlineData("11223344-5566-7788-99aa-bbccddeeff")]
    public void Client_InvalidUuid_ThrowsAtConstruction(string id)
    {
        Assert.Throws<ArgumentException>(() => new VmessClient(Options(id: id)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public void Client_NonZeroAlterId_ThrowsAtConstruction(int alterId)
    {
        var ex = Assert.Throws<ArgumentException>(() => new VmessClient(Options(alterId: alterId)));
        Assert.Contains("alterId", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Client_ExposesTypeAndOptions()
    {
        VmessOptions options = Options();
        var client = new VmessClient(options);

        Assert.Equal(ProxyType.Vmess, client.Type);
        Assert.Equal(ProxyHost, client.ProxyHost);
        Assert.Equal(ProxyPort, client.ProxyPort);
        Assert.Same(options, client.Options);
        Assert.Equal("vmess", client.ProxyUri.Scheme);
    }

    [Fact]
    public void Client_IPv6Host_ConstructsWithoutThrowing()
    {
        var client = VmessClient.FromShareLink(Link(MinimalJson(add: "[2001:db8::1]")));
        Assert.Equal("2001:db8::1", client.ProxyHost);
    }

    [Fact]
    public void FromShareLink_CreatesClient()
    {
        var client = VmessClient.FromShareLink(Link(FullJson));
        Assert.Equal("cdn.example.com", client.Options.Host);
        Assert.Equal(8443, client.Options.Port);
        Assert.True(client.Options.UseTls);
    }

    /// <summary>
    /// Builds a link that <see cref="Uri"/> can actually parse. A VMess payload is
    /// base64 JSON, not a host, so <see cref="Uri"/> rejects anything containing '='
    /// padding or longer than its host-length limit — which is most real links. Trailing
    /// whitespace is legal JSON, so pad until the encoding is alphanumeric-only.
    /// </summary>
    private static string UriLink(string json)
    {
        for (int pad = 0; pad < 3; pad++)
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(json + new string(' ', pad)));
            if (encoded.AsSpan().IndexOfAny('+', '/', '=') < 0)
                return "vmess://" + encoded;
        }

        throw new InvalidOperationException("No Uri-safe encoding of the payload was found.");
    }

    [Fact]
    public void Factory_CreatesVmessClient()
    {
        string link = UriLink(MinimalJson(add: "cdn.example.com", port: "8443",
            extra: ",\"scy\":\"aes-128-gcm\",\"tls\":\"tls\""));

        var client = ProxyClientFactory.Instance.Create(new Uri(link));

        var vmess = Assert.IsType<VmessClient>(client);
        Assert.Equal(ProxyType.Vmess, vmess.Type);
        Assert.Equal("cdn.example.com", vmess.Options.Host);
        Assert.Equal(8443, vmess.Options.Port);
        Assert.Equal(VmessSecurityKind.Aes128Gcm, vmess.Options.Security);
        Assert.True(vmess.Options.UseTls);
    }

    [Fact]
    public void Factory_InvalidVmessUri_Throws()
    {
        var uri = new Uri(UriLink(MinimalJson(extra: ",\"aid\":\"1\"")));
        Assert.Throws<FormatException>(() => ProxyClientFactory.Instance.Create(uri));
    }

    [Fact]
    public void Factory_LongVmessLink_CannotBeExpressedAsAUri()
    {
        // Documents the limitation the factory's XML docs call out: a full v2rayN payload
        // exceeds the Uri host-length limit, so callers must use FromShareLink instead.
        Assert.False(Uri.TryCreate(Link(FullJson), UriKind.Absolute, out _));
        Assert.Equal("cdn.example.com", VmessClient.FromShareLink(Link(FullJson)).Options.Host);
    }

    [Theory]
    [InlineData("ws")]
    [InlineData("grpc")]
    [InlineData("h2")]
    [InlineData("httpupgrade")]
    public async Task Client_UnsupportedTransport_ThrowsNotSupported_BeforeWritingAnything(string net)
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: $",\"net\":\"{net}\"")));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync(transport, "target.example.com", 80, CancellationToken.None).AsTask());

        // EnsureSupported must run before any byte hits the wire and before any read.
        Assert.Empty(transport.Written);
        Assert.Equal(0, transport.ReadCount);
        Assert.Equal(0, transport.DisposeCount);
    }

    [Fact]
    public async Task Client_NullStream_ThrowsArgumentNull()
    {
        var client = new VmessClient(Options());
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => client.ConnectAsync(null!, "target.example.com", 80, CancellationToken.None).AsTask());
    }

    // ================================ end-to-end handshake ================================

    [Fact]
    public async Task Handshake_WritesOnlyTheSealedRequestHeader_AndReadsNothing()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        // Nothing was read: the response header is deferred to the first read, because a
        // real server does not flush it until the target produces data.
        Assert.Equal(0, transport.ReadCount);

        ParsedRequest request = OpenRequest(transport.Written, Uuid);

        // Exactly one header, 58 + L bytes, and no body chunk.
        Assert.Equal(58 + request.CommandSectionLength, transport.Written.Length);

        Assert.Equal(0x01, request.Version);
        Assert.Equal(VmessRequest.CommandTcp, request.Command);
        Assert.Equal(0x00, request.Reserved);
        Assert.Equal("mc.example.com", request.Host);
        Assert.Equal(25565, request.Port);
        Assert.Equal(0x02, request.AddressType); // domain
        Assert.InRange(request.PaddingLength, 0, 15);

        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_SendsBaselineOptionByte_NotTheMaskedPaddedProfile()
    {
        // THE critical interop assertion: VmessStream implements only the baseline framing
        // (plain uint16 lengths, no padding, no authenticated length). Announcing v2ray's
        // usual 0x1D (S|M|P|A) would make the server mask every chunk length with SHAKE128
        // and append padding, desynchronizing the reader on the very first chunk.
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson()));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);
        ParsedRequest request = OpenRequest(transport.Written, Uuid);

        Assert.Equal(0x01, request.Option);
        Assert.Equal(VmessRequest.OptionChunkStream, request.Option);
        Assert.NotEqual(VmessRequest.DefaultOption, request.Option);

        // Every framing-changing flag must be clear.
        Assert.Equal(0, request.Option & VmessRequest.OptionChunkMasking);
        Assert.Equal(0, request.Option & VmessRequest.OptionGlobalPadding);
        Assert.Equal(0, request.Option & VmessRequest.OptionAuthenticatedLength);

        await body.DisposeAsync();
    }

    [Theory]
    [InlineData("aes-128-gcm", VmessRequest.SecurityAes128Gcm)]
    [InlineData("chacha20-poly1305", VmessRequest.SecurityChaCha20Poly1305)]
    public async Task Handshake_WritesTheRequestedSecurityNibble(string scy, byte expected)
    {
        if (expected == VmessRequest.SecurityChaCha20Poly1305 && !ChaCha20Poly1305.IsSupported)
            return; // gated exactly like the implementation

        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: $",\"scy\":\"{scy}\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        Assert.Equal(expected, OpenRequest(transport.Written, Uuid).Security);
        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_AutoResolvesToAConcreteCipherOnTheWire()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"auto\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);
        byte security = OpenRequest(transport.Written, Uuid).Security;

        // Never 2 (AUTO) or 0 (UNKNOWN): the client resolves before serializing.
        Assert.True(security is VmessRequest.SecurityAes128Gcm or VmessRequest.SecurityChaCha20Poly1305);
        Assert.Equal((byte)client.Options.ResolveSecurity(), security);

        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_TargetIPv4_UsesAtyp01()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson()));

        Stream body = await client.ConnectAsync(transport, "192.0.2.10", 443, CancellationToken.None);
        ParsedRequest request = OpenRequest(transport.Written, Uuid);

        Assert.Equal(0x01, request.AddressType);
        Assert.Equal("192.0.2.10", request.Host);
        Assert.Equal(443, request.Port);

        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_TargetIPv6_UsesAtyp03()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson()));

        Stream body = await client.ConnectAsync(transport, "2001:db8::1", 8080, CancellationToken.None);
        ParsedRequest request = OpenRequest(transport.Written, Uuid);

        Assert.Equal(0x03, request.AddressType);
        Assert.Equal("2001:db8::1", request.Host);

        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_RequestHeaderIsFreshPerConnection()
    {
        var client = VmessClient.FromShareLink(Link(MinimalJson()));

        var first = new ScriptedDuplexStream();
        var second = new ScriptedDuplexStream();
        Stream a = await client.ConnectAsync(first, "mc.example.com", 25565, CancellationToken.None);
        Stream b = await client.ConnectAsync(second, "mc.example.com", 25565, CancellationToken.None);

        // Different AuthID, connection nonce and body keys every time.
        Assert.NotEqual(Convert.ToHexStringLower(first.Written), Convert.ToHexStringLower(second.Written));

        ParsedRequest one = OpenRequest(first.Written, Uuid);
        ParsedRequest two = OpenRequest(second.Written, Uuid);
        Assert.NotEqual(one.BodyKey, two.BodyKey);
        Assert.NotEqual(one.BodyIv, two.BodyIv);

        await a.DisposeAsync();
        await b.DisposeAsync();
    }

    [Theory]
    [InlineData("aes-128-gcm")]
    [InlineData("chacha20-poly1305")]
    public async Task Handshake_FullRoundTrip_ReadsResponseHeaderThenBody(string scy)
    {
        if (scy == "chacha20-poly1305" && !ChaCha20Poly1305.IsSupported)
            return;

        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: $",\"scy\":\"{scy}\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        // --- act as the server: recover the session from the sealed request header ---
        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        var session = new ServerSession(request);

        transport.Enqueue(session.SealResponseHeader(request.RespV, option: 0, command: 0, commandData: []));
        transport.Enqueue(session.SealResponseChunk(0, "hello"u8.ToArray()));
        transport.Enqueue(session.SealResponseChunk(1, "world"u8.ToArray()));
        transport.Enqueue(session.SealResponseChunk(2, []));           // in-band EOF

        // --- read the payload back through the client's stream ---
        var received = new List<byte>();
        byte[] buffer = new byte[64];
        int read;
        while ((read = await body.ReadAsync(buffer)) > 0)
            received.AddRange(buffer[..read]);

        Assert.Equal("helloworld"u8.ToArray(), received);
        Assert.Equal(0, transport.Unread);

        // --- and check the client's own writes are chunks the server could open ---
        transport.ClearWritten();
        await body.WriteAsync("ping"u8.ToArray());
        Assert.Equal("ping"u8.ToArray(), session.OpenRequestChunk(0, transport.Written));

        await body.DisposeAsync();
    }

    [Fact]
    public async Task Handshake_ResponseVerifierMismatch_FailsOnTheFirstRead()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        var session = new ServerSession(request);

        // Echo the WRONG verifier byte.
        transport.Enqueue(session.SealResponseHeader((byte)(request.RespV ^ 0xFF), 0, 0, []));
        transport.Enqueue(session.SealResponseChunk(0, "hello"u8.ToArray()));

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => await body.ReadAsync(new byte[64]));

        Assert.Equal(ProxyErrorCode.AuthFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task Handshake_TamperedResponseHeader_FailsAuthentication()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        var session = new ServerSession(request);

        byte[] header = session.SealResponseHeader(request.RespV, 0, 0, []);
        header[^1] ^= 0xFF;
        transport.Enqueue(header);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => await body.ReadAsync(new byte[64]));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task Handshake_ResponseHeaderIsReadExactlyOnce()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        var session = new ServerSession(request);

        transport.Enqueue(session.SealResponseHeader(request.RespV, 0, 0, []));
        transport.Enqueue(session.SealResponseChunk(0, "a"u8.ToArray()));
        transport.Enqueue(session.SealResponseChunk(1, "b"u8.ToArray()));
        transport.Enqueue(session.SealResponseChunk(2, []));

        byte[] buffer = new byte[16];
        Assert.Equal(1, await body.ReadAsync(buffer));
        Assert.Equal((byte)'a', buffer[0]);

        // The second read must go straight to the body: if the header were re-read the
        // chunk bytes would be consumed as a header and fail.
        Assert.Equal(1, await body.ReadAsync(buffer));
        Assert.Equal((byte)'b', buffer[0]);
        Assert.Equal(0, await body.ReadAsync(buffer));
    }

    [Fact]
    public async Task Handshake_ServerCommandData_IsParsedAndSkipped()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);

        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        var session = new ServerSession(request);

        // A dynamic-port style directive: a minimal client parses and ignores it.
        transport.Enqueue(session.SealResponseHeader(request.RespV, option: 0x11, command: 0x01,
            commandData: [0xAA, 0xBB, 0xCC]));
        transport.Enqueue(session.SealResponseChunk(0, "hello"u8.ToArray()));
        transport.Enqueue(session.SealResponseChunk(1, []));

        byte[] buffer = new byte[64];
        int read = await body.ReadAsync(buffer);

        Assert.Equal("hello"u8.ToArray(), buffer[..read]);
        Assert.Equal(0, await body.ReadAsync(buffer));
    }

    [Fact]
    public async Task Handshake_DisposingTheBodyStream_DisposesTheTransport()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson(extra: ",\"scy\":\"aes-128-gcm\"")));

        Stream body = await client.ConnectAsync(transport, "mc.example.com", 25565, CancellationToken.None);
        await body.DisposeAsync();

        Assert.Equal(1, transport.DisposeCount);

        // Disposal also emits the authenticated empty chunk that closes the write half.
        ParsedRequest request = OpenRequest(transport.Written, Uuid);
        byte[] terminator = transport.Written[(58 + request.CommandSectionLength)..];
        Assert.Equal(18, terminator.Length);
        Assert.Equal(16, BinaryPrimitives.ReadUInt16BigEndian(terminator));
    }

    [Fact]
    public async Task Handshake_HonorsCancellation()
    {
        var transport = new ScriptedDuplexStream();
        var client = VmessClient.FromShareLink(Link(MinimalJson()));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.ConnectAsync(transport, "mc.example.com", 25565, cts.Token).AsTask());

        // The transport is disposed on the failed handshake rather than leaked.
        Assert.Equal(1, transport.DisposeCount);
    }

    // ================================ server-side reference ================================

    /// <summary>
    /// The fields a VMess server recovers from a sealed request header.
    /// </summary>
    private sealed record ParsedRequest(
        byte Version,
        byte[] BodyIv,
        byte[] BodyKey,
        byte RespV,
        byte Option,
        int PaddingLength,
        byte Security,
        byte Reserved,
        byte Command,
        int Port,
        byte AddressType,
        string Host,
        int CommandSectionLength);

    /// <summary>
    /// Opens a sealed VMessAEAD request header exactly as <c>proxy/vmess/aead/encrypt.go</c>
    /// would, using only the shared UUID, and verifies the inner FNV-1a checksum.
    /// </summary>
    private static ParsedRequest OpenRequest(byte[] wire, string uuid)
    {
        Assert.True(wire.Length >= VmessRequest.SealOverhead, "request header is truncated");

        byte[] cmdKey = new byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(uuid, cmdKey);

        byte[] authId = wire[..16];
        byte[] connectionNonce = wire[34..42];

        // --- length AEAD (AAD = authid) ---
        byte[] lengthKey = new byte[16];
        byte[] lengthNonce = new byte[12];
        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key_Length"u8, authId, connectionNonce, lengthKey);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce_Length"u8, authId, connectionNonce, lengthNonce);

        byte[] lengthPlaintext = new byte[2];
        using (var gcm = new AesGcm(lengthKey, 16))
            gcm.Decrypt(lengthNonce, wire.AsSpan(16, 2), wire.AsSpan(18, 16), lengthPlaintext, authId);

        int length = BinaryPrimitives.ReadUInt16BigEndian(lengthPlaintext);

        // --- payload AEAD (AAD = authid) ---
        byte[] payloadKey = new byte[16];
        byte[] payloadNonce = new byte[12];
        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key"u8, authId, connectionNonce, payloadKey);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce"u8, authId, connectionNonce, payloadNonce);

        byte[] data = new byte[length];
        using (var gcm = new AesGcm(payloadKey, 16))
            gcm.Decrypt(payloadNonce, wire.AsSpan(42, length), wire.AsSpan(42 + length, 16), data, authId);

        // --- command section ---
        int paddingLength = data[35] >> 4;
        int port = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(38, 2));
        byte addressType = data[40];

        int offset = 41;
        string host;
        switch (addressType)
        {
            case 0x01:
                host = new IPAddress(data.AsSpan(offset, 4)).ToString();
                offset += 4;
                break;
            case 0x02:
                int domainLength = data[offset++];
                host = Encoding.UTF8.GetString(data, offset, domainLength);
                offset += domainLength;
                break;
            case 0x03:
                host = new IPAddress(data.AsSpan(offset, 16)).ToString();
                offset += 16;
                break;
            default:
                throw new InvalidOperationException($"Unexpected address type 0x{addressType:X2}.");
        }

        offset += paddingLength;

        // The inner FNV-1a-32 covers everything up to itself, padding included.
        Assert.Equal(offset + 4, length);
        Assert.Equal(
            Fnv1a32.Compute(data.AsSpan(0, offset)),
            BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4)));

        return new ParsedRequest(
            Version: data[0],
            BodyIv: data[1..17],
            BodyKey: data[17..33],
            RespV: data[33],
            Option: data[34],
            PaddingLength: paddingLength,
            Security: (byte)(data[35] & 0x0F),
            Reserved: data[36],
            Command: data[37],
            Port: port,
            AddressType: addressType,
            Host: host,
            CommandSectionLength: length);
    }

    /// <summary>
    /// The server half of a VMess session: derives the response keys from the recovered
    /// request keys and seals response headers and body chunks the client must accept.
    /// </summary>
    private sealed class ServerSession
    {
        private readonly byte[] _requestBodyKey;
        private readonly byte[] _requestBodyIv;
        private readonly byte[] _responseBodyKey = new byte[16];
        private readonly byte[] _responseBodyIv = new byte[16];
        private readonly VmessSecurity _security;

        public ServerSession(ParsedRequest request)
        {
            _requestBodyKey = request.BodyKey;
            _requestBodyIv = request.BodyIv;
            _security = (VmessSecurity)request.Security;

            // responseBodyKey/IV = SHA256(requestBodyKey/IV)[0:16].
            VmessResponse.DeriveBodyKeys(
                _requestBodyKey, _requestBodyIv, _responseBodyKey, _responseBodyIv);
        }

        public byte[] SealResponseHeader(byte respV, byte option, byte command, byte[] commandData)
        {
            byte[] lengthKey = new byte[16];
            byte[] lengthIv = new byte[12];
            byte[] headerKey = new byte[16];
            byte[] headerIv = new byte[12];
            VmessResponse.DeriveHeaderKeys(
                _responseBodyKey, _responseBodyIv, lengthKey, lengthIv, headerKey, headerIv);

            byte[] plaintext = new byte[4 + commandData.Length];
            plaintext[0] = respV;
            plaintext[1] = option;
            plaintext[2] = command;
            plaintext[3] = (byte)commandData.Length;
            commandData.CopyTo(plaintext, 4);

            byte[] wire = new byte[18 + plaintext.Length + 16];

            byte[] lengthPlaintext = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)plaintext.Length);
            using (var gcm = new AesGcm(lengthKey, 16))
                gcm.Encrypt(lengthIv, lengthPlaintext, wire.AsSpan(0, 2), wire.AsSpan(2, 16));

            using (var gcm = new AesGcm(headerKey, 16))
                gcm.Encrypt(headerIv, plaintext,
                    wire.AsSpan(18, plaintext.Length), wire.AsSpan(18 + plaintext.Length, 16));

            return wire;
        }

        /// <summary>Seals a server→client body chunk: <c>uint16BE(sealedLen) ‖ sealed</c>.</summary>
        public byte[] SealResponseChunk(ushort counter, byte[] plaintext)
        {
            byte[] wire = new byte[2 + plaintext.Length + 16];
            BinaryPrimitives.WriteUInt16BigEndian(wire, (ushort)(plaintext.Length + 16));

            Transform(_responseBodyKey, _responseBodyIv, counter, plaintext,
                wire.AsSpan(2, plaintext.Length), wire.AsSpan(2 + plaintext.Length, 16), encrypt: true);

            return wire;
        }

        /// <summary>Opens a client→server body chunk and returns its plaintext.</summary>
        public byte[] OpenRequestChunk(ushort counter, byte[] wire)
        {
            int sealedLength = BinaryPrimitives.ReadUInt16BigEndian(wire);
            Assert.Equal(wire.Length, 2 + sealedLength);

            int plaintextLength = sealedLength - 16;
            byte[] plaintext = new byte[plaintextLength];

            Transform(_requestBodyKey, _requestBodyIv, counter, wire.AsSpan(2, plaintextLength).ToArray(),
                plaintext, wire.AsSpan(2 + plaintextLength, 16), encrypt: false);

            return plaintext;
        }

        // nonce = uint16BE(counter) ‖ bodyIV[2:12]; AAD is empty.
        private void Transform(
            byte[] key, byte[] iv, ushort counter, byte[] input,
            Span<byte> output, Span<byte> tag, bool encrypt)
        {
            byte[] nonce = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
            iv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

            if (_security == VmessSecurity.Aes128Gcm)
            {
                using var gcm = new AesGcm(key, 16);
                if (encrypt)
                    gcm.Encrypt(nonce, input, output, tag);
                else
                    gcm.Decrypt(nonce, input, tag, output);
                return;
            }

            byte[] expanded = new byte[32];
            VmessBodyKeys.ExpandChaCha20Key(key, expanded);
            using var chacha = new ChaCha20Poly1305(expanded);
            if (encrypt)
                chacha.Encrypt(nonce, input, output, tag);
            else
                chacha.Decrypt(nonce, input, tag, output);
        }
    }
}
