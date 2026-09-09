using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

/// <summary>
/// <c>ss://</c> parsing — both grammars and every base64 quirk the wild produces — and the
/// by-name rejection of ciphers and plugins this library does not speak.
/// </summary>
public class ShadowsocksShareLinkTest
{
    // base64url("aes-128-gcm:test"), the SIP002 spec's own example, unpadded.
    private const string Aes128TestUrlSafe = "YWVzLTEyOC1nY206dGVzdA";

    // base64("aes-256-gcm:password"), standard alphabet, padded.
    private const string Aes256PasswordPadded = "YWVzLTI1Ni1nY206cGFzc3dvcmQ=";

    // "aes-256-gcm:¯¡¾" — a password whose standard base64 contains both '+' and '/'.
    private const string PlusSlashStandard = "YWVzLTI1Ni1nY206wq/CocK+";
    private const string PlusSlashUrlSafe = "YWVzLTI1Ni1nY206wq_CocK-";
    private const string PlusSlashPassword = "¯¡¾";

    // ================================ SIP002 ================================

    [Fact]
    public void Parse_Sip002_Base64UrlUnpadded_TheSpecExample()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@192.168.100.1:8888#Example1");

        Assert.Equal("aes-128-gcm", o.Method);
        Assert.Equal("test", o.Password);
        Assert.Equal("192.168.100.1", o.Host);
        Assert.Equal(8888, o.Port);
        Assert.Equal("Example1", o.Remark);
        Assert.Null(o.Plugin);
    }

    [Fact]
    public void Parse_Sip002_StandardAlphabetWithPadding()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes256PasswordPadded}@example.com:8388");

        Assert.Equal("aes-256-gcm", o.Method);
        Assert.Equal("password", o.Password);
    }

    [Fact]
    public void Parse_Sip002_PercentEncodedPadding_IsDecodedBeforeBase64()
    {
        // Outline and Python's urlsafe_b64encode keep the '=' and it arrives as %3D.
        var o = ShadowsocksShareLink.Parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ%3D@example.com:8388");

        Assert.Equal("aes-256-gcm", o.Method);
        Assert.Equal("password", o.Password);
    }

    [Fact]
    public void Parse_Sip002_BothAlphabets_DecodeToTheSamePassword()
    {
        var standard = ShadowsocksShareLink.Parse($"ss://{PlusSlashStandard}@example.com:8388");
        var urlSafe = ShadowsocksShareLink.Parse($"ss://{PlusSlashUrlSafe}@example.com:8388");

        Assert.Equal(PlusSlashPassword, standard.Password);
        Assert.Equal(PlusSlashPassword, urlSafe.Password);
        Assert.Equal("aes-256-gcm", standard.Method);
    }

    [Fact]
    public void Parse_Sip002_PlainUserInfo_PercentEncoded()
    {
        // ':' after percent-decoding means plain 'method:password'; the password keeps its own ':' and '@'.
        var o = ShadowsocksShareLink.Parse("ss://aes-256-gcm:p%40ss%3Aw0rd%2F1@example.com:8388#n");

        Assert.Equal("aes-256-gcm", o.Method);
        Assert.Equal("p@ss:w0rd/1", o.Password);
        Assert.Equal("example.com", o.Host);
    }

    [Fact]
    public void Parse_Sip002_PlainUserInfo_ColonPercentEncoded()
    {
        var o = ShadowsocksShareLink.Parse("ss://aes-128-gcm%3Asecret@example.com:8388");

        Assert.Equal("aes-128-gcm", o.Method);
        Assert.Equal("secret", o.Password);
    }

    [Theory]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com")]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com/")]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com#tag")]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com/?unsupported=ignored#tag")]
    public void Parse_MissingPort_DefaultsTo8388(string link)
    {
        var o = ShadowsocksShareLink.Parse(link);
        Assert.Equal("example.com", o.Host);
        Assert.Equal(8388, o.Port);
        Assert.Equal(8388, ShadowsocksShareLink.DefaultPort);
    }

    [Fact]
    public void Parse_BracketedIPv6_StripsTheBrackets()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@[2001:db8::1]:9000");
        Assert.Equal("2001:db8::1", o.Host);
        Assert.Equal(9000, o.Port);

        var noPort = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@[2001:db8::1]");
        Assert.Equal("2001:db8::1", noPort.Host);
        Assert.Equal(8388, noPort.Port);
    }

    /// <summary>
    /// An unbracketed IPv6 literal has no unambiguous reading: <c>2001:db8::1:9000</c> is itself a
    /// valid address (the <c>9000</c> is a hextet) and almost certainly meant <c>[2001:db8::1]:9000</c>.
    /// SIP002 requires the brackets, <see cref="Uri"/> and shadowsocks-rust refuse the bare form,
    /// and so does this parser — connecting to a guessed address on a guessed port is worse than
    /// an error that says how to write it.
    /// </summary>
    [Theory]
    [InlineData("2001:db8::1:9000")]
    [InlineData("2001:db8::1:8388")]
    [InlineData("2001:db8::1")]
    public void Parse_UnbracketedIPv6_IsRejected_NotGuessed(string hostPort)
    {
        string link = $"ss://{Aes128TestUrlSafe}@{hostPort}";

        Assert.False(ShadowsocksShareLink.TryParse(link, out var options));
        Assert.Null(options);

        var ex = Assert.Throws<FormatException>(() => ShadowsocksShareLink.Parse(link));
        Assert.Contains("[addr]:port", ex.Message);
    }

    [Fact]
    public void Parse_PercentEncodedTag_IsUnescaped()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@example.com:8388#My%20Node%20%F0%9F%9A%80");
        Assert.Equal("My Node \U0001F680", o.Remark);

        var empty = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@example.com:8388#");
        Assert.Null(empty.Remark);
    }

    [Fact]
    public void Parse_TrailingSlash_BeforeQueryAndFragment()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp#Example2");

        Assert.Equal("example.com", o.Host);
        Assert.Equal(8388, o.Port);
        Assert.Equal("obfs-local;obfs=http", o.Plugin);
        Assert.Equal("Example2", o.Remark);
    }

    [Fact]
    public void Parse_UnknownQueryKeys_AreIgnored()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@example.com:8388/?group=abc&udp=1&novalue");
        Assert.Null(o.Plugin);
    }

    [Fact]
    public void Parse_IsCaseInsensitiveAboutTheScheme_AndTrimsWhitespace()
    {
        var o = ShadowsocksShareLink.Parse($"  SS://{Aes128TestUrlSafe}@example.com:8388\n");
        Assert.Equal("example.com", o.Host);
    }

    // ================================ legacy ================================

    [Fact]
    public void Parse_Legacy_WholeAuthorityIsBase64()
    {
        // base64("aes-256-gcm:p@ss:w0rd@example.com:8388"): the raw password holds '@' and ':'.
        var o = ShadowsocksShareLink.Parse("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODg=#legacy");

        Assert.Equal("aes-256-gcm", o.Method);
        Assert.Equal("p@ss:w0rd", o.Password);
        Assert.Equal("example.com", o.Host);
        Assert.Equal(8388, o.Port);
        Assert.Equal("legacy", o.Remark);
    }

    [Theory]
    [InlineData("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODg")]     // unpadded
    [InlineData("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODg=/")]   // trailing slash
    [InlineData("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODg/#t")]  // both
    [InlineData("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODgK")]    // base64("…:8388\n"): what `echo | base64` makes
    [InlineData("ss://YWVzLTI1Ni1nY206cEBzczp3MHJkQGV4YW1wbGUuY29tOjgzODgg")]    // base64("…:8388 ")
    public void Parse_Legacy_PaddingAndTrailingSlashAreTolerated(string link)
    {
        var o = ShadowsocksShareLink.Parse(link);
        Assert.Equal("p@ss:w0rd", o.Password);
        Assert.Equal(8388, o.Port);
    }

    [Fact]
    public void Parse_Legacy_BracketedIPv6()
    {
        // base64("chacha20-ietf-poly1305:secret@[2001:db8::1]:9000")
        var o = ShadowsocksShareLink.Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXRAWzIwMDE6ZGI4OjoxXTo5MDAw");

        Assert.Equal("chacha20-ietf-poly1305", o.Method);
        Assert.Equal("secret", o.Password);
        Assert.Equal("2001:db8::1", o.Host);
        Assert.Equal(9000, o.Port);
    }

    // ================================ malformed ================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("vless://YWVzLTEyOC1nY206dGVzdA@example.com:8388")]
    [InlineData("ss://")]
    [InlineData("ss://@example.com:8388")]                                  // empty userinfo
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@")]                            // no host
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@:8388")]                       // empty host
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com:99999")]           // bad port
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com:0")]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@example.com:abc")]
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@[2001:db8::1")]                // unterminated bracket
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@[2001:db8::1]x:80")]           // junk after bracket
    [InlineData("ss://YWVzLTEyOC1nY206dGVzdA@2001:db8::zz:8388")]           // unbracketed, not an IPv6 address either
    [InlineData("ss://not!base64!@example.com:8388")]                       // neither base64 nor plain
    [InlineData("ss://YWJj@example.com:8388")]                              // base64("abc"): no ':'
    [InlineData("ss://:password@example.com:8388")]                         // empty method
    [InlineData("ss://aes-256-gcm:@example.com:8388")]                      // empty password
    [InlineData("ss://bm8tYXQtc2lnbg")]                                     // legacy base64("no-at-sign")
    public void TryParse_RejectsMalformed(string link)
    {
        Assert.False(ShadowsocksShareLink.TryParse(link, out var options));
        Assert.Null(options);
        Assert.Throws<FormatException>(() => ShadowsocksShareLink.Parse(link));
    }

    /// <summary>
    /// base64("aes:pw@host") is a well-formed legacy link with the default port. It parses; the
    /// unsupported cipher name is the client's business, not the parser's.
    /// </summary>
    [Fact]
    public void Parse_Legacy_MinimalHostWithoutPort_ParsesWithTheDefaultPort()
    {
        var o = ShadowsocksShareLink.Parse("ss://YWVzOnB3QGhvc3Q");

        Assert.Equal("aes", o.Method);
        Assert.Equal("pw", o.Password);
        Assert.Equal("host", o.Host);
        Assert.Equal(8388, o.Port);
    }

    /// <summary>Whatever a malformed link throws, the credential in it must not be in the message.</summary>
    [Theory]
    [InlineData("ss://aes-256-gcm:SECRETPASSWORD@:8388")]
    [InlineData("ss://aes-256-gcm:SECRETPASSWORD@example.com:99999")]
    [InlineData("ss://aes-256-gcm:SECRETPASSWORD@[2001:db8::1")]
    [InlineData("ss://rc4-md5:SECRETPASSWORD@example.com:8388")]
    [InlineData("ss://aes-256-gcm:SECRETPASSWORD@example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket")]
    [InlineData("ss://SECRETPASSWORD:aes-256-gcm@example.com:8388")]                      // swapped fields: the password lands where the cipher goes
    [InlineData("ss://SECRET%2FPASSWORD%3D:aes-256-gcm@example.com:8388")]                 // same, with characters no cipher name has
    [InlineData("ss://U0VDUkVUUEFTU1dPUkQ6YWVzLTI1Ni1nY20@example.com:8388")]              // same, base64("SECRETPASSWORD:aes-256-gcm")
    public void Errors_NeverEchoTheCredential(string link)
    {
        Exception ex = Assert.ThrowsAny<Exception>(() => ShadowsocksClient.FromShareLink(link));

        for (Exception? e = ex; e is not null; e = e.InnerException)
            Assert.DoesNotContain("SECRET", e.Message);
    }

    // ================================ cipher rejection ================================

    [Theory]
    [InlineData("2022-blake3-aes-128-gcm")]
    [InlineData("2022-blake3-aes-256-gcm")]
    [InlineData("2022-blake3-chacha20-poly1305")]
    [InlineData("2022-blake3-chacha8-poly1305")]
    [InlineData("table")]
    [InlineData("rc4")]
    [InlineData("rc4-md5")]
    [InlineData("chacha20")]
    [InlineData("chacha20-ietf")]
    [InlineData("salsa20")]
    [InlineData("bf-cfb")]
    [InlineData("aes-128-ctr")]
    [InlineData("aes-192-ctr")]
    [InlineData("aes-256-ctr")]
    [InlineData("aes-128-cfb")]
    [InlineData("aes-128-cfb1")]
    [InlineData("aes-128-cfb8")]
    [InlineData("aes-128-cfb128")]
    [InlineData("aes-192-cfb")]
    [InlineData("aes-256-cfb")]
    [InlineData("aes-256-cfb8")]
    [InlineData("aes-128-ofb")]
    [InlineData("aes-256-ofb")]
    [InlineData("camellia-128-cfb")]
    [InlineData("camellia-192-ctr")]
    [InlineData("camellia-256-ofb")]
    [InlineData("camellia-256-cfb128")]
    [InlineData("none")]
    [InlineData("plain")]
    [InlineData("xchacha20-ietf-poly1305")]
    [InlineData("aes-128-ccm")]
    [InlineData("aes-256-ccm")]
    [InlineData("aes-128-gcm-siv")]
    [InlineData("aes-256-gcm-siv")]
    [InlineData("sm4-gcm")]
    [InlineData("sm4-ccm")]
    [InlineData("totally-made-up-cipher")]
    [InlineData("chacha20-poly1305")]      // Xray's bare spelling; early libev meant the 64-bit-nonce draft by it
    [InlineData("AEAD_AES_128_GCM")]       // spec-table identifiers, never wire names
    [InlineData("AEAD_AES_256_GCM")]
    [InlineData("AEAD_CHACHA20_POLY1305")]
    [InlineData("aead_chacha20_poly1305")]
    public void UnsupportedCipher_IsRejectedByName_BeforeAnyByteIsWritten(string method)
    {
        // Plain userinfo: the name goes through percent-decoding untouched.
        string link = $"ss://{method}:pw@example.com:8388";
        var parsed = ShadowsocksShareLink.Parse(link);
        Assert.Equal(method, parsed.Method); // the parser keeps it; the client refuses it

        var ex = Assert.Throws<NotSupportedException>(() => ShadowsocksClient.FromShareLink(link));

        Assert.Contains(method, ex.Message);
        Assert.Contains("aes-256-gcm", ex.Message);
        Assert.Contains("chacha20-ietf-poly1305", ex.Message);

        if (method.StartsWith("2022-"))
            Assert.Contains("BLAKE3", ex.Message);
        if (method == "xchacha20-ietf-poly1305")
            Assert.Contains("XChaCha20", ex.Message);
        if (method is "none" or "plain")
            Assert.Contains("unencrypted", ex.Message);
        if (method is "rc4-md5" or "aes-256-cfb" or "table")
            Assert.Contains("stream cipher", ex.Message);
        if (method == "chacha20-poly1305")
            Assert.Contains("ambiguous", ex.Message);
        if (method.StartsWith("AEAD_") || method.StartsWith("aead_"))
            Assert.Contains("spec-table identifier", ex.Message);
    }

    [Fact]
    public void UnsupportedCipher_InBase64UserInfo_IsRejectedByName()
    {
        // base64url("2022-blake3-aes-256-gcm:somekey") and base64url("rc4-md5:passwd")
        var ex = Assert.Throws<NotSupportedException>(() =>
            ShadowsocksClient.FromShareLink("ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206c29tZWtleQ@example.com:8388"));
        Assert.Contains("2022-blake3-aes-256-gcm", ex.Message);

        ex = Assert.Throws<NotSupportedException>(() =>
            ShadowsocksClient.FromShareLink("ss://cmM0LW1kNTpwYXNzd2Q@example.com:8388"));
        Assert.Contains("rc4-md5", ex.Message);

        // base64("AEAD_CHACHA20_POLY1305:pw")
        ex = Assert.Throws<NotSupportedException>(() =>
            ShadowsocksClient.FromShareLink("ss://QUVBRF9DSEFDSEEyMF9QT0xZMTMwNTpwdw@example.com:8388"));
        Assert.Contains("AEAD_CHACHA20_POLY1305", ex.Message);
    }

    [Fact]
    public void UnsupportedCipher_IsRejectedAtConstruction_NotAtConnect()
    {
        // Nothing can have been written: the exception comes out of the constructor, and the
        // transport it would have written to does not even exist yet.
        var ex = Assert.Throws<NotSupportedException>(() => new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-256-cfb", Password = "pw", Host = "example.com", Port = 8388
        }));
        Assert.Contains("aes-256-cfb", ex.Message);
    }

    [Theory]
    [InlineData("aes-128-gcm", "aes-128-gcm", 16)]
    [InlineData("aes-192-gcm", "aes-192-gcm", 24)]
    [InlineData("aes-256-gcm", "aes-256-gcm", 32)]
    [InlineData("AES-256-GCM", "aes-256-gcm", 32)]
    [InlineData("chacha20-ietf-poly1305", "chacha20-ietf-poly1305", 32)]
    [InlineData("ChaCha20-IETF-Poly1305", "chacha20-ietf-poly1305", 32)]
    public void SupportedCipher_Resolves(string name, string canonical, int keySize)
    {
        var method = ShadowsocksCipher.Resolve(name);
        Assert.Equal(canonical, ShadowsocksCipher.Name(method));
        Assert.Equal(keySize, ShadowsocksCipher.KeySize(method));
    }

    // ================================ plugin rejection ================================

    [Theory]
    [InlineData("plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com", "obfs-local")]
    [InlineData("plugin=simple-obfs%3Bobfs%3Dtls", "simple-obfs")]
    [InlineData("plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Btls", "v2ray-plugin")]
    [InlineData("plugin=xray-plugin", "xray-plugin")]
    [InlineData("plugin=kcptun%3Bkey%3Dx", "kcptun")]
    [InlineData("plugin=GoQuiet%3BKey%3Dx", "GoQuiet")]
    [InlineData("plugin=Cloak", "Cloak")]
    [InlineData("plugin=gost-plugin", "gost-plugin")]
    public void Plugin_IsRejectedByName(string query, string pluginName)
    {
        string link = $"ss://{Aes128TestUrlSafe}@example.com:8388/?{query}#n";

        var parsed = ShadowsocksShareLink.Parse(link);
        Assert.StartsWith(pluginName, parsed.Plugin);

        var ex = Assert.Throws<NotSupportedException>(() => ShadowsocksClient.FromShareLink(link));
        Assert.Contains($"'{pluginName}'", ex.Message);
        Assert.Contains("obfuscated", ex.Message);
    }

    /// <summary>
    /// The HTML-escaped separator must not hide the plugin: <c>amp;plugin</c> dropped as an
    /// unknown key would connect as plain Shadowsocks to a server running obfs.
    /// </summary>
    [Fact]
    public void Plugin_BehindAnHtmlEscapedAmpersand_IsStillRejected()
    {
        string link = $"ss://{Aes128TestUrlSafe}@example.com:8388/?group=x&amp;plugin=v2ray-plugin%3Bmode%3Dwebsocket#n";

        Assert.Equal("v2ray-plugin;mode=websocket", ShadowsocksShareLink.Parse(link).Plugin);

        var ex = Assert.Throws<NotSupportedException>(() => ShadowsocksClient.FromShareLink(link));
        Assert.Contains("v2ray-plugin", ex.Message);
    }

    [Fact]
    public void Plugin_EmptyValue_IsNoPlugin()
    {
        var o = ShadowsocksShareLink.Parse($"ss://{Aes128TestUrlSafe}@example.com:8388/?plugin=");
        Assert.Null(o.Plugin);
        _ = new ShadowsocksClient(o);
    }

    // ================================ client construction ================================

    [Fact]
    public void Client_NullOptions_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() => new ShadowsocksClient(null!));
    }

    [Fact]
    public void Client_EmptyPassword_ThrowsAtConstruction()
    {
        var bad = new ShadowsocksOptions { Method = "aes-256-gcm", Password = "", Host = "example.com", Port = 8388 };
        Assert.Throws<ArgumentException>(() => new ShadowsocksClient(bad));
    }

    /// <summary>
    /// A missing cipher name on hand-built options is the caller's bug — the ArgumentException
    /// family — not a link naming a cipher this library cannot speak. The parser never produces
    /// an empty method, so only direct construction can reach this.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Client_EmptyMethod_ThrowsArgumentException_NotNotSupported(string? method)
    {
        var bad = new ShadowsocksOptions { Method = method!, Password = "pw", Host = "example.com", Port = 8388 };

        var ex = Assert.Throws<ArgumentException>(() => new ShadowsocksClient(bad));
        Assert.Contains("Method", ex.Message);
    }

    [Fact]
    public void Client_IPv6Host_ConstructsWithoutThrowing()
    {
        var client = ShadowsocksClient.FromShareLink($"ss://{Aes128TestUrlSafe}@[2001:db8::1]:8388");
        Assert.Equal("2001:db8::1", client.ProxyHost);
        Assert.Equal(8388, client.ProxyPort);
        Assert.Equal(ProxyType.Shadowsocks, client.Type);
        Assert.Equal("ss", client.ProxyUri.Scheme);
    }

    [Fact]
    public void FromShareLink_CreatesClient()
    {
        var client = ShadowsocksClient.FromShareLink($"ss://{Aes256PasswordPadded}@example.com:8388#node");
        Assert.Equal("example.com", client.Options.Host);
        Assert.Equal(8388, client.Options.Port);
        Assert.Equal("aes-256-gcm", client.Options.Method);
        Assert.Equal("password", client.Options.Password);
        Assert.Equal("node", client.Options.Remark);
    }

    [Fact]
    public void FromShareLink_Malformed_ThrowsFormat()
    {
        Assert.Throws<FormatException>(() => ShadowsocksClient.FromShareLink("ss://not!base64!@example.com:8388"));
    }

    [Fact]
    public async Task Client_ConnectAsync_NullStream_ThrowsArgumentNull()
    {
        var client = ShadowsocksClient.FromShareLink($"ss://{Aes128TestUrlSafe}@example.com:8388");
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await client.ConnectAsync((Stream)null!, "example.org", 443));
    }

    [Fact]
    public async Task Client_ConnectAsync_HostNameTooLong_FailsBeforeWriting()
    {
        var transport = new FakeProxyStream([]);
        var client = ShadowsocksClient.FromShareLink($"ss://{Aes128TestUrlSafe}@example.com:8388");

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await client.ConnectAsync(transport, new string('a', 300), 443));

        Assert.Equal(ProxyErrorCode.StringTooLong, ex.ErrorCode);
        Assert.Empty(transport.WrittenBytes);
    }

    [Theory]
    [InlineData("2bc31b80+786m+k9EXdvb28", "base64 whose bytes are binary noise holding a colon")]
    [InlineData("5fa74a60-cc6c2VjcmV0nu8", "the same, url-safe alphabet")]
    public void TryParse_RejectsBase64UserInfoThatDecodesToBinary(string userInfo, string _)
    {
        Assert.False(ShadowsocksShareLink.TryParse($"ss://{userInfo}@example.com:8388", out ShadowsocksOptions? rejected));
        Assert.Null(rejected);

        var ex = Assert.Throws<FormatException>(
            () => ShadowsocksShareLink.Parse($"ss://{userInfo}@example.com:8388"));
        Assert.Contains("not base64 of 'method:password'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("2022-blake3-aes-256-gcm")]
    [InlineData("AEAD_CHACHA20_POLY1305")]
    [InlineData("some-cipher-we-never-heard-of")]
    public void TryParse_KeepsAcceptingWellFormedNamesFromBase64UserInfo(string method)
    {
        string userInfo = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{method}:secret"))
            .TrimEnd('=');

        Assert.True(ShadowsocksShareLink.TryParse($"ss://{userInfo}@example.com:8388", out var options));
        Assert.Equal(method, options.Method);
        Assert.Equal("secret", options.Password);
    }
}
