using System.Net.Security;
using System.Text;
using static QuickProxyNet.Tests.Integration.DockerEndpoints;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// End-to-end protocol tests against <b>real</b> Xray and sing-box servers started from
/// <c>tests/docker/docker-compose.yml</c>. Enable with <c>QPN_DOCKER_TESTS=1</c>; otherwise
/// every case here reports as <b>skipped</b>.
/// </summary>
/// <remarks>
/// <para>
/// Byte-exact vectors prove the crypto is what an independent implementation computes. They
/// cannot prove that a server <i>accepts</i> the handshake — framing, field order, the option
/// byte, the padding rules and the id derivation all have to be right at once for that. These
/// tests are the only thing in the suite that proves it.
/// </para>
/// <para>
/// Two implementations are exercised because they disagree about what they tolerate: one
/// forgives mistakes the other rejects, so a single server would silently bless a bug.
/// </para>
/// <para>
/// Every case performs a full request/response round trip, never a bare connect. That is
/// mandatory for VMess: <c>VmessResponseStream</c> decodes the sealed response header lazily on
/// the first <c>Read</c>, so <c>ConnectAsync</c> returning successfully proves nothing about the
/// server's reply. Only reading the body validates the response header, the derived response
/// keys and the AEAD chunk framing.
/// </para>
/// </remarks>
public sealed class DockerProtocolTests : IClassFixture<DockerComposeFixture>
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan RoundTripTimeout = TimeSpan.FromSeconds(30);

    private readonly DockerComposeFixture _docker;

    public DockerProtocolTests(DockerComposeFixture docker) => _docker = docker;

    // ---------------------------------------------------------------- VLESS, security=none

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vless_None_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = VlessNoneId,
            Host = "127.0.0.1",
            Port = VlessNonePort(server),
            Security = VlessSecurity.None
        });

        await AssertEchoRoundTripAsync(client);
    }

    // ----------------------------------------------------------------- VLESS, security=tls

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vless_Tls_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = VlessTlsId,
            Host = "127.0.0.1",
            Port = VlessTlsPort(server),
            Security = VlessSecurity.Tls,
            Sni = TlsSni
        })
        {
            ServerCertificateValidationCallback = AcceptTestCertificate
        };

        await AssertEchoRoundTripAsync(client);
    }

    // ------------------------------------------------------------------------ Trojan (TLS)

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Trojan_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new TrojanClient(new TrojanOptions
        {
            Password = TrojanPassword,
            Host = "127.0.0.1",
            Port = TrojanPort(server),
            Sni = TlsSni
            // AllowInsecure stays false on purpose: the callback below still requires the
            // handshake to present *our* test certificate, so TLS is genuinely verified.
        })
        {
            ServerCertificateValidationCallback = AcceptTestCertificate
        };

        await AssertEchoRoundTripAsync(client);
    }

    // ---------------------------------------------------------------------------- VMess

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vmess_Aes128Gcm_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VmessClient(new VmessOptions
        {
            Id = VmessAesId,
            Host = "127.0.0.1",
            Port = VmessAesPort(server),
            Security = VmessSecurityKind.Aes128Gcm,
            AlterId = 0
        });

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vmess_ChaCha20Poly1305_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VmessClient(new VmessOptions
        {
            Id = VmessChachaId,
            Host = "127.0.0.1",
            Port = VmessChachaPort(server),
            Security = VmessSecurityKind.ChaCha20Poly1305,
            AlterId = 0
        });

        await AssertEchoRoundTripAsync(client);
    }

    // ----------------------------------------------------------------------------- Shadowsocks

    /// <remarks>
    /// The Shadowsocks server sends its salt only after the target has replied, so a bare
    /// connect proves nothing here either — the round trip is what validates the lazy salt read,
    /// the read-direction subkey and the chunk framing against a real peer.
    /// </remarks>
    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Shadowsocks_Aes256Gcm_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-256-gcm",
            Password = ShadowsocksPassword,
            Host = "127.0.0.1",
            Port = ShadowsocksAes256Port(server)
        });

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Shadowsocks_ChaCha20Poly1305_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "chacha20-ietf-poly1305",
            Password = ShadowsocksPassword,
            Host = "127.0.0.1",
            Port = ShadowsocksChachaPort(server)
        });

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Shadowsocks_Aes128Gcm_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-128-gcm",
            Password = ShadowsocksPassword,
            Host = "127.0.0.1",
            Port = ShadowsocksAes128Port(server)
        });

        await AssertEchoRoundTripAsync(client);
    }

    /// <summary>
    /// <c>aes-192-gcm</c> is outside the spec table: sing-box and shadowsocks-libev speak it, Xray
    /// has no such cipher, so this inbound is sing-box only. Its 24-byte salt is the detail no
    /// vector from a permissive implementation could pin — none of them supports the cipher.
    /// </summary>
    [DockerFact]
    public async Task Shadowsocks_Aes192Gcm_RoundTrip_SingBoxOnly()
    {
        _docker.EnsureUp();

        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-192-gcm",
            Password = ShadowsocksPassword,
            Host = "127.0.0.1",
            Port = SingBoxShadowsocksAes192
        });

        await AssertEchoRoundTripAsync(client);
    }

    /// <summary>
    /// The same link through the public string entry point, so the factory registration, the
    /// share-link parser and the client are proven together against a real server.
    /// </summary>
    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Shadowsocks_PublicApi_ShareLink_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        string userInfo = Convert.ToBase64String(Encoding.UTF8.GetBytes($"aes-256-gcm:{ShadowsocksPassword}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var client = Proxy.Create($"ss://{userInfo}@127.0.0.1:{ShadowsocksAes256Port(server)}#docker");

        Assert.Equal(ProxyType.Shadowsocks, client.Type);
        await AssertEchoRoundTripAsync((ProxyClient)client);
    }

    /// <summary>
    /// A wrong password must <b>not</b> round trip, and must not fail at connect: the server sends
    /// nothing it cannot decrypt, so <c>ConnectAsync</c> succeeds and the failure lands on the
    /// first <c>Read</c>. Without this, the tests above would still pass if the server accepted
    /// anything at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Xray answers an unauthenticated first chunk by draining a pseudo-random number of further
    /// bytes before closing: <c>NewBehaviorSeedLimitedDrainer(seed, 16+38, 3266, 64)</c> in
    /// <c>proxy/shadowsocks/protocol.go</c>, i.e. under 3400 bytes (54 + 3266 + 64 at the very most)
    /// counted from the first byte received. A bare HTTP request is under 200 bytes, which is why an earlier
    /// version of this test had to accept a timeout — and a timeout is what a client whose first
    /// Read simply hangs also produces. So the request is followed by 4096 filler bytes: the
    /// drainer runs out on both servers, they close, and the only passing outcome is a close on
    /// the first Read, never a timeout.
    /// </para>
    /// <para>
    /// The close is a FIN or a RST — Linux resets when a socket is closed with unread data in it,
    /// and both servers leave our surplus unread. Through the docker port proxy that usually
    /// arrives as a FIN (<see cref="ProxyProtocolException"/>, <see cref="ProxyErrorCode.ConnectionFailed"/>);
    /// a RST surfaces as the transport's <see cref="IOException"/>. Both are "the server closed on
    /// us"; a successful round trip, a clean 0, a cancellation or any other exception fails the test.
    /// </para>
    /// </remarks>
    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Shadowsocks_WrongPassword_ConnectSucceeds_ReadFails(Server server)
    {
        _docker.EnsureUp();

        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-256-gcm",
            Password = ShadowsocksPassword + "-wrong",
            Host = "127.0.0.1",
            Port = ShadowsocksAes256Port(server)
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await using Stream stream = await client.ConnectAsync(EchoHost, EchoPort, ConnectTimeout, cts.Token);

        byte[] request = Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {EchoHost}\r\nConnection: close\r\n\r\n");
        byte[] filler = new byte[4096]; // more than Xray's drainer can ever want; see remarks

        try
        {
            await stream.WriteAsync(request, cts.Token);
            await stream.WriteAsync(filler, cts.Token);
            await stream.FlushAsync(cts.Token);

            int read = await stream.ReadAsync(new byte[4096], cts.Token);
            Assert.Fail($"a wrong password must not yield data or a clean close, but Read returned {read}");
        }
        catch (ProxyProtocolException ex)
        {
            Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
        }
        catch (IOException ex) when (ex is not EndOfStreamException)
        {
            // RST: the server closed with our filler still unread. Still a close, still not a
            // timeout — and only reachable after the drainer gave up. A raw EndOfStreamException
            // is excluded on purpose: the tunnel must translate a FIN, so one escaping is a bug.
        }
    }

    // ------------------------------------------------------------ ws / httpupgrade transports

    /// <remarks>
    /// The transport layer is where a unit test is least trustworthy: a fake server answers the
    /// handshake exactly as written, so it cannot catch a wrong path, a missing header a real
    /// server insists on, or the framing/flush behaviour that decides whether the connection
    /// deadlocks. Only Xray and sing-box can.
    /// </remarks>
    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vless_WebSocket_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = VlessWsId,
            Host = "127.0.0.1",
            Port = VlessWsPort(server),
            Security = VlessSecurity.None,
            Transport = "ws",
            Path = VlessWsPath
        });

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vmess_WebSocket_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VmessClient(new VmessOptions
        {
            Id = VmessWsId,
            Host = "127.0.0.1",
            Port = VmessWsPort(server),
            Security = VmessSecurityKind.Aes128Gcm,
            AlterId = 0,
            Transport = "ws",
            Path = VmessWsPath
        });

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Trojan_WebSocket_OverTls_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        // ws inside TLS: proves the layering order (TLS first, then the upgrade, then the
        // protocol header) rather than just that each layer works alone.
        var client = new TrojanClient(new TrojanOptions
        {
            Password = TrojanPassword,
            Host = "127.0.0.1",
            Port = TrojanWsPort(server),
            Sni = TlsSni,
            Transport = "ws",
            Path = TrojanWsPath
        })
        {
            ServerCertificateValidationCallback = AcceptTestCertificate
        };

        await AssertEchoRoundTripAsync(client);
    }

    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vless_HttpUpgrade_RoundTrip(Server server)
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = VlessHttpUpgradeId,
            Host = "127.0.0.1",
            Port = VlessHttpUpgradePort(server),
            Security = VlessSecurity.None,
            Transport = "httpupgrade",
            Path = HttpUpgradePath
        });

        await AssertEchoRoundTripAsync(client);
    }

    /// <summary>
    /// A wrong path must fail, and fail as a refused upgrade. Without this the tests above
    /// would still pass if the servers upgraded on any path at all.
    /// </summary>
    [DockerTheory]
    [InlineData(Server.Xray)]
    [InlineData(Server.SingBox)]
    public async Task Vless_WebSocket_WrongPath_IsRefused(Server server)
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = VlessWsId,
            Host = "127.0.0.1",
            Port = VlessWsPort(server),
            Security = VlessSecurity.None,
            Transport = "ws",
            Path = "/definitely-not-configured"
        });

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () => await FetchEchoAsync(client));
        Assert.Equal(ProxyErrorCode.TransportUpgradeFailed, ex.ErrorCode);
    }

    // ------------------------------------------------------- non-UUID id derivation vs Xray

    /// <summary>
    /// The Xray inbound on <see cref="XrayVlessNonUuid"/> is configured with the literal id
    /// <c>"not-a-uuid"</c>. Xray's <c>common/uuid.ParseString</c> maps any id of length 1..30 to
    /// <c>UUIDv5(nil-namespace, utf8(id))</c>, and this client is given the same literal string.
    /// </summary>
    /// <remarks>
    /// A successful round trip means <c>UuidCodec</c> derived the identical 16 bytes Xray did:
    /// the VLESS id is compared byte for byte on the server, so a single wrong bit is a rejected
    /// handshake. This is the only test that pins that derivation against the implementation it
    /// was reverse-engineered from — a unit vector could only pin it against ourselves.
    /// </remarks>
    [DockerFact]
    public async Task Vless_NonUuidId_DerivesSameIdAsXray()
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = NonUuidId,
            Host = "127.0.0.1",
            Port = XrayVlessNonUuid,
            Security = VlessSecurity.None
        });

        await AssertEchoRoundTripAsync(client);
    }

    /// <summary>
    /// A wrong id on the same inbound must <b>not</b> round trip. Without this, the test above
    /// would still pass if the server accepted anything at all.
    /// </summary>
    [DockerFact]
    public async Task Vless_WrongNonUuidId_IsRejectedByXray()
    {
        _docker.EnsureUp();

        var client = new VlessClient(new VlessOptions
        {
            Id = "not-a-uuid-either",
            Host = "127.0.0.1",
            Port = XrayVlessNonUuid,
            Security = VlessSecurity.None
        });

        // Xray drops the connection on an unknown user rather than replying, so the failure
        // surfaces on the first read. Asserting the specific exception (and not merely "some
        // exception") keeps a 30 s timeout from being mistaken for a rejection.
        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () => await FetchEchoAsync(client));
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    // ------------------------------------------------------------------------------ helpers

    private static async Task AssertEchoRoundTripAsync(ProxyClient client)
    {
        string response = await FetchEchoAsync(client);

        Assert.StartsWith("HTTP/1.1 200", response);
        Assert.Contains(EchoBody, response);
    }

    /// <summary>
    /// Opens a tunnel to the compose network's echo target, writes an HTTP GET through it and
    /// reads until the body arrives.
    /// </summary>
    /// <remarks>
    /// Reading stops as soon as the expected body is present instead of draining to EOF. That
    /// keeps the assertion about the handshake rather than about how each server chooses to
    /// terminate the stream — for VMess a clean close is an authenticated empty chunk, and
    /// whether a server emits one after a plain socket close is its business, not this test's.
    /// </remarks>
    private static async Task<string> FetchEchoAsync(ProxyClient client)
    {
        using var cts = new CancellationTokenSource(RoundTripTimeout);

        // The target host is a docker-network DNS name, so this also exercises the domain
        // address type of each protocol rather than the IPv4 one.
        await using Stream stream = await client.ConnectAsync(EchoHost, EchoPort, ConnectTimeout, cts.Token);

        byte[] request = Encoding.ASCII.GetBytes(
            $"GET / HTTP/1.1\r\nHost: {EchoHost}\r\nConnection: close\r\n\r\n");

        await stream.WriteAsync(request, cts.Token);
        await stream.FlushAsync(cts.Token);

        var received = new StringBuilder();
        byte[] buffer = new byte[4096];

        while (true)
        {
            int read = await stream.ReadAsync(buffer, cts.Token);
            if (read == 0)
                break;

            received.Append(Encoding.ASCII.GetString(buffer, 0, read));

            if (received.ToString().Contains(EchoBody, StringComparison.Ordinal))
                break;
        }

        return received.ToString();
    }

    /// <summary>
    /// Accepts exactly the committed self-signed test certificate. Deliberately not
    /// "accept anything": the TLS inbounds are supposed to prove a real TLS session with our
    /// server happened.
    /// </summary>
    private static bool AcceptTestCertificate(
        object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate,
        System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors errors) =>
        certificate is not null &&
        certificate.Subject.Contains(TestCertSubjectCn, StringComparison.Ordinal);
}
