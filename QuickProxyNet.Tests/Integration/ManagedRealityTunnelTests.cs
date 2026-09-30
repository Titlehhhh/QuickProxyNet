using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// The full managed stack: REALITY over a hand-written TLS 1.3, carrying VLESS, to a real target.
/// </summary>
/// <remarks>
/// <para>
/// The handshake tests prove Xray accepts us. These prove the connection is actually usable —
/// that the record layer survives real traffic in both directions, and that the bytes VLESS puts
/// on it arrive intact.
/// </para>
/// <para>
/// Everything is on loopback: the REALITY server, the decoy its handshake is borrowed from, and
/// the HTTP target. Nothing here depends on the internet.
/// </para>
/// </remarks>
public class ManagedRealityTunnelTests
{
    private static string Executable => Environment.GetEnvironmentVariable(LocalRealityServer.ExecutablePathVariable)!;

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    /// <summary>Opens a VLESS tunnel to <paramref name="targetPort"/> over managed REALITY.</summary>
    private static async Task<Stream> OpenTunnelAsync(
        LocalRealityServer server, int targetPort, CancellationToken cancellationToken, string? flow = null)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", server.Port, cancellationToken);

        var tlsOptions = new RealityTlsOptions
        {
            ServerName = LocalRealityServer.ServerName,
            PublicKey = Base64Url(LocalRealityServer.PublicKey),
            ShortId = LocalRealityServer.ShortId,
            Alpn = ["h2", "http/1.1"]
        };

        Stream tls = await RealityTlsClient.HandshakeAsync(tcp.GetStream(), tlsOptions, cancellationToken);

        var vless = new VlessOptions
        {
            Id = LocalRealityServer.Id,
            Host = "127.0.0.1",
            Port = server.Port,
            Security = VlessSecurity.Reality,
            Flow = flow
        };

        return await VlessHelper.EstablishVlessTunnelAsync(tls, vless, "127.0.0.1", targetPort, cancellationToken);
    }

    /// <summary>
    /// One request, whole response. On a timeout the failure carries Xray's own log, because
    /// "the operation was canceled" after 30 seconds says nothing — the server's last lines
    /// usually say everything (the 2026 finalRules blackhole took hours to find without them).
    /// </summary>
    private static async Task<string> GetAsync(
        LocalRealityServer server, Stream tunnel, string path, CancellationToken cancellationToken)
    {
        byte[] request = Encoding.ASCII.GetBytes(
            $"GET {path} HTTP/1.1\r\nHost: qpn.test\r\nConnection: close\r\n\r\n");
        await tunnel.WriteAsync(request, cancellationToken);
        await tunnel.FlushAsync(cancellationToken);

        try
        {
            using var reader = new StreamReader(tunnel, Encoding.ASCII);
            return await reader.ReadToEndAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Assert.Fail($"No response through the tunnel before the timeout. Xray said:\n{server.Log()}");
            throw;
        }
    }

    /// <summary>
    /// The same tunnel, but opened the way a user opens it: a share link into
    /// <see cref="Proxy"/>, <c>ConnectAsync</c>, a stream back. Everything the
    /// direct tests above bypass — <c>VlessClient.ConnectAsync</c>, its REALITY branch, the
    /// option mapping from the link, the flow wrapping — is on this path and nowhere else.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task PublicApi_ShareLinkThroughFactory_CarriesVlessOverReality()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        IProxyClient client = Proxy.Create(server.ShareLink());
        await using Stream tunnel = await client.ConnectAsync("127.0.0.1", echo.Port, timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, await GetAsync(server, tunnel, "/", timeout.Token));
    }

    /// <summary>The one-liner, with Vision on — the configuration real nodes almost always have.</summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task PublicApi_ProxyConnectAsyncString_CarriesVlessOverRealityWithVision()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, VisionStream.FlowName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel = await Proxy.ConnectAsync(
            server.ShareLink(), "127.0.0.1", echo.Port, TimeSpan.FromSeconds(30), timeout.Token);

        string response = await GetAsync(server, tunnel, "/" + new string('a', 40_000), timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// A wrong public key through the public path must surface as the proxy error it is —
    /// <see cref="ProxyErrorCode.AuthFailed"/>, the "check pbk/sid/sni" signal — not as some
    /// other type the client's unwinding happened to wrap it in.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task PublicApi_WrongPublicKey_IsAuthFailed()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Valid base64url for 32 bytes, and not the server's key.
        string link = server.ShareLink().Replace($"pbk={LocalRealityServer.PublicKey}", "pbk=LmsbBDEPXyy3PS0kYTdC55wlSCqteIEaw6trnKcMUeE");

        var ex = await Assert.ThrowsAsync<RealityHandshakeException>(async () =>
            await Proxy.ConnectAsync(link, "127.0.0.1", 80, timeout.Token));

        Assert.Equal(ProxyErrorCode.AuthFailed, ex.ErrorCode);
    }

    /// <summary>
    /// The end of the road: bytes go out through managed REALITY and the answer comes back.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedReality_CarriesVlessToATarget()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, await GetAsync(server, tunnel, "/", timeout.Token));
    }

    /// <summary>
    /// A payload larger than one TLS record, to prove records are split and reassembled rather
    /// than silently truncated at the 16 KiB boundary.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedReality_CarriesPayloadsAcrossRecordBoundaries()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

        // Comfortably past TlsRecordStream.MaxPlaintext, so the write path has to emit several
        // records and the server has to reassemble them.
        string response = await GetAsync(server, tunnel, "/" + new string('a', 40_000), timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// Several tunnels over separate connections, to catch state that leaks between handshakes.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedReality_SupportsSequentialTunnels()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

            Assert.Contains(LoopbackEchoServer.Body, await GetAsync(server, tunnel, "/", timeout.Token));
        }
    }

    /// <summary>
    /// The same tunnel against a server whose user requires <c>xtls-rprx-vision</c> — the
    /// configuration almost every REALITY node in the wild uses.
    /// </summary>
    /// <remarks>
    /// Without the flow in the addons, Xray drops the connection outright; with the flow but no
    /// unpadding, the response arrives wrapped in padding frames. Both failures are what this
    /// asserts against, so the assertion has to be on the exact body, not on "some bytes came
    /// back".
    /// </remarks>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedReality_WithVisionFlow_CarriesVlessToATarget()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, VisionStream.FlowName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel =
            await OpenTunnelAsync(server, echo.Port, timeout.Token, VisionStream.FlowName);

        Assert.Contains(LoopbackEchoServer.Body, await GetAsync(server, tunnel, "/", timeout.Token));
    }

    /// <summary>
    /// Vision again, with a response too large to fit the padded frames — the part a client that
    /// only unwraps the first frame gets wrong.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedReality_WithVisionFlow_CarriesPayloadsPastTheFramedPrefix()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, VisionStream.FlowName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel =
            await OpenTunnelAsync(server, echo.Port, timeout.Token, VisionStream.FlowName);

        string response = await GetAsync(server, tunnel, "/" + new string('a', 40_000), timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }
}
