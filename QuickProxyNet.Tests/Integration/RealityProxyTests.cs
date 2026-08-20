using System.Text;
using QuickProxyNet.Reality;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// End-to-end tests for <see cref="RealityProxy"/> against a real Xray-core REALITY server.
/// </summary>
/// <remarks>
/// <para>
/// Everything here runs on loopback: the REALITY server, the decoy TLS endpoint its handshake is
/// relayed to, the tunnel client, and the HTTP target. Nothing leaves the machine, so a failure
/// means the code is wrong rather than that the network was.
/// </para>
/// <para>
/// Gated on <c>QPN_XRAY_PATH</c> because the package deliberately does not ship a binary. Without
/// it these report as <b>skipped</b>, never as passed.
/// </para>
/// </remarks>
public class RealityProxyTests
{
    private static string Executable => Environment.GetEnvironmentVariable(RealityProxyOptions.ExecutablePathVariable)!;

    private static RealityProxyOptions Options(Action<string>? logSink = null) => new()
    {
        ExecutablePath = Executable,
        StartupTimeout = TimeSpan.FromSeconds(20),
        LogLevel = logSink is null ? "warning" : "info",
        LogSink = logSink
    };

    /// <summary>
    /// How long any single tunnel exchange may take before the test gives up.
    /// </summary>
    /// <remarks>
    /// Not optional. A tunnel that fails to authenticate does not necessarily close — Xray may
    /// hold the connection open while it relays the handshake elsewhere — so an unbounded read
    /// turns a failing test into a hung test run, which is strictly worse than a red one.
    /// </remarks>
    private static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Issues a GET through the tunnel and returns the whole response.</summary>
    private static async Task<string> GetThroughAsync(RealityProxy proxy, int targetPort)
    {
        using var timeout = new CancellationTokenSource(ExchangeTimeout);

        await using Stream tunnel = await proxy.ConnectAsync("127.0.0.1", targetPort, timeout.Token);

        byte[] request = Encoding.ASCII.GetBytes(
            $"GET / HTTP/1.1\r\nHost: 127.0.0.1:{targetPort}\r\nConnection: close\r\n\r\n");
        await tunnel.WriteAsync(request, timeout.Token);
        await tunnel.FlushAsync(timeout.Token);

        using var reader = new StreamReader(tunnel, Encoding.ASCII);
        return await reader.ReadToEndAsync(timeout.Token);
    }

    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Reality_RoundTrip()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        await using RealityProxy proxy = await RealityProxy.StartAsync(server.ShareLink(), Options());

        string response = await GetThroughAsync(proxy, echo.Port);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// XTLS Vision over REALITY — the combination the in-process client cannot do at all.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Reality_Vision_RoundTrip()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server =
            await LocalRealityServer.StartAsync(Executable, flow: "xtls-rprx-vision");
        await using RealityProxy proxy = await RealityProxy.StartAsync(server.ShareLink(), Options());

        string response = await GetThroughAsync(proxy, echo.Port);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// A payload several times larger than a single write, carried through the tunnel.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Capped below 16 KiB on purpose. Xray's own SOCKS inbound stops relaying a request larger
    /// than roughly one TLS record: 16 000 bytes round-trips, 16 500 hangs. That boundary is not
    /// ours — <see cref="LargeRequestDiagnosticTests"/> isolates it, showing QuickProxyNet's
    /// SOCKS5 client carrying 100 000 bytes through a plain relay and the same request stalling
    /// against Xray with no VLESS, TLS or REALITY anywhere in the path.
    /// </para>
    /// <para>
    /// Record-boundary coverage therefore lives with the managed implementation, which has no
    /// such intermediary: see <c>ManagedRealityTunnelTests</c>, which carries 40 000 bytes.
    /// </para>
    /// </remarks>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Reality_CarriesLargePayload()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        await using RealityProxy proxy = await RealityProxy.StartAsync(server.ShareLink(), Options());

        using var timeout = new CancellationTokenSource(ExchangeTimeout);
        await using Stream tunnel = await proxy.ConnectAsync("127.0.0.1", echo.Port, timeout.Token);

        // The echo server replies only after the whole request head has arrived, so a long
        // request proves the outbound direction carried all of it.
        byte[] request = Encoding.ASCII.GetBytes(
            $"GET /{new string('a', 8_000)} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        await tunnel.WriteAsync(request, timeout.Token);
        await tunnel.FlushAsync(timeout.Token);

        using var reader = new StreamReader(tunnel, Encoding.ASCII);
        Assert.Contains(LoopbackEchoServer.Body, await reader.ReadToEndAsync(timeout.Token));
    }

    /// <summary>
    /// The test that proves REALITY authentication is actually happening.
    /// </summary>
    /// <remarks>
    /// A well-formed but wrong public key must fail. If it succeeded, the tunnel would be
    /// falling through to an ordinary TLS session against the decoy — which is exactly the
    /// silent downgrade the rest of this repo is built to prevent, and it would make every
    /// other test in this class prove nothing about REALITY.
    /// </remarks>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Reality_WrongPublicKey_DoesNotTunnel()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);

        // Valid base64url for 32 bytes, and not the server's key: Xray accepts the configuration
        // and fails the handshake, which is the case under test.
        string wrongKey = "LmsbBDEPXyy3PS0kYTdC55wlSCqteIEaw6trnKcMUeE";
        string link = server.ShareLink().Replace(LocalRealityServer.PublicKey, wrongKey);

        await using RealityProxy proxy = await RealityProxy.StartAsync(link, Options());

        // The local SOCKS inbound accepts, then Xray fails to reach the server, so the failure
        // surfaces either as a SOCKS error or as the tunnel closing without a response.
        string response;
        try
        {
            response = await GetThroughAsync(proxy, echo.Port);
        }
        catch (Exception ex) when (ex is IOException or ProxyProtocolException or OperationCanceledException)
        {
            // Refused outright, or the tunnel never carried anything before the timeout. Both are
            // the outcome this test wants; only a successful round trip would be wrong.
            return;
        }

        Assert.DoesNotContain(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// The local inbound must never be reachable from off the machine: it has no authentication,
    /// so a routable bind would be an open proxy.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task LocalInbound_IsLoopbackOnly()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        await using RealityProxy proxy = await RealityProxy.StartAsync(server.ShareLink(), Options());

        Assert.Equal("127.0.0.1", proxy.ListenAddress);
        Assert.True(proxy.IsRunning);
    }

    /// <summary>
    /// Disposal must stop the process this instance started.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Dispose_StopsTheProcess()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        RealityProxy proxy = await RealityProxy.StartAsync(server.ShareLink(), Options());

        Assert.True(proxy.IsRunning);
        await proxy.DisposeAsync();
        Assert.False(proxy.IsRunning);

        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await proxy.ConnectAsync("127.0.0.1", 80));
    }
}
