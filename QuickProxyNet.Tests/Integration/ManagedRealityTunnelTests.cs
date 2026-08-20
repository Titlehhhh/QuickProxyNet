using System.Net.Sockets;
using System.Text;
using QuickProxyNet.Reality;
using QuickProxyNet.Reality.Managed;

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
    private static string Executable => Environment.GetEnvironmentVariable(RealityProxyOptions.ExecutablePathVariable)!;

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    /// <summary>Opens a VLESS tunnel to <paramref name="targetPort"/> over managed REALITY.</summary>
    private static async Task<Stream> OpenTunnelAsync(
        LocalRealityServer server, int targetPort, CancellationToken cancellationToken)
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
            Security = VlessSecurity.Reality
        };

        return await VlessHelper.EstablishVlessTunnelAsync(tls, vless, "127.0.0.1", targetPort, cancellationToken);
    }

    private static async Task<string> GetAsync(Stream tunnel, string path, CancellationToken cancellationToken)
    {
        byte[] request = Encoding.ASCII.GetBytes(
            $"GET {path} HTTP/1.1\r\nHost: qpn.test\r\nConnection: close\r\n\r\n");
        await tunnel.WriteAsync(request, cancellationToken);
        await tunnel.FlushAsync(cancellationToken);

        using var reader = new StreamReader(tunnel, Encoding.ASCII);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    /// <summary>
    /// The end of the road: bytes go out through managed REALITY and the answer comes back.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task ManagedReality_CarriesVlessToATarget()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, await GetAsync(tunnel, "/", timeout.Token));
    }

    /// <summary>
    /// A payload larger than one TLS record, to prove records are split and reassembled rather
    /// than silently truncated at the 16 KiB boundary.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task ManagedReality_CarriesPayloadsAcrossRecordBoundaries()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

        // Comfortably past TlsRecordStream.MaxPlaintext, so the write path has to emit several
        // records and the server has to reassemble them.
        string response = await GetAsync(tunnel, "/" + new string('a', 40_000), timeout.Token);

        Assert.Contains(LoopbackEchoServer.Body, response);
    }

    /// <summary>
    /// Several tunnels over separate connections, to catch state that leaks between handshakes.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task ManagedReality_SupportsSequentialTunnels()
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using Stream tunnel = await OpenTunnelAsync(server, echo.Port, timeout.Token);

            Assert.Contains(LoopbackEchoServer.Body, await GetAsync(tunnel, "/", timeout.Token));
        }
    }
}
