using System.Net.Sockets;
using QuickProxyNet.Reality;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// Drives the managed TLS 1.3 client through a complete REALITY handshake with real Xray-core.
/// </summary>
/// <remarks>
/// This is the test the whole managed implementation exists to pass. Everything below the
/// handshake — the curve, the key schedule, the record layer — is verified against published
/// vectors elsewhere; only an actual server can show that they compose into something Xray will
/// talk to.
/// </remarks>
public class ManagedTlsHandshakeTests
{
    private static string Executable => Environment.GetEnvironmentVariable(LocalRealityServer.ExecutablePathVariable)!;

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    private static RealityTlsOptions Options(string? publicKey = null, string? shortId = null) => new()
    {
        ServerName = LocalRealityServer.ServerName,
        PublicKey = Base64Url(publicKey ?? LocalRealityServer.PublicKey),
        ShortId = shortId ?? LocalRealityServer.ShortId,
        Alpn = ["h2", "http/1.1"]
    };

    private static async Task<TcpClient> ConnectAsync(LocalRealityServer server)
    {
        var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", server.Port);
        return client;
    }

    /// <summary>
    /// The milestone: a TLS 1.3 handshake written from scratch, authenticated by REALITY,
    /// completed against the reference server.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task ManagedHandshake_CompletesAgainstXray()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);
        using TcpClient tcp = await ConnectAsync(server);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        await using Stream tls = await RealityTlsClient.HandshakeAsync(
            tcp.GetStream(), Options(), timeout.Token);

        // Reaching here means: the server's Finished verified against our key schedule, and its
        // certificate was bound to our REALITY shared secret by HMAC. Both are unforgeable
        // without the server's private key.
        Assert.True(tls.CanRead);
        Assert.True(tls.CanWrite);
    }

    /// <summary>
    /// With the wrong public key the server relays us to the decoy, and the client must refuse
    /// rather than tunnel.
    /// </summary>
    /// <remarks>
    /// This is the case that decides whether the implementation is safe to use at all. A client
    /// that cannot tell the REALITY server from the borrowed site would send the VLESS id to
    /// whatever answered.
    /// </remarks>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task WrongPublicKey_IsRefusedRatherThanTunnelled()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);
        using TcpClient tcp = await ConnectAsync(server);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        // Valid base64url for 32 bytes, and not the server's key.
        const string wrongKey = "LmsbBDEPXyy3PS0kYTdC55wlSCqteIEaw6trnKcMUeE";

        var ex = await Assert.ThrowsAsync<RealityHandshakeException>(
            async () => await RealityTlsClient.HandshakeAsync(tcp.GetStream(), Options(wrongKey), timeout.Token));

        Assert.Contains("REALITY", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A short id the server does not know must fail the same way: relayed to the decoy, refused.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task UnknownShortId_IsRefused()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);
        using TcpClient tcp = await ConnectAsync(server);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        await Assert.ThrowsAsync<RealityHandshakeException>(
            async () => await RealityTlsClient.HandshakeAsync(
                tcp.GetStream(), Options(shortId: "cdef"), timeout.Token));
    }

    /// <summary>
    /// Two handshakes in a row must both succeed: the ephemeral key, the client random and the
    /// timestamp all change per connection, and a stale value anywhere would show up here.
    /// </summary>
    [EnvFact(LocalRealityServer.ExecutablePathVariable)]
    public async Task RepeatedHandshakes_AllSucceed()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            using TcpClient tcp = await ConnectAsync(server);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));

            await using Stream tls = await RealityTlsClient.HandshakeAsync(
                tcp.GetStream(), Options(), timeout.Token);

            Assert.True(tls.CanRead);
        }
    }
}
