using System.Net.Sockets;
using QuickProxyNet.Reality;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// Proves the managed REALITY authentication against a real Xray-core server.
/// </summary>
/// <remarks>
/// <para>
/// The unit tests open our sealed <c>session_id</c> with the server algorithm transcribed by
/// hand. That catches layout mistakes, but a transcription can be wrong in the same way twice.
/// This test hands the bytes to the actual implementation and reads its verdict.
/// </para>
/// <para>
/// It deliberately stops after the ClientHello. Xray's REALITY server decrypts and validates the
/// session id the moment it has read the hello, long before any key schedule exists, and with
/// <c>show</c> on it says so. So the entire authentication half of REALITY can be proven while
/// the TLS 1.3 handshake is still unwritten — which is the only reason it is worth writing the
/// handshake at all.
/// </para>
/// </remarks>
public class ManagedRealityHandshakeTests
{
    private static string Executable => Environment.GetEnvironmentVariable(RealityProxyOptions.ExecutablePathVariable)!;

    /// <summary>Xray's own version triple; the server may gate on a minimum.</summary>
    private static ReadOnlySpan<byte> ClientVersion => [26, 3, 27];

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    /// <summary>Builds a sealed hello for <paramref name="server"/> and sends it.</summary>
    private static async Task SendHelloAsync(
        LocalRealityServer server, string? shortId = null, string? serverName = null)
    {
        TlsClientHello.Result hello = TlsClientHello.Build(
            serverName ?? LocalRealityServer.ServerName, ["h2", "http/1.1"]);

        byte[] authKey = new byte[RealityAuth.AuthKeySize];
        RealityAuth.DeriveAuthKey(
            authKey,
            hello.PrivateKey,
            Base64Url(LocalRealityServer.PublicKey),
            hello.Handshake.AsSpan(6, 32));

        byte[] parsedShortId = new byte[RealityAuth.ShortIdSize];
        RealityAuth.ParseShortId(parsedShortId, shortId ?? LocalRealityServer.ShortId);

        RealityAuth.SealSessionId(
            hello.Handshake,
            authKey,
            parsedShortId,
            (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ClientVersion);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", server.Port);
        await client.GetStream().WriteAsync(TlsClientHello.ToRecord(hello.Handshake));
        await client.GetStream().FlushAsync();

        // The server answers with the relayed ServerHello. We do not parse it yet; reading keeps
        // the connection alive long enough for the server to finish logging its verdict.
        byte[] scratch = new byte[4096];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            int read = await client.GetStream().ReadAsync(scratch, timeout.Token);
            Assert.True(read >= 0);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
        {
            // Whether the relay answers is not what this test measures.
        }
    }

    /// <summary>Waits for a line to appear in the server's output.</summary>
    private static async Task<bool> WaitForLogAsync(LocalRealityServer server, string marker)
    {
        long deadline = Environment.TickCount64 + 10_000;
        while (Environment.TickCount64 < deadline)
        {
            if (server.Log().Contains(marker, StringComparison.Ordinal))
                return true;

            await Task.Delay(100);
        }

        return false;
    }

    /// <summary>
    /// The milestone test: a ClientHello built entirely in managed code authenticates to Xray.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task HandBuiltClientHello_AuthenticatesToXray()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);

        await SendHelloAsync(server);

        // Xray prints this once it has decrypted the session id and accepted the short id, the
        // client version and the timestamp. 'true' means it treated us as a REALITY client rather
        // than relaying us to the decoy as an unrecognised visitor.
        Assert.True(
            await WaitForLogAsync(server, "hs.c.conn == conn: true"),
            $"Xray did not accept the hand-built ClientHello.\n{server.Log()}");
    }

    /// <summary>
    /// The same hello with a short id the server does not know must be refused.
    /// </summary>
    /// <remarks>
    /// Without this, the test above could pass for the wrong reason: if the server logged
    /// acceptance regardless of what we sent, it would prove nothing about our sealing.
    /// </remarks>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task UnknownShortId_IsNotAccepted()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);

        await SendHelloAsync(server, shortId: "cdef");

        Assert.True(
            await WaitForLogAsync(server, "hs.c.conn == conn: false"),
            $"Xray never reported a verdict for the unknown short id.\n{server.Log()}");
        Assert.DoesNotContain("hs.c.conn == conn: true", server.Log());
    }

    /// <summary>
    /// A hello for an SNI the server does not serve must not even reach the auth path.
    /// </summary>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task UnknownServerName_IsNotAccepted()
    {
        await using LocalRealityServer server = await LocalRealityServer.StartAsync(Executable, show: true);

        await SendHelloAsync(server, serverName: "not-configured.example");

        Assert.False(
            await WaitForLogAsync(server, "hs.c.conn == conn: true"),
            $"Xray accepted a ClientHello for an SNI it does not serve.\n{server.Log()}");
    }
}
