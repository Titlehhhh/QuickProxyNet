using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// Isolates where a request larger than one TLS record stops arriving.
/// </summary>
/// <remarks>
/// Written because <c>Reality_CarriesLargePayload</c> passes at 16 000 bytes and hangs at 16 500 —
/// a boundary suspiciously equal to the 16 KiB TLS record limit. The candidates are the test's own
/// echo server, QuickProxyNet's SOCKS5 stream, and the tunnel itself, and only one of them can be
/// blamed without evidence.
/// </remarks>
public class LargeRequestDiagnosticTests
{
    private static byte[] Request(int padding) => Encoding.ASCII.GetBytes(
        $"GET /{new string('a', padding)} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    /// <summary>
    /// The echo server on its own, over a plain socket. If this hangs, nothing else is at fault.
    /// </summary>
    [Theory]
    [InlineData(1_000)]
    [InlineData(20_000)]
    [InlineData(100_000)]
    public async Task Echo_HandlesLargeRequestsDirectly(int padding)
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", echo.Port, timeout.Token);

        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(Request(padding), timeout.Token);
        await stream.FlushAsync(timeout.Token);

        using var reader = new StreamReader(stream, Encoding.ASCII);
        Assert.Contains(LoopbackEchoServer.Body, await reader.ReadToEndAsync(timeout.Token));
    }

    /// <summary>
    /// The same request through QuickProxyNet's SOCKS5 client and a bare Xray SOCKS proxy — no
    /// VLESS, no TLS, no REALITY.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the test that decided whether the 16 KiB boundary belongs to the tunnel or to
    /// <see cref="Socks5Client"/>. It belongs to neither: the sibling test below carries 100 000
    /// bytes through the same client against a plain relay, while this path — no VLESS, no TLS,
    /// no REALITY — stops relaying somewhere between 16 000 and 16 500 bytes.
    /// </para>
    /// <para>
    /// Verified against Xray-core 26.3.27 on Windows, with the inbound's sniffing explicitly
    /// disabled and with the request written both as one call and in 4 KiB slices; neither
    /// changes the outcome, and neither process logs an error. The sizes here stay under that
    /// ceiling so the test measures the proxy working rather than the ceiling.
    /// </para>
    /// </remarks>
    [EnvTheory(LocalRealityServer.ExecutablePathVariable)]
    [InlineData(1_000)]
    [InlineData(16_000)]
    public async Task Socks5_HandlesLargeRequests(int padding)
    {
        string executable = Environment.GetEnvironmentVariable(LocalRealityServer.ExecutablePathVariable)!;

        using LoopbackEchoServer echo = LoopbackEchoServer.Start();

        int socksPort = FreePort();
        string config =
            $$"""
              {
                "log": { "loglevel": "warning" },
                "inbounds": [ {
                  "listen": "127.0.0.1", "port": {{socksPort}}, "protocol": "socks",
                  "settings": { "auth": "noauth", "udp": false },
                  "sniffing": { "enabled": false } } ],
                "outbounds": [ { "protocol": "freedom" } ]
              }
              """;

        using Process xray = StartXray(executable, config);
        try
        {
            await WaitForPortAsync(socksPort);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var socks = new Socks5Client("127.0.0.1", socksPort);

            await using Stream tunnel = await socks.ConnectAsync("127.0.0.1", echo.Port, timeout.Token);
            await tunnel.WriteAsync(Request(padding), timeout.Token);
            await tunnel.FlushAsync(timeout.Token);

            using var reader = new StreamReader(tunnel, Encoding.ASCII);
            Assert.Contains(LoopbackEchoServer.Body, await reader.ReadToEndAsync(timeout.Token));
        }
        finally
        {
            if (!xray.HasExited)
                xray.Kill(entireProcessTree: true);
        }
    }

    /// <summary>
    /// The same request through <see cref="Socks5Client"/> and a SOCKS5 server implemented here,
    /// which does nothing but relay bytes.
    /// </summary>
    /// <remarks>
    /// The last isolation step. If this passes at 20 000 bytes, QuickProxyNet's SOCKS5 client is
    /// clean and the boundary belongs to whatever proxy sits in the middle.
    /// </remarks>
    [Theory]
    [InlineData(1_000)]
    [InlineData(20_000)]
    [InlineData(100_000)]
    public async Task Socks5_AgainstAPlainRelay_HandlesLargeRequests(int padding)
    {
        using LoopbackEchoServer echo = LoopbackEchoServer.Start();
        using var relay = new PlainSocks5Relay();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var socks = new Socks5Client("127.0.0.1", relay.Port);

        await using Stream tunnel = await socks.ConnectAsync("127.0.0.1", echo.Port, timeout.Token);
        await tunnel.WriteAsync(Request(padding), timeout.Token);
        await tunnel.FlushAsync(timeout.Token);

        using var reader = new StreamReader(tunnel, Encoding.ASCII);
        Assert.Contains(LoopbackEchoServer.Body, await reader.ReadToEndAsync(timeout.Token));
    }

    /// <summary>A SOCKS5 server with no features beyond CONNECT and copying.</summary>
    private sealed class PlainSocks5Relay : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();

        public PlainSocks5Relay()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = AcceptAsync();
        }

        public int Port { get; }

        private async Task AcceptAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                _ = ServeAsync(client);
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    NetworkStream stream = client.GetStream();
                    var header = new byte[2];

                    await stream.ReadExactlyAsync(header, _cts.Token);
                    await stream.ReadExactlyAsync(new byte[header[1]], _cts.Token);
                    await stream.WriteAsync(new byte[] { 5, 0 }, _cts.Token);

                    var request = new byte[4];
                    await stream.ReadExactlyAsync(request, _cts.Token);

                    string host;
                    switch (request[3])
                    {
                        case 1:
                            var v4 = new byte[4];
                            await stream.ReadExactlyAsync(v4, _cts.Token);
                            host = new IPAddress(v4).ToString();
                            break;

                        case 3:
                            var length = new byte[1];
                            await stream.ReadExactlyAsync(length, _cts.Token);
                            var name = new byte[length[0]];
                            await stream.ReadExactlyAsync(name, _cts.Token);
                            host = Encoding.ASCII.GetString(name);
                            break;

                        default:
                            return;
                    }

                    var portBytes = new byte[2];
                    await stream.ReadExactlyAsync(portBytes, _cts.Token);
                    int port = (portBytes[0] << 8) | portBytes[1];

                    using var target = new TcpClient();
                    await target.ConnectAsync(host, port, _cts.Token);

                    await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, _cts.Token);

                    NetworkStream targetStream = target.GetStream();
                    Task up = stream.CopyToAsync(targetStream, _cts.Token);
                    Task down = targetStream.CopyToAsync(stream, _cts.Token);
                    await Task.WhenAny(up, down);
                }
                catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or EndOfStreamException)
                {
                    // The client went away; nothing to report from a test relay.
                }
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            _cts.Dispose();
        }
    }

    private static Process StartXray(string executable, string config)
    {
        var psi = new ProcessStartInfo(executable)
        {
            ArgumentList = { "run", "-c", "stdin:" },
            WorkingDirectory = Path.GetDirectoryName(executable) ?? Environment.CurrentDirectory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process process = Process.Start(psi)!;
        process.StandardInput.Write(config);
        process.StandardInput.Close();

        return process;
    }

    private static async Task WaitForPortAsync(int port)
    {
        long deadline = Environment.TickCount64 + 15_000;
        while (Environment.TickCount64 < deadline)
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await probe.ConnectAsync("127.0.0.1", port);
                return;
            }
            catch (SocketException)
            {
                await Task.Delay(50);
            }
        }

        throw new TimeoutException($"Nothing started listening on {port}.");
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }
}
