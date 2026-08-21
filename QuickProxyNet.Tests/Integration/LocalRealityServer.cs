using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// A real Xray-core REALITY server, running on loopback, for the duration of one test class.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a decoy inbound.</b> A REALITY server does not answer the TLS handshake itself: it
/// relays the ClientHello to <c>dest</c>, a genuine TLS site, and serves that site's certificate
/// back — the stolen identity is the whole mechanism. So a REALITY server cannot be tested
/// without a reachable <c>dest</c>. Pointing it at a real site would make the test depend on the
/// internet and on that site's TLS configuration; instead this fixture gives the same Xray
/// process a second, ordinary TLS inbound and aims <c>dest</c> at it. The handshake is relayed
/// over loopback, and the test proves the same thing with nothing outside the machine.
/// </para>
/// <para>
/// The certificate is the repo's existing self-signed pair under <c>tests/docker/certs</c>. A
/// REALITY client never validates it — authentication is the X25519 exchange hidden in the
/// ClientHello's <c>session_id</c>, not the certificate chain — so a self-signed decoy is not a
/// weakening of the test.
/// </para>
/// <para>
/// The keypair below is synthetic test data, committed on purpose, exactly like the repdigit
/// UUIDs in <see cref="DockerEndpoints"/>.
/// </para>
/// </remarks>
public sealed class LocalRealityServer : IAsyncDisposable
{
    /// <summary>
    /// Environment variable naming the Xray binary these tests run as a <b>server</b>.
    /// </summary>
    /// <remarks>
    /// Xray is no longer part of the library in any form — the client speaks REALITY itself.
    /// It survives here as the reference implementation to test against, which is the only
    /// role in which an outside binary is worth its weight: proof that our handshake is
    /// accepted by the thing everyone else runs. Tests that need it skip when it is unset.
    /// </remarks>
    public const string ExecutablePathVariable = "QPN_XRAY_PATH";

    /// <summary>Generated with <c>xray x25519</c> for this suite; never guarded anything real.</summary>
    public const string PrivateKey = "iGNiP2EaAhjXIfaoiF34sn1_mKKSeO01YdhN46G7xn0";

    /// <summary>The public half of <see cref="PrivateKey"/>, as a share link would carry it.</summary>
    public const string PublicKey = "BhsV4NiigG9rrk98hJnJHPJ7TQ6Iy1WqUykGF0z9I2g";

    /// <summary>Short id configured on the inbound.</summary>
    public const string ShortId = "ab12";

    /// <summary>VLESS id configured on the inbound.</summary>
    public const string Id = "6643f196-ae07-420a-b173-d909d20807c1";

    /// <summary>
    /// SNI the client must present. It is a subject-alternative name on the committed test
    /// certificate, so the decoy inbound serves it without complaint.
    /// </summary>
    public const string ServerName = "qpn.test";

    private readonly Process _process;
    private readonly List<string> _log;
    private readonly string? _flow;
    private int _disposed;

    private LocalRealityServer(Process process, List<string> log, int port, string? flow)
    {
        _process = process;
        _log = log;
        Port = port;
        _flow = flow;
    }

    /// <summary>Port of the REALITY inbound.</summary>
    public int Port { get; }

    /// <summary>A <c>vless://</c> link pointing at this server.</summary>
    /// <param name="extraQuery">Extra query parameters, each starting with <c>&amp;</c>.</param>
    /// <remarks>
    /// The flow the server was started with is included automatically. Xray rejects a client
    /// whose flow disagrees with its user entry, in either direction, so the two must be set
    /// from one place or the test would be measuring the mismatch instead of the tunnel.
    /// </remarks>
    public string ShareLink(string extraQuery = "") =>
        $"vless://{Id}@127.0.0.1:{Port}?security=reality&pbk={PublicKey}&sid={ShortId}" +
        $"&sni={ServerName}&fp=chrome" +
        (_flow is null ? "" : $"&flow={_flow}") +
        $"{extraQuery}#qpn-local";

    /// <summary>The last lines Xray printed, for failure messages.</summary>
    public string Log()
    {
        lock (_log)
            return _log.Count == 0 ? "(no output)" : string.Join("\n", _log);
    }

    /// <summary>Starts the server, waiting until the REALITY inbound accepts connections.</summary>
    /// <param name="executable">Path to the Xray-core binary.</param>
    /// <param name="flow">XTLS flow to require, e.g. <c>xtls-rprx-vision</c>, or null for none.</param>
    /// <param name="show">
    /// Turns on Xray's REALITY diagnostics. The server then prints, per connection, the auth key
    /// prefix and the short id it decrypted out of the session id — which is how a test can prove
    /// a hand-built ClientHello authenticated, without completing a handshake.
    /// </param>
    /// <param name="cancellationToken">Cancels startup.</param>
    public static async Task<LocalRealityServer> StartAsync(
        string executable, string? flow = null, bool show = false,
        CancellationToken cancellationToken = default)
    {
        int realityPort = FreePort();
        int decoyPort = FreePort();
        (string certificate, string key) = LocateCertificate();

        byte[] config = BuildConfig(realityPort, decoyPort, certificate, key, flow, show);

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

        Process process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start '{executable}'.");

        var log = new List<string>();
        var server = new LocalRealityServer(process, log, realityPort, flow);

        try
        {
            void Collect(object? _, DataReceivedEventArgs e)
            {
                if (e.Data is null)
                    return;

                lock (log)
                {
                    log.Add(e.Data);
                    if (log.Count > 40)
                        log.RemoveAt(0);
                }
            }

            process.OutputDataReceived += Collect;
            process.ErrorDataReceived += Collect;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.StandardInput.BaseStream.WriteAsync(config, cancellationToken);
            process.StandardInput.Close();

            await WaitForPortAsync(process, realityPort, server, cancellationToken);
            await WaitForPortAsync(process, decoyPort, server, cancellationToken);
            return server;
        }
        catch
        {
            await server.DisposeAsync();
            throw;
        }
    }

    private static byte[] BuildConfig(
        int realityPort, int decoyPort, string certificate, string key, string? flow, bool show)
    {
        var buffer = new MemoryStream(1024);
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();

            w.WriteStartObject("log");
            w.WriteString("loglevel", "warning");
            w.WriteEndObject();

            w.WriteStartArray("inbounds");

            w.WriteStartObject();
            w.WriteString("listen", "127.0.0.1");
            w.WriteNumber("port", realityPort);
            w.WriteString("protocol", "vless");
            w.WriteString("tag", "reality");
            w.WriteStartObject("settings");
            w.WriteStartArray("clients");
            w.WriteStartObject();
            w.WriteString("id", Id);
            if (flow is not null)
                w.WriteString("flow", flow);
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteString("decryption", "none");
            w.WriteEndObject();
            w.WriteStartObject("streamSettings");
            w.WriteString("network", "tcp");
            w.WriteString("security", "reality");
            w.WriteStartObject("realitySettings");
            w.WriteString("dest", $"127.0.0.1:{decoyPort}");
            w.WriteStartArray("serverNames");
            w.WriteStringValue(ServerName);
            w.WriteEndArray();
            w.WriteString("privateKey", PrivateKey);
            if (show)
                w.WriteBoolean("show", true);
            w.WriteStartArray("shortIds");
            w.WriteStringValue(ShortId);
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndObject();
            w.WriteEndObject();

            // The decoy: an ordinary TLS endpoint whose only job is to own a certificate for
            // the REALITY inbound to relay. Nothing connects to it directly.
            w.WriteStartObject();
            w.WriteString("listen", "127.0.0.1");
            w.WriteNumber("port", decoyPort);
            w.WriteString("protocol", "vless");
            w.WriteString("tag", "decoy");
            w.WriteStartObject("settings");
            w.WriteStartArray("clients");
            w.WriteStartObject();
            w.WriteString("id", Id);
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteString("decryption", "none");
            w.WriteEndObject();
            w.WriteStartObject("streamSettings");
            w.WriteString("network", "tcp");
            w.WriteString("security", "tls");
            w.WriteStartObject("tlsSettings");
            w.WriteString("serverName", ServerName);
            w.WriteStartArray("certificates");
            w.WriteStartObject();
            w.WriteString("certificateFile", certificate);
            w.WriteString("keyFile", key);
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndObject();
            w.WriteEndObject();

            w.WriteEndArray();

            w.WriteStartArray("outbounds");
            w.WriteStartObject();
            w.WriteString("protocol", "freedom");
            w.WriteEndObject();
            w.WriteEndArray();

            w.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static async Task WaitForPortAsync(
        Process process, int port, LocalRealityServer server, CancellationToken cancellationToken)
    {
        long deadline = Environment.TickCount64 + 15_000;

        while (true)
        {
            if (process.HasExited)
                throw new InvalidOperationException(
                    $"The REALITY server exited with code {process.ExitCode}:\n{server.Log()}");

            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    await socket.ConnectAsync("127.0.0.1", port, cancellationToken);
                    return;
                }
                catch (SocketException)
                {
                    // Not listening yet.
                }
            }

            if (Environment.TickCount64 > deadline)
                throw new TimeoutException(
                    $"The REALITY server never listened on {port}:\n{server.Log()}");

            await Task.Delay(50, cancellationToken);
        }
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

    private static (string Certificate, string Key) LocateCertificate()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string certificate = Path.Combine(dir.FullName, "tests", "docker", "certs", "server.crt");
            if (File.Exists(Path.Combine(dir.FullName, "QuickProxyNet.slnx")) && File.Exists(certificate))
                return (certificate, Path.ChangeExtension(certificate, ".key"));

            dir = dir.Parent;
        }

        throw new FileNotFoundException(
            $"Could not find tests/docker/certs/server.crt above '{AppContext.BaseDirectory}'.");
    }

    /// <summary>Stops the server process this instance started — by handle, never by name.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync();
            }
        }
        catch (InvalidOperationException)
        {
            // Already exited.
        }
        finally
        {
            _process.Dispose();
        }
    }
}

/// <summary>
/// A minimal HTTP server on loopback, used as the target the tunnel carries traffic to.
/// </summary>
/// <remarks>
/// It reads the request before replying. Replying first lets the socket close while the client
/// is still sending, which surfaces on Windows as an RST that discards the queued response —
/// the same lesson the docker harness's <c>serve.sh</c> carries.
/// </remarks>
public sealed class LoopbackEchoServer : IDisposable
{
    /// <summary>The body every request is answered with.</summary>
    public const string Body = "QPN-ECHO-OK";

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    private LoopbackEchoServer(TcpListener listener)
    {
        _listener = listener;
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync();
    }

    /// <summary>Port the server accepts on.</summary>
    public int Port { get; }

    /// <summary>Starts accepting on an ephemeral loopback port.</summary>
    public static LoopbackEchoServer Start()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new LoopbackEchoServer(listener);
    }

    private async Task AcceptLoopAsync()
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

                // The whole request head has to be drained before replying. Answering after the
                // first read leaves the client still writing into a socket this side is about to
                // close, which on Windows surfaces as an RST that discards the queued response —
                // so a large request would fail while a small one passed. Same lesson as the
                // docker harness's serve.sh.
                if (!await DrainRequestAsync(stream))
                    return;

                byte[] response = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/plain\r\n" +
                    $"Content-Length: {Body.Length}\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    Body);

                await stream.WriteAsync(response, _cts.Token);
                await stream.FlushAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
            {
                // The tunnel went away; nothing to report.
            }
        }
    }

    /// <summary>
    /// Reads until the end of the HTTP request head, or the client stops sending.
    /// </summary>
    /// <returns>False when the client disconnected without sending a request.</returns>
    private async Task<bool> DrainRequestAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int matched = 0;
        bool sawAnything = false;

        while (true)
        {
            int read = await stream.ReadAsync(buffer, _cts.Token);
            if (read <= 0)
                return sawAnything;

            sawAnything = true;

            for (int i = 0; i < read; i++)
            {
                // Matching "\r\n\r\n" incrementally, since it can straddle two reads.
                char expected = matched switch { 0 or 2 => '\r', _ => '\n' };
                matched = buffer[i] == expected ? matched + 1 : buffer[i] == '\r' ? 1 : 0;

                if (matched == 4)
                    return true;
            }
        }
    }

    /// <summary>Stops accepting.</summary>
    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        _cts.Dispose();
    }
}
