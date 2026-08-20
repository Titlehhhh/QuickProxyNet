using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet.Reality;

/// <summary>
/// A VLESS REALITY (or TLS + XTLS Vision) tunnel, provided by a local Xray-core process with a
/// loopback SOCKS5 inbound in front of it.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is and is not.</b> REALITY authenticates by hiding a key exchange inside the TLS
/// <c>session_id</c> of a ClientHello that must be byte-identical to a real browser's. .NET's
/// <see cref="System.Net.Security.SslStream"/> delegates the handshake to Schannel or OpenSSL and
/// exposes no way to author that ClientHello, so QuickProxyNet's in-process VLESS client cannot
/// speak REALITY and says so rather than downgrading. This package closes that gap the honest
/// way — by running the reference implementation — instead of by approximating a fingerprint,
/// which would mark the user as "not the browser I claim to be" rather than merely failing.
/// </para>
/// <para>
/// The cost is a child process and a binary the caller has to supply. In exchange, everything
/// Xray speaks comes with it: REALITY, <c>xtls-rprx-vision</c>, and the transports underneath.
/// </para>
/// <para>
/// <b>Lifetime.</b> One instance owns exactly one Xray process and one loopback port.
/// <see cref="DisposeAsync"/> kills that process by its own handle — never by image name, since
/// the user's own VPN client is very likely running a binary with the same name.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// await using var proxy = await RealityProxy.StartAsync(
///     "vless://uuid@example.com:443?security=reality&amp;pbk=...&amp;sid=ab12&amp;sni=www.cloudflare.com&amp;fp=chrome#node");
/// await using Stream tunnel = await proxy.ConnectAsync("example.org", 80);
/// </code>
/// </example>
public sealed class RealityProxy : IAsyncDisposable
{
    private readonly Process _process;
    private readonly Socks5Client _client;
    private int _disposed;

    private RealityProxy(Process process, Socks5Client client, string listenAddress, int port)
    {
        _process = process;
        _client = client;
        ListenAddress = listenAddress;
        ListenPort = port;
    }

    /// <summary>Loopback address the local SOCKS5 inbound is bound to.</summary>
    public string ListenAddress { get; }

    /// <summary>Port the local SOCKS5 inbound is bound to.</summary>
    public int ListenPort { get; }

    /// <summary>
    /// A SOCKS5 client aimed at the local inbound, for handing to code that takes an
    /// <see cref="IProxyClient"/>.
    /// </summary>
    public IProxyClient Client => _client;

    /// <summary>Whether the Xray process is still running.</summary>
    /// <remarks>
    /// False once disposed. <see cref="Process.HasExited"/> throws on a disposed handle, and a
    /// property that answers "is it running" by throwing is worse than useless to a caller
    /// cleaning up.
    /// </remarks>
    public bool IsRunning
    {
        get
        {
            if (Volatile.Read(ref _disposed) != 0)
                return false;

            try
            {
                return !_process.HasExited;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
    }

    /// <summary>Starts a tunnel for a <c>vless://</c> share link.</summary>
    /// <param name="shareLink">A <c>vless://</c> link with <c>security=reality</c> or <c>security=tls</c>.</param>
    /// <param name="options">Process settings, or null for the defaults.</param>
    /// <param name="cancellationToken">Cancels startup.</param>
    public static ValueTask<RealityProxy> StartAsync(
        string shareLink,
        RealityProxyOptions? options = null,
        CancellationToken cancellationToken = default) =>
        StartAsync(VlessShareLink.Parse(shareLink), options, cancellationToken);

    /// <summary>Starts a tunnel for an already-parsed VLESS configuration.</summary>
    /// <param name="vless">The outbound to drive.</param>
    /// <param name="options">Process settings, or null for the defaults.</param>
    /// <param name="cancellationToken">Cancels startup.</param>
    /// <exception cref="FileNotFoundException">Xray-core could not be located.</exception>
    /// <exception cref="NotSupportedException">The configuration cannot be rendered.</exception>
    /// <exception cref="InvalidOperationException">Xray started but never accepted on the inbound.</exception>
    public static async ValueTask<RealityProxy> StartAsync(
        VlessOptions vless,
        RealityProxyOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vless);
        options ??= new RealityProxyOptions();

        string executable = XrayExecutable.Resolve(options.ExecutablePath);
        int port = options.ListenPort ?? ReserveEphemeralPort(options.ListenAddress);

        // Rendered before the process exists so a bad configuration throws without leaving one behind.
        byte[] config = XrayClientConfig.Build(vless, options.ListenAddress, port, options.LogLevel);

        var startInfo = new ProcessStartInfo(executable)
        {
            // 'stdin:' is what keeps the VLESS id off disk. See XrayClientConfig.
            ArgumentList = { "run", "-c", "stdin:" },
            WorkingDirectory = Path.GetDirectoryName(executable) ?? Environment.CurrentDirectory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start '{executable}'.");

        var log = new OutputBuffer(options.LogSink);
        var proxy = new RealityProxy(process, new Socks5Client(options.ListenAddress, port), options.ListenAddress, port);

        try
        {
            log.Attach(process);

            try
            {
                await process.StandardInput.BaseStream.WriteAsync(config, cancellationToken).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // The credential is gone from our memory as soon as it has been handed over,
                // and stdin must close for Xray to know the document ended.
                Array.Clear(config);
                process.StandardInput.Close();
            }

            await WaitUntilAcceptingAsync(process, options, port, log, cancellationToken).ConfigureAwait(false);
            return proxy;
        }
        catch
        {
            await proxy.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Opens a tunnelled connection to <paramref name="host"/>:<paramref name="port"/>.</summary>
    /// <param name="host">Target host; resolved by the remote server, not locally.</param>
    /// <param name="port">Target port.</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    public ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _client.ConnectAsync(host, port, cancellationToken);
    }

    /// <summary>Stops the Xray process this instance started.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        try
        {
            if (!_process.HasExited)
            {
                // By handle, and only this handle. Killing by image name would take down the
                // user's own VPN client, which almost certainly runs a binary called 'xray'.
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync().ConfigureAwait(false);
            }
        }
        catch (InvalidOperationException)
        {
            // Already gone between the check and the kill.
        }
        finally
        {
            _process.Dispose();
        }
    }

    /// <summary>
    /// Polls the inbound until it accepts, failing fast if Xray dies first.
    /// </summary>
    /// <remarks>
    /// Xray binds its inbounds only after the whole configuration has been accepted, so an
    /// accepted connection is real evidence the tunnel is configured — unlike a fixed delay,
    /// which would be both slower and a guess.
    /// </remarks>
    private static async Task WaitUntilAcceptingAsync(
        Process process, RealityProxyOptions options, int port, OutputBuffer log, CancellationToken cancellationToken)
    {
        long deadline = Environment.TickCount64 + (long)options.StartupTimeout.TotalMilliseconds;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (process.HasExited)
                throw new InvalidOperationException(
                    $"Xray exited with code {process.ExitCode} during startup.{log.Format()}");

            if (await TryConnectAsync(options.ListenAddress, port, cancellationToken).ConfigureAwait(false))
                return;

            if (Environment.TickCount64 > deadline)
                throw new InvalidOperationException(
                    $"Xray did not start accepting on {options.ListenAddress}:{port} within " +
                    $"{options.StartupTimeout}.{log.Format()}");

            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<bool> TryConnectAsync(string address, int port, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(2));

        try
        {
            await socket.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is SocketException || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            return false;
        }
    }

    /// <summary>
    /// Binds port 0, reads what the OS handed out, and releases it.
    /// </summary>
    /// <remarks>
    /// There is a window between releasing the port and Xray binding it in which something else
    /// could take it; Xray then fails to start and <see cref="StartAsync(VlessOptions, RealityProxyOptions, CancellationToken)"/>
    /// throws with its output. That is preferable to the alternative, which is holding the socket
    /// open and having Xray fail to bind every time. Callers who need determinism set
    /// <see cref="RealityProxyOptions.ListenPort"/>.
    /// </remarks>
    private static int ReserveEphemeralPort(string address)
    {
        var listener = new TcpListener(IPAddress.Parse(address), 0);
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

    /// <summary>
    /// Keeps the last few lines of Xray's output so a startup failure can quote the reason.
    /// </summary>
    private sealed class OutputBuffer(Action<string>? sink)
    {
        private const int MaxLines = 20;
        private readonly Queue<string> _lines = new();

        public void Attach(Process process)
        {
            process.OutputDataReceived += OnData;
            process.ErrorDataReceived += OnData;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
        }

        private void OnData(object? sender, DataReceivedEventArgs e)
        {
            if (e.Data is null)
                return;

            sink?.Invoke(e.Data);

            lock (_lines)
            {
                _lines.Enqueue(e.Data);
                if (_lines.Count > MaxLines)
                    _lines.Dequeue();
            }
        }

        public string Format()
        {
            lock (_lines)
            {
                if (_lines.Count == 0)
                    return " It produced no output.";

                var sb = new StringBuilder(" Its last output was:");
                foreach (string line in _lines)
                    sb.Append('\n').Append("  ").Append(line);

                return sb.ToString();
            }
        }
    }
}
