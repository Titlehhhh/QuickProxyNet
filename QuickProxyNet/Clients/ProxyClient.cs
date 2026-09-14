using System.Net;
using System.Net.Sockets;

namespace QuickProxyNet;

public abstract class ProxyClient : IProxyClient
{
    private readonly string _scheme;

    protected ProxyClient(string protocol, string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (host.Length > 255)
            throw new ArgumentException("A host name is at most 255 characters.", nameof(host));

        // Zero is allowed here and means the default port.
        ArgumentOutOfRangeException.ThrowIfNegative(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        _scheme = protocol;
        // An IPv6 literal is kept unbracketed however it arrived: a Uri authority hands over
        // "[::1]", a parsed share link "::1", and code comparing hosts should not see both.
        ProxyHost = host.Length > 2 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        ProxyPort = port == 0 ? 1080 : port;
    }

    protected ProxyClient(string protocol, string host, int port, NetworkCredential credentials)
        : this(protocol, host, port)
    {
        ProxyCredentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
    }

    /// <summary>
    /// The proxy as <c>scheme://host:port</c>, for logs and diagnostics.
    /// </summary>
    /// <remarks>
    /// Never carries credentials, and for the share-link families none of what it takes to
    /// connect either: the uuid, sni and transport are in <see cref="SourceLink"/>.
    /// </remarks>
    public override string ToString() => ProxyHost.Contains(':')
        ? $"{_scheme}://[{ProxyHost}]:{ProxyPort}"
        : $"{_scheme}://{ProxyHost}:{ProxyPort}";

    /// <inheritdoc />
    /// <remarks>Set by the <see cref="Proxy"/> factory methods when a link was the input.</remarks>
    public string? SourceLink { get; internal set; }

    public abstract ProxyType Type { get; }

    public NetworkCredential? ProxyCredentials { get; }

    public string ProxyHost { get; }

    public int ProxyPort { get; }

    public IPEndPoint? LocalEndPoint { get; set; }

    public LingerOption? LingerState { get; set; } = new LingerOption(true, 0);
    public bool NoDelay { get; set; } = true;

    private Socket CreateSocket()
    {
        // Socket(SocketType, ProtocolType) is dual-mode wherever the OS has IPv6, so the proxy is
        // reachable at an address of either family; an IPv4-only socket fails every IPv6 proxy.
        // A LocalEndPoint is the caller choosing the interface, and with it the family.
        IPEndPoint? local = LocalEndPoint;
        var socket = local is null
            ? new Socket(SocketType.Stream, ProtocolType.Tcp)
            : new Socket(local.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            // No SendTimeout or ReceiveTimeout: they bound only synchronous socket calls, and every
            // read and write of the handshake is asynchronous. The timeout and the token given to
            // ConnectAsync are what bound it.
            socket.NoDelay = NoDelay;
            if (LingerState is not null)
                socket.LingerState = LingerState;
            if (local is not null)
                socket.Bind(local);
            return socket;
        }
        catch
        {
            // A failed bind must not leak the handle: under a few thousand concurrent checks the
            // leak is what turns one address-in-use into handle exhaustion.
            socket.Dispose();
            throw;
        }
    }

    public ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default) =>
        ConnectCoreAsync(host, port, timeout: null, cancellationToken);

    public virtual ValueTask<Stream> ConnectAsync(string host, int port, TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        ConnectCoreAsync(host, port, timeout, cancellationToken);

    /// <summary>The longest delay <see cref="CancellationTokenSource.CancelAfter(TimeSpan)"/> accepts.</summary>
    private static readonly TimeSpan MaxTimeout = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    private async ValueTask<Stream> ConnectCoreAsync(string host, int port, TimeSpan? timeout,
        CancellationToken cancellationToken)
    {
        ValidateArguments(host, port);

        // Checked before anything is allocated. The timer this replaced rejected the same values,
        // but only once the socket existed, and nothing disposed that socket.
        if (timeout is { } limit && limit != Timeout.InfiniteTimeSpan && (limit < TimeSpan.Zero || limit > MaxTimeout))
            throw new ArgumentOutOfRangeException(nameof(timeout), limit,
                "A timeout must be between zero and about 49 days, or Timeout.InfiniteTimeSpan.");

        cancellationToken.ThrowIfCancellationRequested();

        // The timeout is a cancellation like the caller's own, handed to every await of the connect
        // and the handshake. It used to be a timer that disposed the socket: it could fire after
        // the handshake had produced the stream, and the caller got a dead stream and no error.
        using CancellationTokenSource? timeoutSource = timeout is null
            ? null
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource?.CancelAfter(timeout!.Value);
        CancellationToken token = timeoutSource?.Token ?? cancellationToken;

        Socket socket;
        try
        {
            socket = CreateSocket();
        }
        catch (SocketException ex)
        {
            // CreateSocket binds LocalEndPoint and allocates a handle, so it fails for reasons a
            // caller must see as a connection failure like any other: an address already in use,
            // or handle exhaustion under a few thousand concurrent checks. Left outside the guard
            // this was the one path that escaped ConnectAsync as a raw SocketException.
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Could not open a socket for proxy {ProxyHost}:{ProxyPort}.", ex);
        }

        NetworkStream stream;
        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, token);
            // Inside the guard: on a socket that failed underneath, the constructor throws a raw
            // IOException of its own.
            stream = new NetworkStream(socket, ownsSocket: true);
        }
        catch (Exception ex)
        {
            socket.Dispose();
            throw Stopped(ex, timeout, timeoutSource, cancellationToken)
                ?? new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                    $"Failed to connect to proxy {ProxyHost}:{ProxyPort} for target {host}:{port}.", ex);
        }

        try
        {
            return await ConnectAsync(stream, host, port, token);
        }
        catch (Exception ex)
        {
            await stream.DisposeAsync();

            // The proxy closing or resetting the connection mid-negotiation is the same failure as
            // "could not connect" to the caller, and must arrive as one.
            Exception? translated = Stopped(ex, timeout, timeoutSource, cancellationToken)
                ?? (ex is IOException or SocketException
                    ? new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                        $"Proxy {ProxyHost}:{ProxyPort} closed the connection during the handshake for target {host}:{port}.", ex)
                    : null);

            if (translated is null)
                throw;
            throw translated;
        }
    }

    /// <summary>
    /// What a failure means when the attempt was stopped rather than refused, or null when it was not.
    /// </summary>
    /// <remarks>
    /// The caller's own cancellation is checked first, because it cancels the linked timeout source
    /// too. It is <see cref="OperationCanceledException"/> in every phase; it used to arrive wrapped
    /// as <see cref="ProxyErrorCode.ConnectionFailed"/> from the TCP connect and bare from the
    /// handshake. A timeout is never an <see cref="OperationCanceledException"/>.
    /// </remarks>
    private Exception? Stopped(Exception ex, TimeSpan? timeout, CancellationTokenSource? timeoutSource,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
            return new OperationCanceledException(
                $"The connection to proxy {ProxyHost}:{ProxyPort} was canceled.", ex, cancellationToken);

        if (timeoutSource is { IsCancellationRequested: true })
            return new ProxyProtocolException(ProxyErrorCode.Timeout,
                $"Connection to proxy {ProxyHost}:{ProxyPort} timed out after {timeout}.", ex);

        return null;
    }

    public abstract ValueTask<Stream> ConnectAsync(Stream source, string host, int port,
        CancellationToken cancellationToken = default);

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(EndPoint target, CancellationToken cancellationToken = default)
    {
        var (host, port) = SplitTarget(target);
        return await ConnectAsync(host, port, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(EndPoint target, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var (host, port) = SplitTarget(target);
        return await ConnectAsync(host, port, timeout, cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(Stream source, EndPoint target,
        CancellationToken cancellationToken = default)
    {
        var (host, port) = SplitTarget(target);
        return await ConnectAsync(source, host, port, cancellationToken);
    }

    internal static void ValidateArguments(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (host.Length > 255)
            throw new ArgumentException("A host name is at most 255 characters.", nameof(host));

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
    }

    // The EndPoint overloads spell the target the way the host-and-port ones take it. An
    // IPv4-mapped address is an IPv4 host however a dual-mode socket reports it; left as IPv6,
    // SOCKS5, VLESS, VMess and Trojan would all put an IPv6 address type on the wire for it.
    internal static (string Host, int Port) SplitTarget(EndPoint target)
    {
        ArgumentNullException.ThrowIfNull(target);

        return target switch
        {
            DnsEndPoint dns => (dns.Host, dns.Port),
            IPEndPoint ip => (
                (ip.Address.IsIPv4MappedToIPv6 ? ip.Address.MapToIPv4() : ip.Address).ToString(), ip.Port),
            _ => throw new ArgumentException(
                $"A proxy target must be a {nameof(DnsEndPoint)} or an {nameof(IPEndPoint)}, not {target.GetType().Name}.",
                nameof(target))
        };
    }
}
