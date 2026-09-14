using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace QuickProxyNet;

public abstract class ProxyClient : IProxyClient
{
    private ProxyClient(Uri uri)
    {
        ProxyUri = uri;

        ProxyHost = uri.Host;
        ProxyPort = uri.Port;

        if (!string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            var sep = uri.UserInfo.IndexOf(':');
            if (sep < 0)
                throw new ArgumentException("Invalid credentials format.", nameof(uri.UserInfo));

            ProxyCredentials = new NetworkCredential(
                uri.UserInfo.Substring(0, sep),
                uri.UserInfo.Substring(sep + 1));
        }
    }

    protected ProxyClient(string protocol, string host, int port)
    {
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port < 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        ProxyHost = host;
        ProxyPort = port == 0 ? 1080 : port;
        ProxyUri = new Uri($"{protocol}://{FormatUriHost(host)}:{port}");
    }

    protected ProxyClient(string protocol, string host, int port, NetworkCredential credentials)
    {
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port < 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        if (credentials == null)
            throw new ArgumentNullException(nameof(credentials));

        ProxyHost = host;
        ProxyPort = port == 0 ? 1080 : port;

        ProxyUri = new Uri($"{protocol}://{credentials.UserName}:{credentials.Password}@{FormatUriHost(host)}:{port}");
        ProxyCredentials = credentials;
    }

    // An IPv6 literal must be bracketed in a URI ("[2001:db8::1]"), otherwise the Uri
    // parser reads the address's colons as a port separator and throws. Host names and
    // IPv4 literals never contain ':', so this only affects IPv6 endpoints.
    // An IPv6 literal needs brackets inside a URI; one that already has them (a hand-built
    // options object may carry "[::1]") must not get a second pair.
    private static string FormatUriHost(string host) =>
        host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;

    public Uri ProxyUri { get; private set; }

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

    public int WriteTimeout { get; set; }
    public int ReadTimeout { get; set; }

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
            socket.NoDelay = NoDelay;
            socket.SendTimeout = WriteTimeout;
            socket.ReceiveTimeout = ReadTimeout;
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

    public async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        cancellationToken.ThrowIfCancellationRequested();

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

        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch (Exception ex)
        {
            socket.Dispose();
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Failed to connect to proxy {ProxyHost}:{ProxyPort} for target {host}:{port}.", ex);
        }

        var stream = new NetworkStream(socket, true);
        try
        {
            return await ConnectAsync(stream, host, port, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // The proxy closed or reset the connection while we were still negotiating. That is
            // the same failure class as "could not connect" from the caller's point of view, and
            // it must arrive as one: a raw IOException here is the one place the "all protocol
            // errors are ProxyProtocolException" promise was not kept.
            await stream.DisposeAsync();
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Proxy {ProxyHost}:{ProxyPort} closed the connection during the handshake for target {host}:{port}.", ex);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    public virtual async ValueTask<Stream> ConnectAsync(string host, int port, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        cancellationToken.ThrowIfCancellationRequested();

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

        var timedOut = new StrongBox<bool>(false);

        await using ITimer timer = TimeProvider.System.CreateTimer(
            static s =>
            {
                var state = (Tuple<Socket, StrongBox<bool>>)s!;
                Volatile.Write(ref state.Item2.Value, true);
                state.Item1.Dispose();
            },
            Tuple.Create(socket, timedOut), timeout, Timeout.InfiniteTimeSpan);

        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch (Exception ex)
        {
            socket.Dispose();
            if (Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {ProxyHost}:{ProxyPort} timed out after {timeout}.", ex);
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Failed to connect to proxy {ProxyHost}:{ProxyPort} for target {host}:{port}.", ex);
        }

        var stream = new NetworkStream(socket, true);
        try
        {
            return await ConnectAsync(stream, host, port, cancellationToken);
        }
        catch (Exception ex)
        {
            await stream.DisposeAsync();
            if (Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {ProxyHost}:{ProxyPort} timed out after {timeout}.", ex);
            if (ex is IOException or SocketException)
                throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                    $"Proxy {ProxyHost}:{ProxyPort} closed the connection during the handshake for target {host}:{port}.", ex);
            throw;
        }
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
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port <= 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));
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
