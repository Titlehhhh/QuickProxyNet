using System.Net;
using System.Net.Sockets;

namespace QuickProxyNet;

/// <summary>
/// Provides static convenience methods for connecting through a proxy in a single call.
/// No intermediate <see cref="IProxyClient"/> is allocated — the socket and tunnel
/// negotiation happen inline, making this ideal for mass proxy checking.
/// </summary>
/// <example>
/// <code>
/// await using var stream = await Proxy.ConnectAsync(
///     new Uri("socks5://user:pass@127.0.0.1:1080"),
///     "example.com", 443);
/// </code>
/// </example>
public static class Proxy
{
    /// <summary>
    /// Connects to a target host through the specified proxy.
    /// Opens a socket, negotiates the tunnel, and returns the connected stream.
    /// The caller owns the returned <see cref="Stream"/> and must dispose it.
    /// </summary>
    /// <param name="proxyUri">
    /// Proxy URI including scheme, host, port, and optional credentials.
    /// Supported schemes: http, https, socks4, socks4a, socks5.
    /// </param>
    /// <param name="host">The target host to connect to through the proxy.</param>
    /// <param name="port">The target port.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static ValueTask<Stream> ConnectAsync(Uri proxyUri, string host, int port,
        CancellationToken cancellationToken = default)
    {
        return ConnectCoreAsync(proxyUri, host, port, timeout: null, cancellationToken);
    }

    /// <summary>
    /// Connects to a target host through the specified proxy with a timeout.
    /// </summary>
    /// <param name="proxyUri">
    /// Proxy URI including scheme, host, port, and optional credentials.
    /// Supported schemes: http, https, socks4, socks4a, socks5.
    /// </param>
    /// <param name="host">The target host to connect to through the proxy.</param>
    /// <param name="port">The target port.</param>
    /// <param name="timeout">Maximum time to wait for the connection to complete.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static ValueTask<Stream> ConnectAsync(Uri proxyUri, string host, int port,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        return ConnectCoreAsync(proxyUri, host, port, timeout, cancellationToken);
    }

    /// <summary>
    /// Negotiates a proxy tunnel over an existing stream (e.g. for proxy chaining).
    /// No socket is created — the caller provides an already-connected stream to the proxy.
    /// </summary>
    /// <param name="proxyUri">
    /// Proxy URI including scheme and optional credentials.
    /// Supported schemes: http, https, socks4, socks4a, socks5.
    /// </param>
    /// <param name="source">An already-connected stream to the proxy server.</param>
    /// <param name="host">The target host to connect to through the proxy.</param>
    /// <param name="port">The target port.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static ValueTask<Stream> ConnectAsync(Uri proxyUri, Stream source, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var credentials = ParseCredentials(proxyUri);
        return ProxyConnector.ConnectToProxyAsync(source, proxyUri, host, port, credentials, cancellationToken);
    }

    private static async ValueTask<Stream> ConnectCoreAsync(Uri proxyUri, string host, int port,
        TimeSpan? timeout, CancellationToken cancellationToken)
    {
        ProxyClient.ValidateArguments(host, port);
        cancellationToken.ThrowIfCancellationRequested();

        var credentials = ParseCredentials(proxyUri);

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            LingerState = new LingerOption(true, 0)
        };

        ITimer? timer = null;
        if (timeout.HasValue)
            timer = TimeProvider.System.CreateTimer(static s => ((Socket)s!).Dispose(), socket,
                timeout.Value, Timeout.InfiniteTimeSpan);

        try
        {
            await socket.ConnectAsync(proxyUri.Host, proxyUri.Port, cancellationToken);
        }
        catch
        {
            if (timer is not null) await timer.DisposeAsync();
            socket.Dispose();
            throw;
        }

        var stream = new NetworkStream(socket, ownsSocket: true);
        try
        {
            var result = await ProxyConnector.ConnectToProxyAsync(stream, proxyUri, host, port, credentials,
                cancellationToken);
            return result;
        }
        catch
        {
            if (timer is not null) await timer.DisposeAsync();
            await stream.DisposeAsync();
            throw;
        }
        finally
        {
            if (timer is not null) await timer.DisposeAsync();
        }
    }

    private static NetworkCredential? ParseCredentials(Uri proxyUri)
    {
        if (string.IsNullOrEmpty(proxyUri.UserInfo))
            return null;

        var sep = proxyUri.UserInfo.IndexOf(':');
        if (sep < 0)
            return new NetworkCredential(proxyUri.UserInfo, string.Empty);

        return new NetworkCredential(
            proxyUri.UserInfo.Substring(0, sep),
            proxyUri.UserInfo.Substring(sep + 1));
    }
}

/// <summary>
/// Extension methods for connecting through proxies via <see cref="Uri"/>.
/// </summary>
public static class ProxyUriExtensions
{
    /// <summary>
    /// Connects to a target host through the proxy specified by this URI.
    /// </summary>
    /// <param name="proxyUri">The proxy URI (scheme://[user:pass@]host:port).</param>
    /// <param name="host">The target host.</param>
    /// <param name="port">The target port.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static ValueTask<Stream> ConnectThroughProxyAsync(this Uri proxyUri, string host, int port,
        CancellationToken cancellationToken = default)
    {
        return Proxy.ConnectAsync(proxyUri, host, port, cancellationToken);
    }

    /// <summary>
    /// Connects to a target host through the proxy specified by this URI, with a timeout.
    /// </summary>
    /// <param name="proxyUri">The proxy URI (scheme://[user:pass@]host:port).</param>
    /// <param name="host">The target host.</param>
    /// <param name="port">The target port.</param>
    /// <param name="timeout">Maximum time to wait for the connection.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static ValueTask<Stream> ConnectThroughProxyAsync(this Uri proxyUri, string host, int port,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        return Proxy.ConnectAsync(proxyUri, host, port, timeout, cancellationToken);
    }
}
