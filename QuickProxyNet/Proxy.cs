using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

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
    /// Connects to a target host through a proxy described by a URL or share link of any
    /// supported scheme, including <c>vless</c>, <c>trojan</c> and <c>vmess</c>.
    /// </summary>
    /// <param name="proxyLink">
    /// The proxy URL or share link. See <see cref="Create(string)"/> for the schemes this accepts.
    /// </param>
    /// <param name="host">The target host to connect to through the proxy.</param>
    /// <param name="port">The target port.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    /// <remarks>
    /// The <see cref="Uri"/> overloads below cover only the classic schemes, and deliberately so:
    /// they skip the client object entirely, which is what makes them suitable for checking
    /// proxies by the thousand. This one goes through <see cref="Create(string)"/> instead,
    /// because VLESS, Trojan and VMess need the parsed configuration to negotiate at all. When
    /// you have a link and no reason to care which family it belongs to, use this.
    /// </remarks>
    public static async ValueTask<Stream> ConnectAsync(string proxyLink, string host, int port,
        CancellationToken cancellationToken = default)
    {
        IProxyClient client = Create(proxyLink);
        return await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Connects to a target host through a proxy described by a URL or share link, giving up
    /// after <paramref name="timeout"/>.
    /// </summary>
    /// <param name="proxyLink">The proxy URL or share link.</param>
    /// <param name="host">The target host to connect to through the proxy.</param>
    /// <param name="port">The target port.</param>
    /// <param name="timeout">Maximum time to wait for the connection to complete.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A connected <see cref="Stream"/> tunneled through the proxy.</returns>
    public static async ValueTask<Stream> ConnectAsync(string proxyLink, string host, int port,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        IProxyClient client = Create(proxyLink);
        return await client.ConnectAsync(host, port, timeout, cancellationToken).ConfigureAwait(false);
    }

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

    /// <summary>
    /// Creates an <see cref="IProxyClient"/> from a proxy URL or share link, whatever its scheme.
    /// </summary>
    /// <param name="proxyLink">
    /// <c>http</c>, <c>https</c>, <c>socks4</c>, <c>socks4a</c>, <c>socks5</c>, <c>vless</c>,
    /// <c>trojan</c> or <c>vmess</c>. Credentials in the authority are honoured for the classic
    /// schemes; the rest carry their configuration in the link itself.
    /// </param>
    /// <returns>A client ready to <see cref="IProxyClient.ConnectAsync(string, int, CancellationToken)"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="proxyLink"/> is empty or has no scheme.</exception>
    /// <exception cref="NotSupportedException">The scheme is not one this library speaks.</exception>
    /// <exception cref="FormatException">The scheme is known but the link is malformed.</exception>
    /// <remarks>
    /// <para>
    /// This is the entry point to reach for when all you have is a string. It reads the scheme
    /// off the front of the text rather than going through <see cref="Uri"/>, which matters for
    /// <c>vmess://</c>: those links are base64-encoded JSON, and <see cref="Uri"/> rejects most
    /// real ones outright for exceeding its host-length limit or carrying base64 padding. Via
    /// <see cref="Create(Uri)"/> such a link cannot even be represented, let alone parsed.
    /// </para>
    /// <para>
    /// Use <see cref="TryCreate(string, out IProxyClient?, out string?)"/> to walk a whole
    /// subscription: a list from the wild always contains links this library cannot speak, and
    /// driving that with exceptions costs more than it tells you.
    /// </para>
    /// </remarks>
    public static IProxyClient Create(string proxyLink)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proxyLink);

        string trimmed = proxyLink.Trim();
        int separator = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (separator <= 0)
            throw new ArgumentException(
                $"The proxy link ({trimmed.Length} characters) has no scheme: expected something like " +
                "'socks5://host:port' or 'vless://...'.", nameof(proxyLink));

        ReadOnlySpan<char> scheme = trimmed.AsSpan(0, separator);

        // The share-link protocols carry everything in the text and are parsed from it directly.
        if (scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            return Tag(new VlessClient(VlessShareLink.Parse(trimmed)), trimmed);

        if (scheme.Equals("trojan", StringComparison.OrdinalIgnoreCase))
            return Tag(new TrojanClient(TrojanShareLink.Parse(trimmed)), trimmed);

        if (scheme.Equals("vmess", StringComparison.OrdinalIgnoreCase))
            return Tag(new VmessClient(VmessShareLink.Parse(trimmed)), trimmed);

        // The classic ones are host/port URIs, so they go through Uri for its authority parsing.
        if (scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks4", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks4a", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri))
                throw new FormatException(
                    $"The {scheme} proxy link is not a well-formed URI (expected '{scheme}://[user:password@]host:port').");

            return Tag(Create(uri), trimmed);
        }

        throw new NotSupportedException(
            $"Proxy scheme '{scheme}' is not supported. This library speaks http, https, socks4, " +
            "socks4a, socks5, vless, trojan and vmess.");
    }

    /// <summary>
    /// Attempts to create an <see cref="IProxyClient"/> from a proxy URL or share link.
    /// </summary>
    /// <param name="proxyLink">The proxy URL or share link, in any scheme <see cref="Create(string)"/> accepts.</param>
    /// <param name="client">The created client, or <see langword="null"/> when the link could not be used.</param>
    /// <returns><see langword="true"/> when a client was created.</returns>
    public static bool TryCreate(string proxyLink, [NotNullWhen(true)] out IProxyClient? client) =>
        TryCreate(proxyLink, out client, out _);

    /// <summary>
    /// Attempts to create an <see cref="IProxyClient"/> from a proxy URL or share link, reporting
    /// why a rejected link was rejected.
    /// </summary>
    /// <param name="proxyLink">The proxy URL or share link, in any scheme <see cref="Create(string)"/> accepts.</param>
    /// <param name="client">The created client, or <see langword="null"/> when the link could not be used.</param>
    /// <param name="error">
    /// <see langword="null"/> on success; otherwise the exception type and message, which is what
    /// makes a rejection worth grouping — a run over real links wants to know how many were an
    /// unsupported scheme versus a truncated payload.
    /// </param>
    /// <returns><see langword="true"/> when a client was created.</returns>
    /// <remarks>
    /// This never throws for bad input, including input no parser anticipated. A subscription is
    /// other people's text: one malformed line out of thousands must not end the run, and a
    /// rejection naming an exception type the parsers do not raise on purpose is how a parser bug
    /// makes itself visible instead of hiding behind a caller's <c>catch</c>.
    /// </remarks>
    public static bool TryCreate(
        string proxyLink,
        [NotNullWhen(true)] out IProxyClient? client,
        [NotNullWhen(false)] out string? error)
    {
        try
        {
            client = Create(proxyLink);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            client = null;
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Creates an <see cref="IProxyClient"/> from a proxy <see cref="Uri"/>, taking the proxy type
    /// from the scheme and the credentials from the authority when present.
    /// </summary>
    /// <param name="proxyUri">The proxy URI, including scheme, host, port and optional credentials.</param>
    /// <returns>A client configured for the proxy the URI describes.</returns>
    /// <exception cref="NotSupportedException">The URI scheme is not one this library speaks.</exception>
    /// <remarks>
    /// <b>Note for <c>vmess://</c>:</b> a VMess share link is base64-encoded JSON rather than a
    /// host/port URI, and <see cref="Uri"/> rejects a payload longer than its host-length limit or
    /// containing base64 padding — which covers most real-world links. Such a link cannot be turned
    /// into a <see cref="Uri"/> at all, so prefer <see cref="Create(string)"/>. The special case
    /// below exists for the short links that <em>are</em> representable.
    /// </remarks>
    public static IProxyClient Create(Uri proxyUri)
    {
        ArgumentNullException.ThrowIfNull(proxyUri);

        // VLESS, Trojan and VMess carry their whole configuration (uuid, security, sni, ...) in
        // the URI, so they are parsed as share links rather than as host/port/credential triples.
        if (proxyUri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            return Tag(new VlessClient(VlessShareLink.Parse(proxyUri.OriginalString)), proxyUri.OriginalString);

        if (proxyUri.Scheme.Equals("trojan", StringComparison.OrdinalIgnoreCase))
            return Tag(new TrojanClient(TrojanShareLink.Parse(proxyUri.OriginalString)), proxyUri.OriginalString);

        if (proxyUri.Scheme.Equals("vmess", StringComparison.OrdinalIgnoreCase))
            return Tag(new VmessClient(VmessShareLink.Parse(proxyUri.OriginalString)), proxyUri.OriginalString);

        ProxyType type = proxyUri.Scheme switch
        {
            "http" => ProxyType.Http,
            "https" => ProxyType.Https,
            "socks4" => ProxyType.Socks4,
            "socks4a" => ProxyType.Socks4a,
            "socks5" => ProxyType.Socks5,
            _ => throw new NotSupportedException(
                $"Proxy scheme '{proxyUri.Scheme}' is not supported. This library speaks http, https, socks4, " +
                "socks4a, socks5, vless, trojan and vmess.")
        };

        return Tag(Create(type, proxyUri.Host, proxyUri.Port, ParseCredentials(proxyUri)), proxyUri.OriginalString);
    }

    /// <summary>
    /// Creates an <see cref="IProxyClient"/> for one of the classic proxy families from explicit
    /// settings.
    /// </summary>
    /// <param name="type">The proxy type. The share-link families are not created this way.</param>
    /// <param name="host">The hostname or IP address of the proxy server.</param>
    /// <param name="port">The port the proxy listens on.</param>
    /// <param name="credentials">Credentials for the proxy, or <see langword="null"/> for none.</param>
    /// <returns>A client configured for the given proxy.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="type"/> is one of the share-link families, which need a parsed
    /// configuration and cannot be described by host and port alone.
    /// </exception>
    public static IProxyClient Create(ProxyType type, string host, int port, NetworkCredential? credentials)
    {
        if (credentials is null)
            return CreateClassic(type, host, port);

        return type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port, credentials),
            ProxyType.Https => new HttpsProxyClient(host, port, credentials),
            ProxyType.Socks4 => new Socks4Client(host, port, credentials),
            ProxyType.Socks4a => new Socks4aClient(host, port, credentials),
            ProxyType.Socks5 => new Socks5Client(host, port, credentials),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, ShareLinkFamilyMessage)
        };
    }

    private static IProxyClient CreateClassic(ProxyType type, string host, int port) =>
        type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port),
            ProxyType.Https => new HttpsProxyClient(host, port),
            ProxyType.Socks4 => new Socks4Client(host, port),
            ProxyType.Socks4a => new Socks4aClient(host, port),
            ProxyType.Socks5 => new Socks5Client(host, port),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, ShareLinkFamilyMessage)
        };

    private const string ShareLinkFamilyMessage =
        "VLESS, Trojan and VMess carry a configuration that host and port cannot express; " +
        "build them from a share link instead.";

    // Records the text a client was built from, so a caller holding only IProxyClient can report
    // the node it checked. ProxyUri cannot stand in: for the share-link families it is only
    // scheme://host:port, and writing a vless node out that way drops its uuid, sni and transport.
    private static IProxyClient Tag(IProxyClient client, string link)
    {
        if (client is ProxyClient concrete)
            concrete.SourceLink = link;
        return client;
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
        StrongBox<bool>? timedOut = null;
        if (timeout.HasValue)
        {
            timedOut = new StrongBox<bool>(false);
            timer = TimeProvider.System.CreateTimer(
                static s =>
                {
                    var state = (Tuple<Socket, StrongBox<bool>>)s!;
                    Volatile.Write(ref state.Item2.Value, true);
                    state.Item1.Dispose();
                },
                Tuple.Create(socket, timedOut), timeout.Value, Timeout.InfiniteTimeSpan);
        }

        try
        {
            await socket.ConnectAsync(proxyUri.Host, proxyUri.Port, cancellationToken);
        }
        catch (Exception ex)
        {
            if (timer is not null) await timer.DisposeAsync();
            socket.Dispose();
            if (timedOut is not null && Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {proxyUri.Host}:{proxyUri.Port} timed out after {timeout!.Value}.", ex);
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Failed to connect to proxy {proxyUri.Host}:{proxyUri.Port} for target {host}:{port}.", ex);
        }

        var stream = new NetworkStream(socket, ownsSocket: true);
        try
        {
            var result = await ProxyConnector.ConnectToProxyAsync(stream, proxyUri, host, port, credentials,
                cancellationToken);
            // Dispose timer before returning to prevent race where timer fires
            // and destroys the socket after we hand the stream to the caller.
            if (timer is not null) await timer.DisposeAsync();
            return result;
        }
        catch (Exception ex)
        {
            if (timer is not null) await timer.DisposeAsync();
            await stream.DisposeAsync();
            if (timedOut is not null && Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {proxyUri.Host}:{proxyUri.Port} timed out after {timeout!.Value}.", ex);
            throw;
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
