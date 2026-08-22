namespace QuickProxyNet;

/// <summary>
/// The stream transport a VPN-style outbound is carried over, underneath the protocol header
/// and above TLS.
/// </summary>
internal enum TransportKind
{
    /// <summary>Raw TCP (<c>tcp</c>, <c>raw</c>, or unspecified) — no extra layer.</summary>
    RawTcp,

    /// <summary>RFC 6455 WebSocket (<c>ws</c>, <c>websocket</c>).</summary>
    WebSocket,

    /// <summary>Bare HTTP upgrade with no framing (<c>httpupgrade</c>).</summary>
    HttpUpgrade,

    /// <summary>A transport this library does not speak (<c>grpc</c>, <c>xhttp</c>, <c>h2</c>, …).</summary>
    Unsupported
}

/// <summary>
/// Resolves and applies the transport layer shared by the VLESS, VMess and Trojan clients.
/// </summary>
/// <remarks>
/// The layering is the same for all three: socket → optional <c>SslStream</c> → transport →
/// protocol request header. The transport knows nothing about which protocol rides on it,
/// which is why one implementation serves all three.
/// </remarks>
internal static class ProxyTransport
{
    public static TransportKind Resolve(string? transport)
    {
        if (string.IsNullOrEmpty(transport))
            return TransportKind.RawTcp;

        // 'raw' is Xray's newer name for 'tcp'; both mean no transport layer at all.
        if (transport.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
            transport.Equals("raw", StringComparison.OrdinalIgnoreCase))
            return TransportKind.RawTcp;

        if (transport.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
            transport.Equals("websocket", StringComparison.OrdinalIgnoreCase))
            return TransportKind.WebSocket;

        if (transport.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase))
            return TransportKind.HttpUpgrade;

        return TransportKind.Unsupported;
    }

    /// <summary>
    /// Wraps <paramref name="stream"/> in the requested transport, returning the stream the
    /// protocol header should be written to.
    /// </summary>
    /// <remarks>
    /// On failure the caller still owns <paramref name="stream"/> and must dispose it; nothing
    /// here takes ownership until the returned wrapper exists.
    /// </remarks>
    public static async ValueTask<Stream> ApplyAsync(
        TransportKind kind,
        Stream stream,
        string? path,
        string hostHeader,
        CancellationToken cancellationToken)
    {
        switch (kind)
        {
            case TransportKind.RawTcp:
                return stream;

            case TransportKind.WebSocket:
            {
                Stream upgraded = await HttpUpgradeHandshake
                    .PerformAsync(stream, NormalizePath(path), hostHeader, webSocket: true, cancellationToken)
                    .ConfigureAwait(false);
                return new WebSocketStream(upgraded);
            }

            case TransportKind.HttpUpgrade:
                // Not a WebSocket handshake: no Sec-WebSocket-* headers and nothing to validate.
                // sing-box answers 404 if the key is present — see HttpUpgradeHandshake.
                return await HttpUpgradeHandshake
                    .PerformAsync(stream, NormalizePath(path), hostHeader, webSocket: false, cancellationToken)
                    .ConfigureAwait(false);

            default:
                throw new NotSupportedException($"Transport kind '{kind}' has no implementation.");
        }
    }

    /// <summary>
    /// Normalizes the configured path to a request target.
    /// </summary>
    /// <remarks>
    /// The path is otherwise sent verbatim, query and all. Xray's early-data feature encodes
    /// itself as <c>?ed=2048</c> on the path, and the server matches the path it was
    /// configured with — stripping or re-encoding the query turns a working node into a 404.
    /// </remarks>
    public static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return "/";

        return path[0] == '/' ? path : "/" + path;
    }

    /// <summary>
    /// Picks the <c>Host</c> header: the explicit transport host, else the SNI, else the
    /// server address — the same precedence Xray and sing-box apply.
    /// </summary>
    public static string ResolveHostHeader(string? hostHeader, string? sni, string serverHost)
    {
        if (!string.IsNullOrEmpty(hostHeader))
            return hostHeader;
        if (!string.IsNullOrEmpty(sni))
            return sni;
        return serverHost;
    }
}
