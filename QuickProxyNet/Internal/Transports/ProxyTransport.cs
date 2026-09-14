using System.Diagnostics.CodeAnalysis;

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
    /// <para>
    /// The path is otherwise sent verbatim, query and all. Xray's early-data feature encodes
    /// itself as <c>?ed=2048</c> on the path, and the server matches the path it was
    /// configured with — stripping or re-encoding the query turns a working node into a 404.
    /// </para>
    /// <para>
    /// A space is the one exception, and goes out as <c>%20</c>. A request target cannot hold one
    /// (RFC 9112 §3.2): the request line ends at it, and a server reads what follows as the HTTP
    /// version. A share link's path is percent-decoded, so its <c>%20</c> arrives here as a space,
    /// and 68 of the 10 822 vless links in the real-world corpus carry one in their ws path.
    /// Refusing them would refuse a path a server can be configured with. Xray's client builds
    /// this request with Go's net/url, which writes a space in a path as <c>%20</c>, and the
    /// server decodes it back before comparing. Control characters never get here:
    /// <see cref="TryValidateRequest"/> refuses them where the configuration enters.
    /// </para>
    /// </remarks>
    public static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return "/";

        if (path[0] != '/')
            path = "/" + path;

        return path.Contains(' ') ? path.Replace(" ", "%20") : path;
    }

    /// <summary>
    /// Checks the two configured values a <c>ws</c> or <c>httpupgrade</c> transport writes into its
    /// HTTP upgrade request: the path, in the request line, and the <c>Host</c> header.
    /// </summary>
    /// <param name="kind">The transport. Only <c>ws</c> and <c>httpupgrade</c> write either value.</param>
    /// <param name="path">The configured path, before <see cref="NormalizePath"/>.</param>
    /// <param name="hostHeader">The Host header value, as <see cref="ResolveHostHeader"/> picks it.</param>
    /// <param name="error">What is wrong, when this returns false.</param>
    /// <remarks>
    /// Both go into the request as the characters they are, and a share link decodes <c>%0D%0A</c>
    /// to CR LF, so <c>path=</c>, <c>host=</c> or <c>sni=</c> could end a line of the request and
    /// add headers, or a second request, to what the client sends the node's server or the CDN in
    /// front of it. An ASCII control character belongs in neither a request target nor a host
    /// name, and Go's net/url and net/http, which Xray builds the same request with, refuse one too.
    /// The raw-TCP transport writes neither value, so a tcp link with junk in an unused field is left
    /// working. The error names the field and the position, never the value: a path can carry a
    /// secret.
    /// </remarks>
    public static bool TryValidateRequest(
        TransportKind kind, string? path, string hostHeader, [NotNullWhen(false)] out string? error)
    {
        if (kind is not (TransportKind.WebSocket or TransportKind.HttpUpgrade))
        {
            error = null;
            return true;
        }

        string name = kind == TransportKind.WebSocket ? "ws" : "httpupgrade";

        int bad = IndexOfControl(path);
        if (bad >= 0)
        {
            error = $"The {name} transport's path cannot contain an ASCII control character; this one has " +
                    $"U+{(int)path![bad]:X4} at index {bad}.";
            return false;
        }

        bad = IndexOfControl(hostHeader);
        if (bad >= 0)
        {
            error = $"The {name} transport's Host header (host, else sni, else the server address) cannot " +
                    $"contain an ASCII control character; this one has U+{(int)hostHeader[bad]:X4} at index {bad}.";
            return false;
        }

        error = null;
        return true;
    }

    private static int IndexOfControl(ReadOnlySpan<char> value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] < ' ' || value[i] == (char)0x7F) // 0x7F is DEL
                return i;
        }

        return -1;
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
