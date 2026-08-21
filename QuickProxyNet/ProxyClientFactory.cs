using System.Net;

namespace QuickProxyNet;

/// <summary>
/// Provides a factory for creating proxy client instances based on a specified URI or configuration.
/// This class simplifies the process of selecting the correct proxy type and configuring it with the necessary settings.
/// </summary>
public sealed class ProxyClientFactory
{
    /// <summary>
    /// Gets a singleton instance of the ProxyClientFactory.
    /// </summary>
    public static ProxyClientFactory Instance { get; } = new();

    /// <summary>
    /// Creates an <see cref="IProxyClient"/> from a proxy URL or share link, whatever its scheme.
    /// </summary>
    /// <param name="link">
    /// <c>http</c>, <c>https</c>, <c>socks4</c>, <c>socks4a</c>, <c>socks5</c>, <c>vless</c>,
    /// <c>trojan</c> or <c>vmess</c>. Credentials in the authority are honoured for the classic
    /// schemes; the rest carry their configuration in the link itself.
    /// </param>
    /// <returns>A client ready to <see cref="IProxyClient.ConnectAsync(string, int, CancellationToken)"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="link"/> is empty or has no scheme.</exception>
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
    /// </remarks>
    public IProxyClient Create(string link)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(link);

        string trimmed = link.Trim();
        int separator = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (separator <= 0)
            throw new ArgumentException(
                $"'{Summarize(trimmed)}' is not a proxy link: expected a scheme followed by '://'.", nameof(link));

        ReadOnlySpan<char> scheme = trimmed.AsSpan(0, separator);

        // The share-link protocols carry everything in the text and are parsed from it directly.
        if (scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            return new VlessClient(VlessShareLink.Parse(trimmed));

        if (scheme.Equals("trojan", StringComparison.OrdinalIgnoreCase))
            return new TrojanClient(TrojanShareLink.Parse(trimmed));

        if (scheme.Equals("vmess", StringComparison.OrdinalIgnoreCase))
            return new VmessClient(VmessShareLink.Parse(trimmed));

        // The classic ones are host/port URIs, so they go through Uri for its authority parsing.
        if (scheme.Equals("http", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks4", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks4a", StringComparison.OrdinalIgnoreCase) ||
            scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? uri))
                throw new FormatException($"'{Summarize(trimmed)}' is not a well-formed {scheme} URI.");

            return Create(uri);
        }

        throw new NotSupportedException(
            $"Proxy scheme '{scheme}' is not supported. This library speaks http, https, socks4, " +
            "socks4a, socks5, vless, trojan and vmess.");
    }

    /// <summary>Shortens a link for an error message, so a credential does not end up in a log.</summary>
    private static string Summarize(string link) =>
        link.Length <= 24 ? link : string.Concat(link.AsSpan(0, 24), "…");

    /// <summary>
    /// Creates an IProxyClient instance based on the provided URI, automatically determining the proxy type
    /// and extracting credentials if they are present in the URI.
    /// </summary>
    /// <param name="proxyUri">The URI of the proxy server, including scheme, host, port, and optional credentials.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy.</returns>
    /// <exception cref="NotSupportedException">Thrown if the URI scheme is not supported.</exception>
    /// <remarks>
    /// <b>Note for <c>vmess://</c>:</b> a VMess share link is base64-encoded JSON rather
    /// than a host/port URI, and <see cref="Uri"/> rejects a payload that is longer than
    /// its host-length limit or that contains base64 padding — which covers most
    /// real-world links. Such a link cannot be turned into a <see cref="Uri"/> at all, so
    /// prefer <see cref="VmessClient.FromShareLink(string)"/> (or
    /// <see cref="VmessShareLink.Parse(string)"/>) to parse the string directly. The
    /// special case below exists for the short links that <em>are</em> representable.
    /// </remarks>
    public IProxyClient Create(Uri proxyUri)
    {
        // VLESS carries its whole configuration (uuid, security, sni, …) in the URI,
        // so it is parsed as a share link rather than the generic host/port/credential path.
        if (proxyUri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            return new VlessClient(VlessShareLink.Parse(proxyUri.OriginalString));

        // Trojan likewise carries its whole configuration (password, sni, alpn, …) in the URI.
        if (proxyUri.Scheme.Equals("trojan", StringComparison.OrdinalIgnoreCase))
            return new TrojanClient(TrojanShareLink.Parse(proxyUri.OriginalString));

        // VMess carries its whole configuration as base64-encoded JSON in the URI body.
        if (proxyUri.Scheme.Equals("vmess", StringComparison.OrdinalIgnoreCase))
            return new VmessClient(VmessShareLink.Parse(proxyUri.OriginalString));

        NetworkCredential? credential = null;
        ProxyType type = proxyUri.Scheme switch
        {
            "http" => ProxyType.Http,
            "https" => ProxyType.Https,
            "socks4" => ProxyType.Socks4,
            "socks4a" => ProxyType.Socks4a,
            "socks5" => ProxyType.Socks5,
            _ => throw new NotSupportedException($"Scheme: {proxyUri.Scheme}")
        };

        if (!string.IsNullOrEmpty(proxyUri.UserInfo))
        {
            var sep = proxyUri.UserInfo.IndexOf(':');
            credential = sep < 0
                ? new NetworkCredential(proxyUri.UserInfo, string.Empty)
                : new NetworkCredential(
                    proxyUri.UserInfo.Substring(0, sep),
                    proxyUri.UserInfo.Substring(sep + 1));
        }

        return Create(type, proxyUri.Host, proxyUri.Port, credential);
    }

    /// <summary>
    /// Creates an IProxyClient instance based on the specified proxy type, host, and port.
    /// </summary>
    /// <param name="type">The type of proxy to create (e.g., HTTP, SOCKS5).</param>
    /// <param name="host">The hostname or IP address of the proxy server.</param>
    /// <param name="port">The port number of the proxy server.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy type.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the proxy type is unsupported.</exception>
    private IProxyClient Create(ProxyType type, string host, int port)
    {
        return type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port),
            ProxyType.Https => new HttpsProxyClient(host, port),
            ProxyType.Socks4 => new Socks4Client(host, port),
            ProxyType.Socks4a => new Socks4aClient(host, port),
            ProxyType.Socks5 => new Socks5Client(host, port),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }

    /// <summary>
    /// Creates an IProxyClient instance with optional credentials, based on the specified proxy type, host, and port.
    /// </summary>
    /// <param name="type">The type of proxy to create (e.g., HTTP, SOCKS5).</param>
    /// <param name="host">The hostname or IP address of the proxy server.</param>
    /// <param name="port">The port number of the proxy server.</param>
    /// <param name="networkCredential">Optional credentials for authenticating with the proxy server.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy type with the provided credentials.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the proxy type is unsupported.</exception>
    public IProxyClient Create(ProxyType type, string host, int port, NetworkCredential? networkCredential)
    {
        if (networkCredential is null)
        {
            return Create(type, host, port);
        }

        return type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port, networkCredential),
            ProxyType.Https => new HttpsProxyClient(host, port, networkCredential),
            ProxyType.Socks4 => new Socks4Client(host, port, networkCredential),
            ProxyType.Socks4a => new Socks4aClient(host, port, networkCredential),
            ProxyType.Socks5 => new Socks5Client(host, port, networkCredential),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }
}