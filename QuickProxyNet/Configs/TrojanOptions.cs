namespace QuickProxyNet;

/// <summary>
/// Strongly-typed configuration for a Trojan outbound, produced by
/// <see cref="TrojanShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// Trojan is TLS-mandatory: the request header is written inside the TLS session. The
/// <c>tcp</c>/<c>raw</c>, <c>ws</c> and <c>httpupgrade</c> transports are supported at
/// connect time; others (<c>grpc</c>, …) are parsed so callers can inspect them, but
/// connecting with them throws <see cref="System.NotSupportedException"/>.
/// </remarks>
public sealed class TrojanOptions
{
    /// <summary>The Trojan password. Authenticated as <c>hex(SHA224(password))</c>.</summary>
    public required string Password { get; init; }

    /// <summary>Proxy server host name or IP address.</summary>
    public required string Host { get; init; }

    /// <summary>Proxy server port.</summary>
    public required int Port { get; init; }

    /// <summary>
    /// Transport network: <c>tcp</c>/<c>raw</c> (raw TCP), <c>ws</c>/<c>websocket</c>, or
    /// <c>httpupgrade</c>. Others (<c>grpc</c>, …) are unsupported.
    /// </summary>
    public string Transport { get; init; } = "tcp";

    /// <summary>
    /// Request path for the <c>ws</c>/<c>httpupgrade</c> transports (<c>path</c>). Defaults to
    /// <c>/</c>. Sent verbatim, including any query.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// <c>Host</c> header for the <c>ws</c>/<c>httpupgrade</c> transports (<c>host</c>).
    /// Falls back to <see cref="Sni"/>, then to <see cref="Host"/>.
    /// </summary>
    public string? HostHeader { get; init; }

    /// <summary>TLS server name (SNI). Falls back to <see cref="Host"/> when null.</summary>
    public string? Sni { get; init; }

    /// <summary>ALPN protocol identifiers for the TLS handshake, if specified.</summary>
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>
    /// When true, the proxy server's TLS certificate is accepted unconditionally
    /// (<c>allowInsecure</c>). Use only against known servers with self-signed certs.
    /// </summary>
    public bool AllowInsecure { get; init; }

    /// <summary>Human-readable label from the share-link fragment (<c>#name</c>).</summary>
    public string? Remark { get; init; }

    /// <summary>The resolved transport layer this configuration selects.</summary>
    internal TransportKind TransportKind => ProxyTransport.Resolve(Transport);
}
