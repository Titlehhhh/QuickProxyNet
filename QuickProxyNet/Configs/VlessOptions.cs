namespace QuickProxyNet;

/// <summary>
/// Transport security layer negotiated underneath the VLESS request header.
/// </summary>
public enum VlessSecurity
{
    /// <summary>Plain TCP, no encryption (<c>security=none</c>).</summary>
    None,

    /// <summary>Standard TLS via <see cref="System.Net.Security.SslStream"/> (<c>security=tls</c>).</summary>
    Tls,

    /// <summary>
    /// REALITY transport security (<c>security=reality</c>), spoken by this library's own
    /// TLS 1.3 client with no external process. Requires <see cref="VlessOptions.RealityPublicKey"/>.
    /// The ClientHello is not yet a browser fingerprint; see <c>docs/reality-fingerprint-plan.md</c>.
    /// </summary>
    Reality
}

/// <summary>
/// Strongly-typed configuration for a VLESS outbound, produced by
/// <see cref="VlessShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// Supported at connect time: the <c>tcp</c>/<c>raw</c>, <c>ws</c> and <c>httpupgrade</c>
/// transports with any of <see cref="VlessSecurity.None"/>, <see cref="VlessSecurity.Tls"/> or
/// <see cref="VlessSecurity.Reality"/>, with or without <c>xtls-rprx-vision</c> in
/// <see cref="Flow"/>. The rest (any other flow, the <c>grpc</c>/<c>xhttp</c> transports) is
/// parsed so callers can inspect it, but connecting throws
/// <see cref="System.NotSupportedException"/>.
/// </remarks>
public sealed class VlessOptions
{
    /// <summary>The VLESS user id — a canonical UUID.</summary>
    public required string Id { get; init; }

    /// <summary>Proxy server host name or IP address.</summary>
    public required string Host { get; init; }

    /// <summary>Proxy server port.</summary>
    public required int Port { get; init; }

    /// <summary>Transport security layer. Defaults to <see cref="VlessSecurity.None"/>.</summary>
    public VlessSecurity Security { get; init; } = VlessSecurity.None;

    /// <summary>
    /// Transport network: <c>tcp</c>/<c>raw</c> (raw TCP), <c>ws</c>/<c>websocket</c>, or
    /// <c>httpupgrade</c>. Others (<c>grpc</c>, <c>xhttp</c>, <c>h2</c>) are unsupported.
    /// </summary>
    public string Transport { get; init; } = "tcp";

    /// <summary>
    /// Request path for the <c>ws</c>/<c>httpupgrade</c> transports (<c>path</c>). Defaults to
    /// <c>/</c>. Sent verbatim, including any query such as <c>?ed=2048</c>.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// <c>Host</c> header for the <c>ws</c>/<c>httpupgrade</c> transports (<c>host</c>).
    /// Falls back to <see cref="Sni"/>, then to <see cref="Host"/>.
    /// </summary>
    public string? HostHeader { get; init; }

    /// <summary>TLS/REALITY server name (SNI). Falls back to <see cref="Host"/> when null.</summary>
    public string? Sni { get; init; }

    /// <summary>ALPN protocol identifiers for the TLS handshake, if specified.</summary>
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>XTLS flow control mode (e.g. <c>xtls-rprx-vision</c>). Empty/null for plain VLESS.</summary>
    public string? Flow { get; init; }

    /// <summary>uTLS / browser fingerprint hint (<c>fp</c>), e.g. <c>chrome</c>. Advisory only.</summary>
    public string? Fingerprint { get; init; }

    /// <summary>REALITY public key (<c>pbk</c>). Set only when <see cref="Security"/> is REALITY.</summary>
    public string? RealityPublicKey { get; init; }

    /// <summary>REALITY short id (<c>sid</c>).</summary>
    public string? RealityShortId { get; init; }

    /// <summary>Human-readable label from the share-link fragment (<c>#name</c>).</summary>
    public string? Remark { get; init; }

    /// <summary>The resolved transport layer this configuration selects.</summary>
    internal TransportKind TransportKind => ProxyTransport.Resolve(Transport);
}
