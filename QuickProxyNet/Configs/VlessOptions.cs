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
    /// REALITY transport security (<c>security=reality</c>). Parsed for completeness but
    /// not yet supported at connect time — it requires a browser-like uTLS ClientHello
    /// fingerprint that <see cref="System.Net.Security.SslStream"/> cannot produce.
    /// </summary>
    Reality
}

/// <summary>
/// Strongly-typed configuration for a VLESS outbound, produced by
/// <see cref="VlessShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// Only <c>tcp</c>/<c>raw</c> transport with <see cref="VlessSecurity.None"/> or
/// <see cref="VlessSecurity.Tls"/> is supported at connect time in this release. Other
/// fields (REALITY keys, non-empty <see cref="Flow"/>, alternate transports) are parsed
/// so callers can inspect them, but connecting with them throws
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

    /// <summary>Transport network: <c>tcp</c> or <c>raw</c> (both raw TCP). Others are unsupported.</summary>
    public string Transport { get; init; } = "tcp";

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

    /// <summary>True when the transport is plain TCP (<c>tcp</c> or <c>raw</c>).</summary>
    internal bool IsRawTcp =>
        Transport.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
        Transport.Equals("raw", StringComparison.OrdinalIgnoreCase);
}
