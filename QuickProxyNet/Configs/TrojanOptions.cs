namespace QuickProxyNet;

/// <summary>
/// Strongly-typed configuration for a Trojan outbound, produced by
/// <see cref="TrojanShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// Trojan is TLS-mandatory: the request header is written inside the TLS session. Only
/// <c>tcp</c>/<c>raw</c> transport is supported at connect time in this release; other
/// transports (<c>ws</c>, <c>grpc</c>, …) are parsed so callers can inspect them, but
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

    /// <summary>Transport network: <c>tcp</c> or <c>raw</c> (both raw TCP). Others are unsupported.</summary>
    public string Transport { get; init; } = "tcp";

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

    /// <summary>True when the transport is plain TCP (<c>tcp</c> or <c>raw</c>).</summary>
    internal bool IsRawTcp =>
        Transport.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
        Transport.Equals("raw", StringComparison.OrdinalIgnoreCase);
}
