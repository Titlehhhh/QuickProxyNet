using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Body cipher requested for a VMess outbound — the share-link <c>scy</c>/<c>security</c>
/// field.
/// </summary>
/// <remarks>
/// Only the two AEAD ciphers of modern VMessAEAD are offered. The legacy values
/// (<c>aes-128-cfb</c>), the unauthenticated ones (<c>none</c>, <c>zero</c>) and the
/// on-wire placeholder <c>auto</c> never reach the wire: <see cref="Auto"/> is resolved to
/// a concrete cipher before the request header is serialized, exactly as v2ray does.
/// </remarks>
public enum VmessSecurityKind
{
    /// <summary>
    /// Let the client pick (<c>auto</c>). Resolved to <see cref="Aes128Gcm"/> on CPUs with
    /// an AES instruction set and to <see cref="ChaCha20Poly1305"/> otherwise.
    /// </summary>
    Auto,

    /// <summary>AES-128-GCM (<c>aes-128-gcm</c>, security type 3).</summary>
    Aes128Gcm,

    /// <summary>ChaCha20-Poly1305 (<c>chacha20-poly1305</c>, security type 4).</summary>
    ChaCha20Poly1305
}

/// <summary>
/// Strongly-typed configuration for a VMess outbound, produced by
/// <see cref="VmessShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// <para>
/// This is a <b>VMessAEAD-only</b> configuration: <see cref="AlterId"/> must be <c>0</c>.
/// A non-zero alterId selects the legacy MD5-authenticated header format, which is
/// deliberately not implemented, so it is rejected rather than silently downgraded.
/// </para>
/// <para>
/// The <c>tcp</c>/<c>raw</c>, <c>ws</c> and <c>httpupgrade</c> transports are supported at
/// connect time, with or without TLS. Others (<c>grpc</c>, <c>h2</c>, …) are parsed so
/// callers can inspect them, but connecting with them throws
/// <see cref="System.NotSupportedException"/>.
/// </para>
/// </remarks>
public sealed class VmessOptions
{
    /// <summary>The VMess user id — a canonical UUID.</summary>
    public required string Id { get; init; }

    /// <summary>Proxy server host name or IP address (the share-link <c>add</c> field).</summary>
    public required string Host { get; init; }

    /// <summary>Proxy server port.</summary>
    public required int Port { get; init; }

    /// <summary>
    /// Body cipher. Defaults to <see cref="VmessSecurityKind.Auto"/>, which resolves to a
    /// concrete AEAD at connect time.
    /// </summary>
    public VmessSecurityKind Security { get; init; } = VmessSecurityKind.Auto;

    /// <summary>
    /// Legacy alterId. Must be <c>0</c>: this implementation speaks VMessAEAD only, and a
    /// non-zero value means the legacy MD5-authenticated format.
    /// </summary>
    public int AlterId { get; init; }

    /// <summary>
    /// Transport network (the share-link <c>net</c> field): <c>tcp</c>/<c>raw</c> (raw TCP),
    /// <c>ws</c>/<c>websocket</c>, or <c>httpupgrade</c>. Others are unsupported.
    /// </summary>
    public string Transport { get; init; } = "tcp";

    /// <summary>
    /// Request path for the <c>ws</c>/<c>httpupgrade</c> transports (the share-link
    /// <c>path</c> field). Defaults to <c>/</c>. Sent verbatim, including any query.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// <c>Host</c> header for the <c>ws</c>/<c>httpupgrade</c> transports (the share-link
    /// <c>host</c> field). Falls back to <see cref="Sni"/>, then to <see cref="Host"/>.
    /// </summary>
    public string? HostHeader { get; init; }

    /// <summary>
    /// When true the VMess session runs inside TLS (the share-link <c>tls</c> field).
    /// </summary>
    public bool UseTls { get; init; }

    /// <summary>TLS server name (SNI). Falls back to <see cref="Host"/> when null.</summary>
    public string? Sni { get; init; }

    /// <summary>ALPN protocol identifiers for the TLS handshake, if specified.</summary>
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>
    /// When true, the proxy server's TLS certificate is accepted unconditionally
    /// (<c>allowInsecure</c>). Use only against known servers with self-signed certs.
    /// </summary>
    public bool AllowInsecure { get; init; }

    /// <summary>Human-readable label from the share-link <c>ps</c> field.</summary>
    public string? Remark { get; init; }

    /// <summary>The resolved transport layer this configuration selects.</summary>
    internal TransportKind TransportKind => ProxyTransport.Resolve(Transport);

    /// <summary>
    /// Maps <see cref="Security"/> onto the concrete body cipher written into the request
    /// header's security nibble, resolving <see cref="VmessSecurityKind.Auto"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The platform provides neither AES-GCM nor ChaCha20-Poly1305.
    /// </exception>
    internal VmessSecurity ResolveSecurity() => Security switch
    {
        VmessSecurityKind.Aes128Gcm => VmessSecurity.Aes128Gcm,
        VmessSecurityKind.ChaCha20Poly1305 => VmessSecurity.ChaCha20Poly1305,
        _ => ResolveAuto()
    };

    /// <summary>
    /// Resolves <c>auto</c> the way v2ray does: AES-128-GCM when the CPU can do AES in
    /// hardware, ChaCha20-Poly1305 otherwise (it is the faster software cipher).
    /// </summary>
    /// <remarks>
    /// Both ciphers are equally interoperable — the server simply follows the security
    /// nibble — so this is purely a local performance choice. AES-GCM is still preferred
    /// over an unavailable ChaCha20-Poly1305, because
    /// <see cref="System.Security.Cryptography.ChaCha20Poly1305.IsSupported"/> is false on
    /// some platforms.
    /// </remarks>
    private static VmessSecurity ResolveAuto()
    {
        if (AesGcm.IsSupported && HasHardwareAes)
            return VmessSecurity.Aes128Gcm;

        if (ChaCha20Poly1305.IsSupported)
            return VmessSecurity.ChaCha20Poly1305;

        if (AesGcm.IsSupported)
            return VmessSecurity.Aes128Gcm;

        throw new NotSupportedException(
            "VMess requires AES-128-GCM or ChaCha20-Poly1305, and this platform provides neither.");
    }

    private static bool HasHardwareAes =>
        System.Runtime.Intrinsics.X86.Aes.IsSupported ||
        System.Runtime.Intrinsics.Arm.Aes.IsSupported;
}
