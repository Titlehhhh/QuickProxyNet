namespace QuickProxyNet;

/// <summary>
/// Strongly-typed configuration for a Shadowsocks outbound, produced by
/// <see cref="ShadowsocksShareLink.Parse(string)"/> or built directly.
/// </summary>
/// <remarks>
/// <para>
/// Only the AEAD ciphers of SIP004/SIP007 are spoken: <c>aes-128-gcm</c>, <c>aes-192-gcm</c>,
/// <c>aes-256-gcm</c> and <c>chacha20-ietf-poly1305</c>. Every other <see cref="Method"/> — the
/// AEAD-2022 (<c>2022-blake3-*</c>) family, the legacy stream ciphers, <c>none</c>/<c>plain</c>,
/// <c>xchacha20-ietf-poly1305</c> — is parsed so callers can inspect it, but constructing a
/// <see cref="ShadowsocksClient"/> from it throws <see cref="System.NotSupportedException"/>
/// naming the cipher.
/// </para>
/// <para>
/// The same holds for <see cref="Plugin"/>: a SIP003 plugin is a separate process this library
/// does not spawn, so any value is rejected by name at construction, never ignored.
/// </para>
/// </remarks>
public sealed class ShadowsocksOptions
{
    /// <summary>
    /// The cipher name (<c>method</c>), e.g. <c>aes-256-gcm</c> or <c>chacha20-ietf-poly1305</c>.
    /// </summary>
    public required string Method { get; init; }

    /// <summary>
    /// The password. The master key is derived from its UTF-8 bytes with OpenSSL's
    /// <c>EVP_BytesToKey</c> (MD5, no salt, one round).
    /// </summary>
    public required string Password { get; init; }

    /// <summary>Proxy server host name or IP address.</summary>
    public required string Host { get; init; }

    /// <summary>Proxy server port. Share links without a port default to <c>8388</c>.</summary>
    public required int Port { get; init; }

    /// <summary>
    /// The SIP003 plugin string from the share link's <c>plugin=</c> parameter
    /// (<c>name;key=value;…</c>), or <see langword="null"/>. Any plugin is unsupported.
    /// </summary>
    public string? Plugin { get; init; }

    /// <summary>Human-readable label from the share-link fragment (<c>#tag</c>).</summary>
    public string? Remark { get; init; }
}
