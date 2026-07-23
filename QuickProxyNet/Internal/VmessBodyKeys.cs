using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Pure body key-derivation helpers for VMessAEAD (<c>alterId = 0</c>):
/// the ChaCha20-Poly1305 MD5 key expansion and the SHA-256-based response
/// key/IV derivation (<c>proxy/vmess/encoding</c>).
/// </summary>
internal static class VmessBodyKeys
{
    /// <summary>Length of the expanded ChaCha20 key in bytes.</summary>
    public const int ChaCha20KeySize = 32;

    /// <summary>Length of a derived response key or IV in bytes.</summary>
    public const int ResponseKeySize = 16;

    /// <summary>
    /// Expands a 16-byte body key into the 32-byte ChaCha20-Poly1305 key used by VMess
    /// (<c>GenerateChacha20Poly1305Key</c>): <c>key[0:16] = MD5(bodyKey)</c>,
    /// <c>key[16:32] = MD5(key[0:16])</c>.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 32 bytes.
    /// </exception>
    public static void ExpandChaCha20Key(ReadOnlySpan<byte> bodyKey, Span<byte> destination)
    {
        if (destination.Length < ChaCha20KeySize)
            throw new ArgumentException(
                $"Destination must be at least {ChaCha20KeySize} bytes.", nameof(destination));

        MD5.HashData(bodyKey, destination[..16]);
        MD5.HashData(destination[..16], destination.Slice(16, 16));
    }

    /// <summary>
    /// Derives a 16-byte VMessAEAD response body key or IV from the corresponding
    /// request value: <c>SHA256(source)[0:16]</c>.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 16 bytes.
    /// </exception>
    public static void DeriveResponseKeyOrIv(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (destination.Length < ResponseKeySize)
            throw new ArgumentException(
                $"Destination must be at least {ResponseKeySize} bytes.", nameof(destination));

        Span<byte> full = stackalloc byte[32];
        SHA256.HashData(source, full);
        full[..ResponseKeySize].CopyTo(destination);
    }
}
