using System.Runtime.Intrinsics;

namespace QuickProxyNet;

/// <summary>
/// Self-contained SHA-224 (FIPS 180-4) over a single contiguous input. The BCL has no
/// SHA-224, but the Trojan protocol authenticates with <c>hex(SHA224(password))</c>.
/// SHA-224 is SHA-256 with different initial hash values and the digest truncated to
/// the first 28 bytes, so everything but the IV and the output length comes from
/// <see cref="Sha256Core"/>. Allocation-free: state, schedule and padding are stack-allocated.
/// </summary>
internal static class Sha224
{
    /// <summary>Digest size in bytes (224 bits).</summary>
    public const int HashSize = 28;

    /// <summary>Digest size in lowercase-hex ASCII bytes.</summary>
    public const int HexSize = HashSize * 2;

    /// <summary>
    /// Computes SHA224(<paramref name="data"/>) and writes the 28-byte digest into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 28 bytes.
    /// </exception>
    public static void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, Vector128.IsHardwareAccelerated);

    /// <summary>
    /// Scalar-only variant of <see cref="ComputeHash"/>. Exists so tests can verify the
    /// fallback path on hardware where the vector path would normally be selected, and
    /// so benchmarks can compare the two.
    /// </summary>
    internal static void ComputeHashScalar(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, vectorize: false);

    /// <summary>
    /// Computes SHA224(<paramref name="data"/>) and writes the digest as exactly 56
    /// lowercase-hex ASCII bytes into <paramref name="destinationAscii"/>. Used by the
    /// Trojan request builder to emit the auth prefix directly into a wire buffer.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destinationAscii"/> is shorter than 56 bytes.
    /// </exception>
    public static void WriteHexLower(ReadOnlySpan<byte> data, Span<byte> destinationAscii)
    {
        if (destinationAscii.Length < HexSize)
            throw new ArgumentException(
                $"Destination must be at least {HexSize} bytes.", nameof(destinationAscii));

        Span<byte> digest = stackalloc byte[HashSize];
        ComputeHash(data, digest);

        for (int i = 0; i < HashSize; i++)
        {
            destinationAscii[2 * i] = HexDigit(digest[i] >> 4);
            destinationAscii[2 * i + 1] = HexDigit(digest[i] & 0xF);
        }
    }

    private static byte HexDigit(int nibble)
        => (byte)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));

    private static void ComputeHashCore(ReadOnlySpan<byte> data, Span<byte> destination, bool vectorize)
    {
        if (destination.Length < HashSize)
            throw new ArgumentException(
                $"Destination must be at least {HashSize} bytes.", nameof(destination));

        Sha256Core.ComputeHash(Sha256Core.Sha224Iv, data, destination, HashSize, vectorize);
    }
}
