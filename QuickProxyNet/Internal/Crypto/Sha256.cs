using System.Runtime.Intrinsics;

namespace QuickProxyNet;

/// <summary>
/// Self-contained SHA-256 (FIPS 180-4) over a single contiguous input, sharing
/// <see cref="Sha256Core"/> with <see cref="Sha224"/>.
/// </summary>
/// <remarks>
/// This is <b>not</b> a replacement for <see cref="System.Security.Cryptography.SHA256"/>:
/// for a plain hash the BCL delegates to the OS, which is roughly 1.6x faster per block. It
/// exists so the shared core can be cross-checked against an independent implementation —
/// the BCL has no SHA-224, so <see cref="Sha224"/> alone cannot be diffed against anything
/// the runtime ships.
/// </remarks>
internal static class Sha256
{
    /// <summary>Digest size in bytes (256 bits).</summary>
    public const int HashSize = Sha256Core.DigestSize;

    /// <summary>
    /// Computes SHA256(<paramref name="data"/>) and writes the 32-byte digest into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 32 bytes.
    /// </exception>
    public static void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, Vector128.IsHardwareAccelerated);

    /// <summary>
    /// Scalar-only variant of <see cref="ComputeHash"/>, so tests can exercise the fallback
    /// schedule on hardware where the vector path would normally be selected.
    /// </summary>
    internal static void ComputeHashScalar(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, vectorize: false);

    private static void ComputeHashCore(ReadOnlySpan<byte> data, Span<byte> destination, bool vectorize)
    {
        if (destination.Length < HashSize)
            throw new ArgumentException(
                $"Destination must be at least {HashSize} bytes.", nameof(destination));

        Sha256Core.ComputeHash(Sha256Core.Sha256Iv, data, destination, HashSize, vectorize);
    }
}
