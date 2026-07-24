using System.Buffers.Binary;

namespace QuickProxyNet;

/// <summary>
/// FNV-1a 32-bit hash. VMess uses it as the inner integrity checksum of the request
/// command section (<c>fnv.New32a</c> in <c>encoding/client.go</c>) and serialises the
/// result <b>big-endian</b>.
/// </summary>
internal static class Fnv1a32
{
    /// <summary>FNV-1a 32-bit offset basis (<c>2166136261</c>).</summary>
    public const uint OffsetBasis = 2166136261u;

    /// <summary>FNV-1a 32-bit prime (<c>16777619</c>).</summary>
    public const uint Prime = 16777619u;

    /// <summary>Computes the FNV-1a-32 hash of <paramref name="data"/> (xor then multiply).</summary>
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint hash = OffsetBasis;
        foreach (byte b in data)
        {
            hash ^= b;
            hash *= Prime;
        }

        return hash;
    }

    /// <summary>
    /// Computes the FNV-1a-32 hash of <paramref name="data"/> and writes it big-endian
    /// (network order, as VMess emits it) into <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than 4 bytes.</exception>
    public static void WriteBigEndian(ReadOnlySpan<byte> data, Span<byte> destination)
        => BinaryPrimitives.WriteUInt32BigEndian(destination, Compute(data));
}
