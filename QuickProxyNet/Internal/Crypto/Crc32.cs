using System.Buffers.Binary;

namespace QuickProxyNet;

/// <summary>
/// CRC-32/IEEE (the zlib / PKZIP CRC, reflected polynomial <c>0xEDB88320</c>, init
/// <c>0xFFFFFFFF</c>, input and output reflected, final XOR <c>0xFFFFFFFF</c>) — the
/// value produced by Go's <c>crc32.ChecksumIEEE</c>. VMess uses it in the AuthID
/// plaintext and serialises the result <b>big-endian</b>.
/// </summary>
internal static class Crc32
{
    private const uint ReflectedPolynomial = 0xEDB88320u;

    // 256-entry lookup table, computed once at first use.
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ (ReflectedPolynomial & (uint)(-(int)(crc & 1)));

            table[i] = crc;
        }

        return table;
    }

    /// <summary>Computes the CRC-32/IEEE checksum of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
            crc = (crc >> 8) ^ Table[(crc ^ b) & 0xFF];

        return crc ^ 0xFFFFFFFFu;
    }

    /// <summary>
    /// Computes the CRC-32/IEEE checksum of <paramref name="data"/> and writes it
    /// big-endian (as VMess emits it) into <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than 4 bytes.</exception>
    public static void WriteBigEndian(ReadOnlySpan<byte> data, Span<byte> destination)
        => BinaryPrimitives.WriteUInt32BigEndian(destination, Compute(data));
}
