namespace QuickProxyNet;

/// <summary>
/// Encodes a canonical UUID string into its 16-byte RFC 4122 (network / big-endian)
/// representation, as required by the VLESS and VMess wire formats.
/// </summary>
/// <remarks>
/// The legacy <see cref="System.Guid.ToByteArray()"/> overload emits the first three
/// fields in little-endian on all platforms, which is the wrong order for these
/// protocols. This codec always produces big-endian bytes and allocates nothing.
/// </remarks>
internal static class UuidCodec
{
    public const int Size = 16;

    /// <summary>
    /// Writes the 16 big-endian bytes of <paramref name="id"/> into <paramref name="dest"/>.
    /// </summary>
    /// <exception cref="FormatException"><paramref name="id"/> is not a valid UUID.</exception>
    public static void WriteBigEndian(ReadOnlySpan<char> id, Span<byte> dest)
    {
        if (!TryWriteBigEndian(id, dest))
            throw new FormatException(
                $"VLESS/VMess user id must be a canonical UUID; got '{id.ToString()}'.");
    }

    /// <summary>
    /// Attempts to write the 16 big-endian bytes of <paramref name="id"/> into
    /// <paramref name="dest"/>. Returns <see langword="false"/> without throwing if the
    /// id is not a valid UUID or the destination is too small.
    /// </summary>
    public static bool TryWriteBigEndian(ReadOnlySpan<char> id, Span<byte> dest)
    {
        if (dest.Length < Size)
            return false;

        // Guid is a struct — TryParse + big-endian TryWriteBytes is fully zero-allocation.
        // bigEndian:true (net8+) yields RFC 4122 order == the canonical string byte order.
        if (!Guid.TryParse(id, out var guid))
            return false;

        return guid.TryWriteBytes(dest, bigEndian: true, out _);
    }
}
