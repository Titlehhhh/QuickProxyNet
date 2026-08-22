using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// Encodes a VLESS/VMess user id into its 16-byte RFC 4122 (network / big-endian)
/// representation, mirroring Xray's <c>common/uuid.ParseString</c> byte for byte.
/// </summary>
/// <remarks>
/// <para>
/// The legacy <see cref="System.Guid.ToByteArray()"/> overload emits the first three
/// fields in little-endian on all platforms, which is the wrong order for these
/// protocols. This codec always produces big-endian bytes and allocates nothing.
/// </para>
/// <para>
/// An id is <b>not</b> required to be a UUID. Xray maps any id of length 1..30 to
/// <c>UUIDv5(nil-namespace, utf8(id))</c> — that is, <c>SHA1(16 zero bytes || id)</c>
/// truncated to 16 bytes with the version nibble set to 5 and the RFC 4122 variant bits
/// set — and both endpoints derive the same value, so such ids work end to end. Rejecting
/// them would break configurations that Xray and sing-box accept; about 0.3% of
/// real-world VLESS links use one. Lengths 32..36 are parsed as canonical hex; length 0,
/// length 31 and lengths above 36 are errors, exactly as upstream.
/// </para>
/// </remarks>
internal static class UuidCodec
{
    public const int Size = 16;

    /// <summary>Longest id Xray will derive a UUID from.</summary>
    private const int MaxDerivedLength = 30;

    /// <summary>Shortest and longest id Xray parses as canonical hex.</summary>
    private const int MinCanonicalLength = 32;
    private const int MaxCanonicalLength = 36;

    /// <summary>
    /// Writes the 16 big-endian bytes of <paramref name="id"/> into <paramref name="dest"/>.
    /// </summary>
    /// <exception cref="FormatException"><paramref name="id"/> is not a usable user id.</exception>
    public static void WriteBigEndian(ReadOnlySpan<char> id, Span<byte> dest)
    {
        if (!TryWriteBigEndian(id, dest))
            throw new FormatException(
                $"VLESS/VMess user id '{id.ToString()}' is neither a canonical UUID nor a " +
                "string of 1..30 characters (which would be mapped to a UUID).");
    }

    /// <summary>
    /// Attempts to write the 16 big-endian bytes of <paramref name="id"/> into
    /// <paramref name="dest"/>. Returns <see langword="false"/> without throwing if the
    /// id is unusable or the destination is too small.
    /// </summary>
    public static bool TryWriteBigEndian(ReadOnlySpan<char> id, Span<byte> dest)
    {
        if (dest.Length < Size)
            return false;

        // Length decides the branch, and the two ranges cannot overlap: no canonical Guid
        // format is 30 characters or shorter ("N" is 32, "D" 36, "B"/"P" 38).
        if (id.Length >= MinCanonicalLength && id.Length <= MaxCanonicalLength)
        {
            // Guid is a struct — TryParse + big-endian TryWriteBytes is fully zero-allocation.
            // bigEndian:true (net8+) yields RFC 4122 order == the canonical string byte order.
            return Guid.TryParse(id, out var guid) &&
                   guid.TryWriteBytes(dest, bigEndian: true, out _);
        }

        if (id.Length is > 0 and <= MaxDerivedLength)
            return TryDerive(id, dest);

        return false;
    }

    /// <summary>
    /// Derives a UUID from a non-UUID id the way Xray does:
    /// <c>u = SHA1(nil-namespace || utf8(id))[0..16]</c>, then version 5 and the RFC 4122
    /// variant are stamped into <c>u[6]</c> and <c>u[8]</c>.
    /// </summary>
    private static bool TryDerive(ReadOnlySpan<char> id, Span<byte> dest)
    {
        // At most 30 chars; 4 bytes each is the worst case UTF-8 can produce.
        Span<byte> input = stackalloc byte[Size + MaxDerivedLength * 4];
        input[..Size].Clear(); // the nil namespace: 16 zero bytes

        if (!Encoding.UTF8.TryGetBytes(id, input[Size..], out int nameLength))
            return false;

        Span<byte> hash = stackalloc byte[20]; // SHA-1 digest
        if (!SHA1.TryHashData(input[..(Size + nameLength)], hash, out _))
            return false;

        hash[..Size].CopyTo(dest);
        dest[6] = (byte)((dest[6] & 0x0F) | 0x50); // version 5
        dest[8] = (byte)((dest[8] & 0x3F) | 0x80); // RFC 4122 variant
        return true;
    }
}
