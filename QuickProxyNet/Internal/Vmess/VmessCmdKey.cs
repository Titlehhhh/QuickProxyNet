using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Derives the VMess <c>cmdKey</c> — the 16-byte master key that every VMessAEAD key
/// derivation is rooted in (<c>common/protocol/id.go</c>):
/// <code>
/// cmdKey = MD5( uuid16 ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21" )
/// </code>
/// </summary>
/// <remarks>
/// The user id contributes its 16 <b>RFC 4122 big-endian</b> bytes (via
/// <see cref="UuidCodec"/>, not <see cref="System.Guid.ToByteArray()"/>), and the magic
/// suffix is appended as 36 literal ASCII bytes — it is a constant string, never parsed
/// as a UUID. The MD5 input is therefore always exactly 52 bytes.
/// </remarks>
internal static class VmessCmdKey
{
    /// <summary>Length of a cmdKey in bytes.</summary>
    public const int Size = 16;

    /// <summary>Total MD5 input length: 16 uuid bytes + 36 ASCII magic bytes.</summary>
    private const int HashInputSize = UuidCodec.Size + 36;

    // Verbatim from common/protocol/id.go — hashed as ASCII, not as a UUID.
    private static ReadOnlySpan<byte> Magic => "c48619fe-8f02-49e0-b9e9-edf763e17e21"u8;

    /// <summary>
    /// Derives the cmdKey for <paramref name="uuid"/> into <paramref name="destination"/>.
    /// </summary>
    /// <param name="uuid">The canonical VMess user id.</param>
    /// <param name="destination">Receives the 16-byte cmdKey.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 16 bytes.
    /// </exception>
    /// <exception cref="FormatException"><paramref name="uuid"/> is not a canonical UUID.</exception>
    public static void Derive(ReadOnlySpan<char> uuid, Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));

        Span<byte> input = stackalloc byte[HashInputSize];
        try
        {
            UuidCodec.WriteBigEndian(uuid, input[..UuidCodec.Size]);
            Magic.CopyTo(input[UuidCodec.Size..]);
            MD5.HashData(input, destination[..Size]);
        }
        finally
        {
            // The buffer holds the raw user id (the VMess credential).
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
