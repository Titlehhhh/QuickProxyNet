using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Builds the VMessAEAD <c>AuthID</c> (the 16-byte "EAuID" that opens every request),
/// per <c>proxy/vmess/aead/authid.go</c>.
/// </summary>
/// <remarks>
/// Plaintext layout (16 bytes):
/// <code>
/// [0..8)   Unix timestamp, seconds, int64 big-endian
/// [8..12)  4 random bytes
/// [12..16) CRC-32/IEEE of bytes [0..12), uint32 big-endian
/// </code>
/// The plaintext is then encrypted as a <b>single raw AES-128 block</b> (ECB, no
/// padding, no IV) under <c>KDF16(cmdKey, "AES Auth ID Encryption")</c>. This is a
/// block-cipher permutation, not an AEAD — <see cref="AesGcm"/> must not be used here.
/// </remarks>
internal static class VmessAuthId
{
    /// <summary>Length of an AuthID (and of its plaintext) in bytes.</summary>
    public const int Size = 16;

    /// <summary>Number of random bytes embedded in the AuthID plaintext.</summary>
    public const int RandomSize = 4;

    // Offsets inside the 16-byte plaintext.
    private const int TimestampOffset = 0;
    private const int RandomOffset = 8;
    private const int ChecksumOffset = 12;

    private static ReadOnlySpan<byte> EncryptionKeyLabel => "AES Auth ID Encryption"u8;

    /// <summary>
    /// Writes the 16-byte AuthID <b>plaintext</b> (pre-encryption) into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="unixSeconds">Timestamp in whole Unix seconds (int64, big-endian).</param>
    /// <param name="random4">Exactly <see cref="RandomSize"/> random bytes.</param>
    /// <param name="destination">Receives the 16-byte plaintext.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="random4"/> is not 4 bytes, or <paramref name="destination"/> is
    /// shorter than 16 bytes.
    /// </exception>
    public static void WritePlaintext(long unixSeconds, ReadOnlySpan<byte> random4, Span<byte> destination)
    {
        if (random4.Length != RandomSize)
            throw new ArgumentException($"Random must be exactly {RandomSize} bytes.", nameof(random4));
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));

        Span<byte> plaintext = destination[..Size];
        BinaryPrimitives.WriteInt64BigEndian(plaintext[TimestampOffset..], unixSeconds);
        random4.CopyTo(plaintext[RandomOffset..]);

        // CRC covers timestamp ‖ random (the first 12 bytes) and is stored big-endian.
        Crc32.WriteBigEndian(plaintext[..ChecksumOffset], plaintext[ChecksumOffset..]);
    }

    /// <summary>
    /// Creates an AuthID from explicit time and randomness — the deterministic form used
    /// by tests and by <see cref="VmessRequest"/>.
    /// </summary>
    /// <param name="cmdKey">The 16-byte cmdKey (<see cref="VmessCmdKey"/>).</param>
    /// <param name="unixSeconds">Timestamp in whole Unix seconds.</param>
    /// <param name="random4">Exactly <see cref="RandomSize"/> random bytes.</param>
    /// <param name="destination">Receives the encrypted 16-byte AuthID.</param>
    /// <exception cref="ArgumentException">An input or the destination has the wrong size.</exception>
    public static void Create(
        ReadOnlySpan<byte> cmdKey, long unixSeconds, ReadOnlySpan<byte> random4, Span<byte> destination)
    {
        if (cmdKey.Length != VmessCmdKey.Size)
            throw new ArgumentException($"cmdKey must be exactly {VmessCmdKey.Size} bytes.", nameof(cmdKey));
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));

        Span<byte> plaintext = stackalloc byte[Size];

        // Aes.Key only accepts an array on net8.0 (SetKey(ReadOnlySpan<byte>) is newer),
        // so the derived key is materialised once per handshake and zeroed afterwards.
        byte[] key = new byte[16];
        try
        {
            WritePlaintext(unixSeconds, random4, plaintext);
            VmessKdf.Kdf16(cmdKey, EncryptionKeyLabel, key);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.EncryptEcb(plaintext, destination[..Size], PaddingMode.None);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Creates an AuthID for "now", drawing the timestamp from
    /// <see cref="DateTimeOffset.UtcNow"/> and the 4 random bytes from
    /// <see cref="RandomNumberGenerator"/>.
    /// </summary>
    /// <remarks>
    /// VMessAEAD uses the exact current second with <b>no</b> jitter (the ±30 s window
    /// belongs to legacy, non-AEAD VMess). Servers accept a ±120 s clock skew.
    /// </remarks>
    /// <param name="cmdKey">The 16-byte cmdKey.</param>
    /// <param name="destination">Receives the encrypted 16-byte AuthID.</param>
    public static void Create(ReadOnlySpan<byte> cmdKey, Span<byte> destination)
    {
        Span<byte> random = stackalloc byte[RandomSize];
        RandomNumberGenerator.Fill(random);
        Create(cmdKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), random, destination);
    }
}
