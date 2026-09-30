using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The REALITY authentication primitives: deriving the auth key, sealing it into the TLS
/// <c>session_id</c>, and recognising the server's answer.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole of REALITY's own cryptography, and it is small. Everything else REALITY
/// needs is ordinary TLS 1.3 — which is where the actual difficulty lives, not here.
/// </para>
/// <para>
/// The construction, as implemented by <c>XTLS/REALITY</c> and <c>Xray-core</c>:
/// </para>
/// <list type="number">
///   <item><description>
///     <c>authKey = X25519(clientKeySharePrivate, serverPublicKey)</c> — the private half is the
///     <b>same ephemeral key the ClientHello offers in <c>key_share</c></b>, not a separate one.
///     The server recovers it from <c>clientHello.keyShares</c>, which is why no extra field has
///     to be smuggled anywhere.
///   </description></item>
///   <item><description>
///     <c>authKey = HKDF-SHA256(ikm: authKey, salt: clientRandom[0..20], info: "REALITY")</c>, 32 bytes.
///   </description></item>
///   <item><description>
///     <c>session_id = AES-256-GCM(key: authKey, nonce: clientRandom[20..32], plaintext: 16-byte
///     header, aad: the raw ClientHello with session_id zeroed)</c> — 16 bytes of ciphertext plus
///     a 16-byte tag exactly fill the 32-byte field.
///   </description></item>
/// </list>
/// <para>
/// The AAD binding is what stops the sealed <c>session_id</c> from being replayed into a
/// different ClientHello: any edit to the hello invalidates the tag, so a censor cannot lift the
/// blob out of a recorded handshake and reuse it.
/// </para>
/// </remarks>
internal static class RealityAuth
{
    /// <summary>Size of the TLS <c>session_id</c> REALITY requires; the ciphertext exactly fills it.</summary>
    public const int SessionIdSize = 32;

    /// <summary>Size of the derived auth key. 32 bytes, so the AEAD is AES-256-GCM.</summary>
    public const int AuthKeySize = 32;

    /// <summary>Size of the short id, zero-padded from the hex in the share link's <c>sid</c>.</summary>
    public const int ShortIdSize = 8;

    /// <summary>
    /// Offset of <c>session_id</c> inside a raw ClientHello handshake message.
    /// </summary>
    /// <remarks>
    /// 4 bytes of handshake header, 2 of legacy_version, 32 of random, 1 length byte. Fixed only
    /// because the length byte must read 32 — REALITY requires a full-length session id, which
    /// every TLS 1.3 client sends anyway for middlebox compatibility.
    /// </remarks>
    public const int SessionIdOffset = 39;

    private static ReadOnlySpan<byte> HkdfInfo => "REALITY"u8;

    /// <summary>
    /// Derives the auth key from our ephemeral private key and the server's REALITY public key.
    /// </summary>
    /// <param name="authKey">Receives 32 bytes.</param>
    /// <param name="clientPrivateKey">Our <c>key_share</c> private scalar.</param>
    /// <param name="serverPublicKey">The server's public key — <c>pbk</c> in the share link.</param>
    /// <param name="clientRandom">The ClientHello's 32-byte random.</param>
    public static void DeriveAuthKey(
        Span<byte> authKey,
        ReadOnlySpan<byte> clientPrivateKey,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> clientRandom)
    {
        if (authKey.Length != AuthKeySize)
            throw new ArgumentException($"The auth key is {AuthKeySize} bytes.", nameof(authKey));
        if (clientRandom.Length != 32)
            throw new ArgumentException("The client random is 32 bytes.", nameof(clientRandom));

        Span<byte> shared = stackalloc byte[X25519.KeySize];
        Span<byte> prk = stackalloc byte[AuthKeySize];
        Span<byte> info = stackalloc byte[HkdfInfo.Length + 1];
        try
        {
            X25519.Agree(shared, clientPrivateKey, serverPublicKey);

            // HKDF-SHA256 with a 32-byte output is Extract, then the single Expand block
            // HMAC(prk, info || 0x01). Spelled out because HKDF.DeriveKey allocates about 300
            // bytes a call on net9 and net10. Not derived in place: the shared secret, the PRK and
            // the auth key are all 32 bytes, and aliasing any two would corrupt silently.
            HKDF.Extract(HashAlgorithmName.SHA256, shared, clientRandom[..20], prk);
            HkdfInfo.CopyTo(info);
            info[^1] = 0x01;
            HMACSHA256.HashData(prk, info, authKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    /// <summary>
    /// Writes the sealed authentication blob into the <c>session_id</c> of a raw ClientHello.
    /// </summary>
    /// <param name="clientHello">
    /// The complete handshake message, starting at the handshake type byte. Modified in place:
    /// bytes 39..71 are replaced with the ciphertext and tag.
    /// </param>
    /// <param name="authKey">The key from <see cref="DeriveAuthKey"/>.</param>
    /// <param name="shortId">The short id, 8 bytes.</param>
    /// <param name="unixTime">Client timestamp; the server may reject a large skew.</param>
    /// <param name="clientVersion">Three version bytes the server can gate on.</param>
    public static void SealSessionId(
        Span<byte> clientHello,
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> shortId,
        uint unixTime,
        ReadOnlySpan<byte> clientVersion)
    {
        if (clientHello.Length < SessionIdOffset + SessionIdSize)
            throw new ArgumentException("The ClientHello is too short to contain a session id.", nameof(clientHello));
        if (clientHello[SessionIdOffset - 1] != SessionIdSize)
            throw new ArgumentException(
                $"REALITY requires a {SessionIdSize}-byte session id; this ClientHello declares " +
                $"{clientHello[SessionIdOffset - 1]}.", nameof(clientHello));
        if (shortId.Length != ShortIdSize)
            throw new ArgumentException($"The short id is {ShortIdSize} bytes.", nameof(shortId));
        if (clientVersion.Length != 3)
            throw new ArgumentException("The client version is 3 bytes.", nameof(clientVersion));

        Span<byte> sessionId = clientHello.Slice(SessionIdOffset, SessionIdSize);
        ReadOnlySpan<byte> clientRandom = clientHello.Slice(6, 32);

        Span<byte> plaintext = stackalloc byte[16];
        clientVersion.CopyTo(plaintext);
        plaintext[3] = 0; // reserved
        BinaryPrimitives.WriteUInt32BigEndian(plaintext[4..], unixTime);
        shortId.CopyTo(plaintext[8..]);

        // The AAD is the hello with the session id zeroed — the state the server reconstructs
        // before it can verify the tag.
        sessionId.Clear();

        Span<byte> nonce = stackalloc byte[12];
        clientRandom[20..].CopyTo(nonce);

        // Written to a separate buffer and copied back, rather than encrypted in place. The
        // destination is a slice of the same array that is passed as additional data, and
        // AesGcm does not document what it does when output and AAD overlap — it happens to
        // work on the platforms tested only because GHASH consumes the AAD before any
        // ciphertext is produced. Depending on that is not worth 32 bytes of stack.
        Span<byte> sealedBlob = stackalloc byte[SessionIdSize];

        try
        {
            using var aes = new AesGcm(authKey, tagSizeInBytes: 16);
            aes.Encrypt(nonce, plaintext, sealedBlob[..16], sealedBlob[16..], clientHello);
            sealedBlob.CopyTo(sessionId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decides whether a server certificate came from the REALITY server or from the real site
    /// whose handshake it relays.
    /// </summary>
    /// <param name="authKey">The key from <see cref="DeriveAuthKey"/>.</param>
    /// <param name="ed25519PublicKey">The leaf certificate's Ed25519 public key, raw 32 bytes.</param>
    /// <param name="certificateSignature">The leaf certificate's signature field.</param>
    /// <returns>
    /// True when the signature is <c>HMAC-SHA512(authKey, publicKey)</c> — proof the peer knows
    /// the shared secret, which only the real REALITY server does.
    /// </returns>
    /// <remarks>
    /// A false result is not an error: it is the normal outcome when the handshake was relayed
    /// through to the decoy site, and the caller must then fall back to ordinary X.509 validation
    /// rather than treating the connection as a tunnel. Getting that branch wrong in the other
    /// direction — tunnelling anyway — would send the VLESS id to whatever server answered.
    /// </remarks>
    public static bool VerifyCertificate(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> ed25519PublicKey,
        ReadOnlySpan<byte> certificateSignature)
    {
        if (certificateSignature.Length != HMACSHA512.HashSizeInBytes)
            return false;

        Span<byte> expected = stackalloc byte[HMACSHA512.HashSizeInBytes];
        HMACSHA512.HashData(authKey, ed25519PublicKey, expected);

        return CryptographicOperations.FixedTimeEquals(expected, certificateSignature);
    }

    /// <summary>
    /// Decodes a share link's <c>pbk</c>: base64url, usually unpadded, of the server's X25519 key.
    /// </summary>
    /// <param name="value">The <c>pbk</c> text.</param>
    /// <param name="key">The 32-byte key, when this returns true.</param>
    /// <param name="error">What is wrong with the value, naming it, when this returns false.</param>
    public static bool TryDecodePublicKey(
        string value, [NotNullWhen(true)] out byte[]? key, [NotNullWhen(false)] out string? error)
    {
        key = null;
        char[] chars = new char[value.Length + 3];
        byte[] decoded = new byte[(value.Length + 3) / 4 * 3];

        if (!ShareLinkBase64.TryNormalize(value, chars, out int length) ||
            !Convert.TryFromBase64Chars(chars.AsSpan(0, length), decoded, out int written))
        {
            error = $"The REALITY public key '{value}' is not valid base64url (expected the 'pbk' value from the share link).";
            return false;
        }

        if (written != X25519.KeySize)
        {
            error = $"The REALITY public key '{value}' decodes to {written} bytes; an X25519 key is {X25519.KeySize}.";
            return false;
        }

        key = decoded[..X25519.KeySize];
        error = null;
        return true;
    }

    /// <summary>
    /// Parses the share link's <c>sid</c> — an even-length hex string — into a zero-padded short id.
    /// </summary>
    /// <param name="shortId">Receives 8 bytes, all zero when this returns false.</param>
    /// <param name="hex">The hex text; may be empty, which is a valid configuration.</param>
    /// <param name="error">What is wrong with the text, naming it, when this returns false.</param>
    public static bool TryParseShortId(Span<byte> shortId, string? hex, [NotNullWhen(false)] out string? error)
    {
        if (shortId.Length != ShortIdSize)
            throw new ArgumentException($"The short id is {ShortIdSize} bytes.", nameof(shortId));

        shortId.Clear();
        error = null;

        if (string.IsNullOrEmpty(hex))
            return true;

        if ((hex.Length & 1) != 0)
        {
            error = $"A REALITY short id is an even number of hex digits; '{hex}' is not.";
            return false;
        }

        if (hex.Length > ShortIdSize * 2)
        {
            error = $"A REALITY short id is at most {ShortIdSize} bytes ({ShortIdSize * 2} hex digits); " +
                    $"'{hex}' is {hex.Length / 2}.";
            return false;
        }

        for (int i = 0; i < hex.Length; i++)
        {
            int nibble = hex[i] switch
            {
                >= '0' and <= '9' => hex[i] - '0',
                >= 'a' and <= 'f' => hex[i] - 'a' + 10,
                >= 'A' and <= 'F' => hex[i] - 'A' + 10,
                _ => -1
            };

            if (nibble < 0)
            {
                shortId.Clear();
                error = $"'{hex[i]}' in the REALITY short id '{hex}' is not a hex digit.";
                return false;
            }

            shortId[i / 2] |= (byte)(i % 2 == 0 ? nibble << 4 : nibble);
        }

        return true;
    }

    /// <summary>
    /// Parses the share link's <c>sid</c> — an even-length hex string — into a zero-padded short id.
    /// </summary>
    /// <param name="shortId">Receives 8 bytes.</param>
    /// <param name="hex">The hex text; may be empty, which is a valid configuration.</param>
    /// <exception cref="FormatException">The text is not hex, or is longer than 8 bytes.</exception>
    public static void ParseShortId(Span<byte> shortId, string? hex)
    {
        if (!TryParseShortId(shortId, hex, out string? error))
            throw new FormatException(error);
    }
}
