using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The per-connection random and time inputs of a VMessAEAD request header, supplied by
/// the caller so the whole header is a pure function of its inputs.
/// </summary>
/// <remarks>
/// VMess mixes randomness into six independent places (AuthID timestamp and nonce, the
/// connection nonce, the body key and IV, the response verifier, and the padding). Taking
/// them as an explicit input makes <see cref="VmessRequest"/> deterministic and therefore
/// testable against fixed wire vectors; production code fills the struct through
/// <see cref="VmessRequest.CreateMaterial"/>. It is a <c>ref struct</c> over
/// caller-owned buffers, so building a header allocates nothing.
/// </remarks>
internal readonly ref struct VmessRequestMaterial
{
    /// <summary>Timestamp embedded in the AuthID, in whole Unix seconds.</summary>
    public long AuthIdTimestamp { get; init; }

    /// <summary>The 4 random bytes of the AuthID plaintext.</summary>
    public ReadOnlySpan<byte> AuthIdRandom { get; init; }

    /// <summary>The 8-byte connection nonce that salts both header AEAD derivations.</summary>
    public ReadOnlySpan<byte> ConnectionNonce { get; init; }

    /// <summary>The 16-byte request body key (used later by the body cipher).</summary>
    public ReadOnlySpan<byte> BodyKey { get; init; }

    /// <summary>The 16-byte request body IV (used later by the body cipher).</summary>
    public ReadOnlySpan<byte> BodyIv { get; init; }

    /// <summary>The response verifier byte the server echoes back in its response header.</summary>
    public byte ResponseVerifier { get; init; }

    /// <summary>
    /// The random padding appended after the address. Its <b>length</b> is the padding
    /// length written into the high nibble of the security byte, so it must be 0–15 bytes.
    /// </summary>
    public ReadOnlySpan<byte> Padding { get; init; }
}

/// <summary>
/// Builds the VMessAEAD (<c>alterId = 0</c>) client request header: the plaintext
/// instruction/command section (<c>proxy/vmess/encoding/client.go</c>) and the AEAD
/// envelope that seals it (<c>proxy/vmess/aead/encrypt.go</c>).
/// </summary>
/// <remarks>
/// Wire layout of the sealed header:
/// <code>
/// authid(16) ‖ encryptedLength(2+16) ‖ connectionNonce(8) ‖ encryptedHeader(L+16)
/// </code>
/// where <c>L</c> is the length of the command section — total <c>58 + L</c> bytes. Both
/// AEADs are AES-128-GCM with a 16-byte tag, keyed by
/// <c>KDF(cmdKey, label, authid, connectionNonce)</c>, and both use the <b>AuthID</b> as
/// associated data.
/// <para>
/// Note that the command section writes the <b>port before the address</b> (VMess is
/// configured <c>PortThenAddress</c>), unlike SOCKS5/Trojan. The address type codes match
/// VLESS: 0x01 IPv4 / 0x02 domain / 0x03 IPv6.
/// </para>
/// </remarks>
internal static class VmessRequest
{
    /// <summary>Request header version byte.</summary>
    public const byte Version = 0x01;

    /// <summary>Command: TCP.</summary>
    public const byte CommandTcp = 0x01;

    /// <summary>Command: UDP.</summary>
    public const byte CommandUdp = 0x02;

    /// <summary>Command: Mux.</summary>
    public const byte CommandMux = 0x03;

    /// <summary>Option flag S: the body is sent as a chunked stream.</summary>
    public const byte OptionChunkStream = 0x01;

    /// <summary>Option flag M: chunk length obfuscation.</summary>
    public const byte OptionChunkMasking = 0x04;

    /// <summary>Option flag P: global padding.</summary>
    public const byte OptionGlobalPadding = 0x08;

    /// <summary>Option flag A: authenticated chunk length.</summary>
    public const byte OptionAuthenticatedLength = 0x10;

    /// <summary>Option set a modern AEAD client sends (S | M | P | A).</summary>
    public const byte DefaultOption =
        OptionChunkStream | OptionChunkMasking | OptionGlobalPadding | OptionAuthenticatedLength;

    /// <summary>Security type 3: AES-128-GCM body cipher.</summary>
    public const byte SecurityAes128Gcm = 0x03;

    /// <summary>Security type 4: ChaCha20-Poly1305 body cipher.</summary>
    public const byte SecurityChaCha20Poly1305 = 0x04;

    /// <summary>Security type 5: no body encryption.</summary>
    public const byte SecurityNone = 0x05;

    /// <summary>Security type 6: "zero" — no encryption and no authentication.</summary>
    public const byte SecurityZero = 0x06;

    /// <summary>Length of the request body key and IV, in bytes.</summary>
    public const int BodyKeySize = 16;

    /// <summary>Length of the connection nonce, in bytes.</summary>
    public const int ConnectionNonceSize = 8;

    /// <summary>Maximum random padding the 4-bit padding-length nibble can express.</summary>
    public const int MaxPaddingLength = 15;

    /// <summary>
    /// Bytes the envelope adds on top of the command section:
    /// authid(16) + encryptedLength(18) + connectionNonce(8) + GCM tag(16).
    /// </summary>
    public const int SealOverhead = VmessAuthId.Size + 2 + TagSize + ConnectionNonceSize + TagSize;

    /// <summary>
    /// Scratch size required by <see cref="CreateMaterial"/>:
    /// random(4) + nonce(8) + bodyKey(16) + bodyIv(16) + respV(1) + padding(15).
    /// </summary>
    public const int MaterialScratchSize =
        VmessAuthId.RandomSize + ConnectionNonceSize + BodyKeySize + BodyKeySize + 1 + MaxPaddingLength;

    private const int TagSize = 16;
    private const int GcmKeySize = 16;
    private const int GcmNonceSize = 12;

    // Field offsets inside the CreateMaterial scratch buffer.
    private const int ScratchRandomOffset = 0;
    private const int ScratchNonceOffset = ScratchRandomOffset + VmessAuthId.RandomSize;      // 4
    private const int ScratchBodyKeyOffset = ScratchNonceOffset + ConnectionNonceSize;        // 12
    private const int ScratchBodyIvOffset = ScratchBodyKeyOffset + BodyKeySize;               // 28
    private const int ScratchResponseVerifierOffset = ScratchBodyIvOffset + BodyKeySize;      // 44
    private const int ScratchPaddingOffset = ScratchResponseVerifierOffset + 1;               // 45

    // version(1) + iv(16) + key(16) + respV(1) + option(1) + padSec(1) + reserved(1) +
    // command(1) + port(2) — everything before the address type byte.
    private const int AddressOffset = 40;

    /// <summary>Largest command section this builder can emit.</summary>
    public const int MaxCommandSectionSize =
        AddressOffset + ProxyAddress.MaxLength + MaxPaddingLength + 4;

    /// <summary>Largest sealed request header this builder can emit.</summary>
    public const int MaxRequestSize = MaxCommandSectionSize + SealOverhead;

    private static ReadOnlySpan<byte> LengthKeyLabel => "VMess Header AEAD Key_Length"u8;
    private static ReadOnlySpan<byte> LengthNonceLabel => "VMess Header AEAD Nonce_Length"u8;
    private static ReadOnlySpan<byte> PayloadKeyLabel => "VMess Header AEAD Key"u8;
    private static ReadOnlySpan<byte> PayloadNonceLabel => "VMess Header AEAD Nonce"u8;

    /// <summary>
    /// Fills a <see cref="VmessRequestMaterial"/> from the system CSPRNG and the current
    /// UTC second. The returned struct points into <paramref name="scratch"/>, which the
    /// caller must keep alive (and should clear) for as long as the material is used.
    /// </summary>
    /// <param name="scratch">
    /// A buffer of at least <see cref="MaterialScratchSize"/> bytes.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="scratch"/> is too small.</exception>
    public static VmessRequestMaterial CreateMaterial(Span<byte> scratch)
    {
        if (scratch.Length < MaterialScratchSize)
            throw new ArgumentException(
                $"Scratch must be at least {MaterialScratchSize} bytes.", nameof(scratch));

        Span<byte> buffer = scratch[..MaterialScratchSize];
        RandomNumberGenerator.Fill(buffer);

        // dice.RollWith(16) — a uniform padding length in [0, 16).
        int paddingLength = RandomNumberGenerator.GetInt32(0, MaxPaddingLength + 1);

        return new VmessRequestMaterial
        {
            AuthIdTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            AuthIdRandom = buffer.Slice(ScratchRandomOffset, VmessAuthId.RandomSize),
            ConnectionNonce = buffer.Slice(ScratchNonceOffset, ConnectionNonceSize),
            BodyKey = buffer.Slice(ScratchBodyKeyOffset, BodyKeySize),
            BodyIv = buffer.Slice(ScratchBodyIvOffset, BodyKeySize),
            ResponseVerifier = buffer[ScratchResponseVerifierOffset],
            Padding = buffer.Slice(ScratchPaddingOffset, paddingLength),
        };
    }

    /// <summary>
    /// Writes the plaintext command section for <paramref name="host"/>:<paramref name="port"/>
    /// into <paramref name="destination"/> and returns the number of bytes written.
    /// </summary>
    /// <param name="destination">Receives the command section; see <see cref="MaxCommandSectionSize"/>.</param>
    /// <param name="material">The random inputs (body key/IV, response verifier, padding).</param>
    /// <param name="option">The option bitflags (see <see cref="DefaultOption"/>).</param>
    /// <param name="security">The security type nibble (0–15, e.g. <see cref="SecurityAes128Gcm"/>).</param>
    /// <param name="command">The command byte (e.g. <see cref="CommandTcp"/>).</param>
    /// <param name="host">The target host: an IPv4/IPv6 literal or a domain name.</param>
    /// <param name="port">The target port.</param>
    /// <exception cref="ArgumentException">A material field or the destination has the wrong size.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="security"/> exceeds 15.</exception>
    public static int WriteCommandSection(
        Span<byte> destination,
        in VmessRequestMaterial material,
        byte option,
        byte security,
        byte command,
        string host,
        int port)
    {
        if (material.BodyIv.Length != BodyKeySize)
            throw new ArgumentException($"BodyIv must be exactly {BodyKeySize} bytes.", nameof(material));
        if (material.BodyKey.Length != BodyKeySize)
            throw new ArgumentException($"BodyKey must be exactly {BodyKeySize} bytes.", nameof(material));
        if (material.Padding.Length > MaxPaddingLength)
            throw new ArgumentException(
                $"Padding must be at most {MaxPaddingLength} bytes (it is a 4-bit field).", nameof(material));
        if (security > 0x0F)
            throw new ArgumentOutOfRangeException(nameof(security), security,
                "Security type must fit the low nibble (0-15).");
        // The address length is only known after it has been written, so the buffer must
        // be able to hold the worst case (a 255-byte domain plus padding and checksum).
        if (destination.Length < MaxCommandSectionSize)
            throw new ArgumentException(
                $"Destination must be at least {MaxCommandSectionSize} bytes.", nameof(destination));

        destination[0] = Version;
        material.BodyIv.CopyTo(destination.Slice(1, BodyKeySize));
        material.BodyKey.CopyTo(destination.Slice(1 + BodyKeySize, BodyKeySize));
        destination[33] = material.ResponseVerifier;
        destination[34] = option;
        destination[35] = (byte)((material.Padding.Length << 4) | security);
        destination[36] = 0x00; // reserved
        destination[37] = command;
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(38, 2), (ushort)port);

        // VMess writes port first, then atyp + address (PortThenAddress).
        int offset = AddressOffset + ProxyAddress.WriteTypeAndAddress(
            host, destination[AddressOffset..], AtypIPv4, AtypDomain, AtypIPv6);

        material.Padding.CopyTo(destination[offset..]);
        offset += material.Padding.Length;

        // FNV-1a-32 (big-endian) over everything written so far, padding included.
        Fnv1a32.WriteBigEndian(destination[..offset], destination[offset..]);
        return offset + 4;
    }

    private const byte AtypIPv4 = 0x01;
    private const byte AtypDomain = 0x02;
    private const byte AtypIPv6 = 0x03;

    /// <summary>
    /// Seals a command section into the AEAD envelope and returns the total number of
    /// bytes written (<c>58 + data.Length</c>).
    /// </summary>
    /// <param name="destination">Receives the sealed header.</param>
    /// <param name="cmdKey">The 16-byte cmdKey.</param>
    /// <param name="authId">The 16-byte AuthID; also the associated data of both AEADs.</param>
    /// <param name="connectionNonce">The 8-byte connection nonce.</param>
    /// <param name="data">The plaintext command section.</param>
    /// <exception cref="ArgumentException">An input or the destination has the wrong size.</exception>
    public static int Seal(
        Span<byte> destination,
        ReadOnlySpan<byte> cmdKey,
        ReadOnlySpan<byte> authId,
        ReadOnlySpan<byte> connectionNonce,
        ReadOnlySpan<byte> data)
    {
        if (cmdKey.Length != VmessCmdKey.Size)
            throw new ArgumentException($"cmdKey must be exactly {VmessCmdKey.Size} bytes.", nameof(cmdKey));
        if (authId.Length != VmessAuthId.Size)
            throw new ArgumentException($"AuthID must be exactly {VmessAuthId.Size} bytes.", nameof(authId));
        if (connectionNonce.Length != ConnectionNonceSize)
            throw new ArgumentException(
                $"Connection nonce must be exactly {ConnectionNonceSize} bytes.", nameof(connectionNonce));
        if (data.Length > ushort.MaxValue)
            throw new ArgumentException("Command section exceeds 65535 bytes.", nameof(data));

        int total = SealOverhead + data.Length;
        if (destination.Length < total)
            throw new ArgumentException($"Destination must be at least {total} bytes.", nameof(destination));

        Span<byte> key = stackalloc byte[GcmKeySize];
        Span<byte> nonce = stackalloc byte[GcmNonceSize];
        try
        {
            authId.CopyTo(destination);

            // --- length AEAD: uint16 BE of len(data), AAD = authid ---
            Span<byte> lengthPlaintext = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)data.Length);

            VmessKdf.Kdf16(cmdKey, LengthKeyLabel, authId, connectionNonce, key);
            VmessKdf.Kdf12(cmdKey, LengthNonceLabel, authId, connectionNonce, nonce);
            using (var lengthGcm = new AesGcm(key, TagSize))
            {
                lengthGcm.Encrypt(
                    nonce,
                    lengthPlaintext,
                    destination.Slice(VmessAuthId.Size, 2),
                    destination.Slice(VmessAuthId.Size + 2, TagSize),
                    authId);
            }

            int nonceOffset = VmessAuthId.Size + 2 + TagSize; // 34
            connectionNonce.CopyTo(destination[nonceOffset..]);

            // --- payload AEAD: the command section, AAD = authid ---
            int payloadOffset = nonceOffset + ConnectionNonceSize; // 42
            VmessKdf.Kdf16(cmdKey, PayloadKeyLabel, authId, connectionNonce, key);
            VmessKdf.Kdf12(cmdKey, PayloadNonceLabel, authId, connectionNonce, nonce);
            using (var payloadGcm = new AesGcm(key, TagSize))
            {
                payloadGcm.Encrypt(
                    nonce,
                    data,
                    destination.Slice(payloadOffset, data.Length),
                    destination.Slice(payloadOffset + data.Length, TagSize),
                    authId);
            }

            return total;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// Builds the complete sealed VMessAEAD request header into
    /// <paramref name="destination"/> and returns the number of bytes written.
    /// </summary>
    /// <param name="destination">Receives the header; see <see cref="MaxRequestSize"/>.</param>
    /// <param name="cmdKey">The 16-byte cmdKey (<see cref="VmessCmdKey.Derive"/>).</param>
    /// <param name="material">The random and time inputs (<see cref="CreateMaterial"/>).</param>
    /// <param name="option">The option bitflags (see <see cref="DefaultOption"/>).</param>
    /// <param name="security">The security type nibble (e.g. <see cref="SecurityAes128Gcm"/>).</param>
    /// <param name="command">The command byte (e.g. <see cref="CommandTcp"/>).</param>
    /// <param name="host">The target host.</param>
    /// <param name="port">The target port.</param>
    /// <exception cref="ArgumentException">An input or the destination has the wrong size.</exception>
    public static int Build(
        Span<byte> destination,
        ReadOnlySpan<byte> cmdKey,
        in VmessRequestMaterial material,
        byte option,
        byte security,
        byte command,
        string host,
        int port)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(MaxCommandSectionSize);
        try
        {
            int length = WriteCommandSection(rented, material, option, security, command, host, port);

            Span<byte> authId = stackalloc byte[VmessAuthId.Size];
            VmessAuthId.Create(cmdKey, material.AuthIdTimestamp, material.AuthIdRandom, authId);

            return Seal(destination, cmdKey, authId, material.ConnectionNonce, rented.AsSpan(0, length));
        }
        finally
        {
            // The command section carries the body key and IV in the clear.
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }
}
