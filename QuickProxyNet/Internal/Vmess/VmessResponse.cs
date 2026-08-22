using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The parsed plaintext of a VMessAEAD server response header.
/// </summary>
internal readonly struct VmessResponseHeader
{
    /// <summary>The response verifier the server echoed back (byte 0).</summary>
    public byte ResponseVerifier { get; init; }

    /// <summary>The response option bitmask (byte 1).</summary>
    public byte Option { get; init; }

    /// <summary>The command id (byte 2); <c>0</c> means "no command".</summary>
    public byte Command { get; init; }

    /// <summary>
    /// The length of the command data (byte 3). Reported as <c>0</c> when
    /// <see cref="Command"/> is <c>0</c>, because the field is then meaningless.
    /// </summary>
    public byte CommandLength { get; init; }
}

/// <summary>
/// Reads the VMessAEAD (<c>alterId = 0</c>) server response header
/// (<c>proxy/vmess/encoding/client.go</c>, <c>DecodeResponseHeader</c>).
/// </summary>
/// <remarks>
/// The response header is sealed in two AES-128-GCM blocks — <b>always AES-128-GCM,
/// independent of the negotiated body cipher</b> — with <b>empty</b> associated data:
/// <code>
/// encryptedLength(2 + 16 tag)  ‖  encryptedHeader(L + 16 tag)
/// </code>
/// Each block uses a single fixed nonce taken straight from the KDF; there is no chunk
/// counter here. Both keys derive from <c>responseBodyKey</c> and both nonces from
/// <c>responseBodyIV</c>, which are themselves <c>SHA256(requestBodyKey/IV)[0:16]</c>.
/// </remarks>
internal static class VmessResponse
{
    /// <summary>Size of the sealed length block: <c>uint16 + 16-byte tag</c>.</summary>
    public const int LengthBlockSize = 2 + TagSize;

    /// <summary>Length of a response body key or IV, in bytes.</summary>
    public const int KeySize = VmessBodyKeys.ResponseKeySize;

    /// <summary>Smallest legal header plaintext: respV, option, command, commandLength.</summary>
    public const int MinHeaderSize = 4;

    private const int TagSize = 16;
    private const int NonceSize = 12;

    // Layout of the scratch buffer holding all four derived values.
    private const int LengthKeyOffset = 0;                              // 16 bytes
    private const int LengthIvOffset = LengthKeyOffset + 16;            // 12 bytes
    private const int HeaderKeyOffset = LengthIvOffset + NonceSize;     // 16 bytes
    private const int HeaderIvOffset = HeaderKeyOffset + 16;            // 12 bytes
    private const int MaterialSize = HeaderIvOffset + NonceSize;        // 56

    private static ReadOnlySpan<byte> LengthKeyLabel => "AEAD Resp Header Len Key"u8;
    private static ReadOnlySpan<byte> LengthIvLabel => "AEAD Resp Header Len IV"u8;
    private static ReadOnlySpan<byte> HeaderKeyLabel => "AEAD Resp Header Key"u8;
    private static ReadOnlySpan<byte> HeaderIvLabel => "AEAD Resp Header IV"u8;

    /// <summary>
    /// Derives the response body key and IV from the request ones:
    /// <c>SHA256(requestBodyKey)[0:16]</c> and <c>SHA256(requestBodyIV)[0:16]</c>.
    /// </summary>
    /// <param name="requestBodyKey">The 16-byte request body key.</param>
    /// <param name="requestBodyIv">The 16-byte request body IV.</param>
    /// <param name="responseBodyKey">Receives the 16-byte response body key.</param>
    /// <param name="responseBodyIv">Receives the 16-byte response body IV.</param>
    /// <exception cref="ArgumentException">An input or destination has the wrong size.</exception>
    public static void DeriveBodyKeys(
        ReadOnlySpan<byte> requestBodyKey,
        ReadOnlySpan<byte> requestBodyIv,
        Span<byte> responseBodyKey,
        Span<byte> responseBodyIv)
    {
        if (requestBodyKey.Length != KeySize)
            throw new ArgumentException($"Request body key must be exactly {KeySize} bytes.", nameof(requestBodyKey));
        if (requestBodyIv.Length != KeySize)
            throw new ArgumentException($"Request body IV must be exactly {KeySize} bytes.", nameof(requestBodyIv));

        VmessBodyKeys.DeriveResponseKeyOrIv(requestBodyKey, responseBodyKey);
        VmessBodyKeys.DeriveResponseKeyOrIv(requestBodyIv, responseBodyIv);
    }

    /// <summary>
    /// Derives the four response-header AEAD parameters. Note that both <b>keys</b> come
    /// from <paramref name="responseBodyKey"/> and both <b>IVs</b> from
    /// <paramref name="responseBodyIv"/>.
    /// </summary>
    /// <param name="responseBodyKey">The 16-byte response body key.</param>
    /// <param name="responseBodyIv">The 16-byte response body IV.</param>
    /// <param name="lengthKey">Receives the 16-byte length-block key.</param>
    /// <param name="lengthIv">Receives the 12-byte length-block nonce.</param>
    /// <param name="headerKey">Receives the 16-byte header key.</param>
    /// <param name="headerIv">Receives the 12-byte header nonce.</param>
    /// <exception cref="ArgumentException">An input or destination has the wrong size.</exception>
    public static void DeriveHeaderKeys(
        ReadOnlySpan<byte> responseBodyKey,
        ReadOnlySpan<byte> responseBodyIv,
        Span<byte> lengthKey,
        Span<byte> lengthIv,
        Span<byte> headerKey,
        Span<byte> headerIv)
    {
        if (responseBodyKey.Length != KeySize)
            throw new ArgumentException($"Response body key must be exactly {KeySize} bytes.", nameof(responseBodyKey));
        if (responseBodyIv.Length != KeySize)
            throw new ArgumentException($"Response body IV must be exactly {KeySize} bytes.", nameof(responseBodyIv));

        VmessKdf.Kdf16(responseBodyKey, LengthKeyLabel, lengthKey);
        VmessKdf.Kdf12(responseBodyIv, LengthIvLabel, lengthIv);
        VmessKdf.Kdf16(responseBodyKey, HeaderKeyLabel, headerKey);
        VmessKdf.Kdf12(responseBodyIv, HeaderIvLabel, headerIv);
    }

    /// <summary>
    /// Reads, decrypts and validates the server response header from
    /// <paramref name="stream"/>, leaving the stream positioned on the first response
    /// body chunk. Command data, if any, is parsed and skipped.
    /// </summary>
    /// <param name="stream">The transport, positioned at the start of the response header.</param>
    /// <param name="responseBodyKey">The 16-byte response body key (<see cref="DeriveBodyKeys"/>).</param>
    /// <param name="responseBodyIv">The 16-byte response body IV (<see cref="DeriveBodyKeys"/>).</param>
    /// <param name="expectedResponseVerifier">
    /// The response verifier byte the client put in its request header; the server must echo it.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <exception cref="ArgumentException">A key or IV has the wrong size.</exception>
    /// <exception cref="EndOfStreamException">The response header is truncated.</exception>
    /// <exception cref="ProxyProtocolException">
    /// The header failed authentication, is malformed, or the response verifier does not match.
    /// </exception>
    public static async ValueTask<VmessResponseHeader> ReadAsync(
        Stream stream,
        ReadOnlyMemory<byte> responseBodyKey,
        ReadOnlyMemory<byte> responseBodyIv,
        byte expectedResponseVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (responseBodyKey.Length != KeySize)
            throw new ArgumentException($"Response body key must be exactly {KeySize} bytes.", nameof(responseBodyKey));
        if (responseBodyIv.Length != KeySize)
            throw new ArgumentException($"Response body IV must be exactly {KeySize} bytes.", nameof(responseBodyIv));

        byte[] material = ArrayPool<byte>.Shared.Rent(MaterialSize);
        try
        {
            DeriveInto(material, responseBodyKey, responseBodyIv);

            int headerLength;
            byte[] lengthBlock = ArrayPool<byte>.Shared.Rent(LengthBlockSize);
            try
            {
                // A short read here is truncation, never a clean end of stream.
                await stream.ReadExactlyAsync(lengthBlock.AsMemory(0, LengthBlockSize), cancellationToken);
                headerLength = OpenLength(material, lengthBlock);
            }
            catch (EndOfStreamException ex)
            {
                throw ClosedBeforeResponse(ex);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lengthBlock, clearArray: true);
            }

            if (headerLength < MinHeaderSize)
                throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                    $"VMess response header is too short: {headerLength} bytes (minimum {MinHeaderSize}).");

            int sealedLength = headerLength + TagSize;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(sealedLength + headerLength);
            try
            {
                await stream.ReadExactlyAsync(buffer.AsMemory(0, sealedLength), cancellationToken);
                return OpenHeader(material, buffer, headerLength, expectedResponseVerifier);
            }
            catch (EndOfStreamException ex)
            {
                throw ClosedBeforeResponse(ex);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(material, clearArray: true);
        }
    }

    // ---- synchronous cores (span locals are illegal inside an async method) ----

    private static void DeriveInto(
        byte[] material, ReadOnlyMemory<byte> responseBodyKey, ReadOnlyMemory<byte> responseBodyIv)
        => DeriveHeaderKeys(
            responseBodyKey.Span,
            responseBodyIv.Span,
            material.AsSpan(LengthKeyOffset, 16),
            material.AsSpan(LengthIvOffset, NonceSize),
            material.AsSpan(HeaderKeyOffset, 16),
            material.AsSpan(HeaderIvOffset, NonceSize));

    private static int OpenLength(byte[] material, byte[] lengthBlock)
    {
        Span<byte> plaintext = stackalloc byte[2];
        try
        {
            using var gcm = new AesGcm(material.AsSpan(LengthKeyOffset, 16), TagSize);
            gcm.Decrypt(
                material.AsSpan(LengthIvOffset, NonceSize),
                lengthBlock.AsSpan(0, 2),
                lengthBlock.AsSpan(2, TagSize),
                plaintext);
        }
        catch (CryptographicException ex)
        {
            // Same class of failure as a verifier mismatch below: the bytes were sealed under
            // keys that are not ours, so whatever answered is not the session we requested.
            throw new ProxyProtocolException(ProxyErrorCode.AuthFailed,
                "VMess response header length block failed authentication: the response was " +
                "produced with different keys, so the server rejected the request or something " +
                "else answered in its place.", ex);
        }

        return BinaryPrimitives.ReadUInt16BigEndian(plaintext);
    }

    /// <summary>
    /// The error for a connection that ends before a response header arrives.
    /// </summary>
    /// <remarks>
    /// This is the normal way a VMess server says no: an unknown AuthID — wrong id, a non-zero
    /// alterId on the server, or clocks more than about two minutes apart — is simply dropped,
    /// never answered. So the bare <see cref="EndOfStreamException"/> this replaces was the
    /// library's most common rejection surfacing with no protocol name and no hint.
    /// </remarks>
    private static ProxyProtocolException ClosedBeforeResponse(EndOfStreamException inner) =>
        new(ProxyErrorCode.ConnectionFailed,
            "VMess server closed the connection before sending a response header. This is how " +
            "a VMess server rejects a request it cannot authenticate: check the user id, that " +
            "the server's alterId is 0 (VMessAEAD), and that this machine's clock is within " +
            "about two minutes of the server's.",
            inner);

    private static VmessResponseHeader OpenHeader(
        byte[] material, byte[] buffer, int headerLength, byte expectedResponseVerifier)
    {
        // The plaintext is written just past the sealed bytes inside the same rental.
        Span<byte> plaintext = buffer.AsSpan(headerLength + TagSize, headerLength);
        try
        {
            using var gcm = new AesGcm(material.AsSpan(HeaderKeyOffset, 16), TagSize);
            gcm.Decrypt(
                material.AsSpan(HeaderIvOffset, NonceSize),
                buffer.AsSpan(0, headerLength),
                buffer.AsSpan(headerLength, TagSize),
                plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new ProxyProtocolException(ProxyErrorCode.AuthFailed,
                "VMess response header failed authentication: the response was produced with " +
                "different keys, so the server rejected the request or something else answered " +
                "in its place.", ex);
        }

        if (plaintext[0] != expectedResponseVerifier)
            throw new ProxyProtocolException(ProxyErrorCode.AuthFailed,
                $"VMess response verifier mismatch: expected 0x{expectedResponseVerifier:X2}, " +
                $"got 0x{plaintext[0]:X2}.");

        byte command = plaintext[2];
        byte commandLength = plaintext[3];

        // Commands are dynamic-port / switch-account directives; a minimal client parses
        // and ignores them, but the bytes must still fit inside the decrypted header.
        if (command != 0 && MinHeaderSize + commandLength > headerLength)
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                $"VMess response command data ({commandLength} bytes) does not fit the " +
                $"{headerLength}-byte header.");

        return new VmessResponseHeader
        {
            ResponseVerifier = plaintext[0],
            Option = plaintext[1],
            Command = command,
            CommandLength = command == 0 ? (byte)0 : commandLength,
        };
    }
}
