using System.Buffers;
using System.Security.Cryptography;

namespace QuickProxyNet.Reality.Managed;

/// <summary>TLS record content types (RFC 8446 §5.1).</summary>
internal enum TlsContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

/// <summary>TLS 1.3 handshake message types (RFC 8446 §4).</summary>
internal enum TlsHandshakeType : byte
{
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24
}

/// <summary>
/// A negotiated TLS 1.3 cipher suite: its hash, its key length, and how to build its AEAD.
/// </summary>
internal sealed class TlsCipherSuite
{
    private TlsCipherSuite(ushort id, string name, HashAlgorithmName hash, int hashLength, int keyLength, bool chaCha)
    {
        Id = id;
        Name = name;
        Hash = hash;
        HashLength = hashLength;
        KeyLength = keyLength;
        IsChaCha = chaCha;
    }

    public ushort Id { get; }
    public string Name { get; }
    public HashAlgorithmName Hash { get; }
    public int HashLength { get; }
    public int KeyLength { get; }
    public bool IsChaCha { get; }

    /// <summary>All TLS 1.3 AEADs are 16-byte-tag AEADs with a 12-byte nonce.</summary>
    public const int TagLength = 16;

    /// <summary>Nonce length, fixed by RFC 8446 §5.3.</summary>
    public const int NonceLength = 12;

    /// <summary>Resolves a suite by its wire id, or null when we did not offer it.</summary>
    /// <remarks>
    /// A server that answers with a suite outside this set has either misbehaved or we offered
    /// something we cannot implement — either way, failing loudly beats guessing.
    /// </remarks>
    public static TlsCipherSuite? FromId(ushort id) => id switch
    {
        0x1301 => new TlsCipherSuite(id, "TLS_AES_128_GCM_SHA256", HashAlgorithmName.SHA256, 32, 16, chaCha: false),
        0x1302 => new TlsCipherSuite(id, "TLS_AES_256_GCM_SHA384", HashAlgorithmName.SHA384, 48, 32, chaCha: false),
        0x1303 when ChaCha20Poly1305.IsSupported =>
            new TlsCipherSuite(id, "TLS_CHACHA20_POLY1305_SHA256", HashAlgorithmName.SHA256, 32, 32, chaCha: true),
        _ => null
    };
}

/// <summary>
/// One direction's record protection: a key, a static IV, and the sequence number that turns
/// them into a per-record nonce.
/// </summary>
/// <remarks>
/// <para>
/// The sequence number restarts at zero every time the keys change, which is why this type is
/// replaced wholesale at each epoch rather than reset — a stale counter surviving a key change is
/// a bug that shows up as "the first record after the handshake fails to decrypt".
/// </para>
/// </remarks>
internal sealed class TlsRecordProtection : IDisposable
{
    private readonly byte[] _iv;
    private readonly AesGcm? _aes;
    private readonly ChaCha20Poly1305? _chaCha;
    private ulong _sequenceNumber;

    public TlsRecordProtection(TlsCipherSuite suite, ReadOnlySpan<byte> trafficSecret)
    {
        byte[] key = new byte[suite.KeyLength];
        _iv = new byte[TlsCipherSuite.NonceLength];

        try
        {
            TlsKeySchedule.TrafficKeys(suite.Hash, trafficSecret, key, _iv);

            if (suite.IsChaCha)
                _chaCha = new ChaCha20Poly1305(key);
            else
                _aes = new AesGcm(key, TlsCipherSuite.TagLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Encrypts one record's inner plaintext, producing the ciphertext and tag in place.
    /// </summary>
    /// <param name="plaintext">Content plus the one-byte real content type.</param>
    /// <param name="ciphertext">Receives the ciphertext; same length as the plaintext.</param>
    /// <param name="tag">Receives the 16-byte tag.</param>
    /// <param name="header">The outer record header, which is the additional data.</param>
    public void Protect(
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> header)
    {
        Span<byte> nonce = stackalloc byte[TlsCipherSuite.NonceLength];
        TlsKeySchedule.BuildNonce(nonce, _iv, _sequenceNumber++);

        if (_chaCha is not null)
            _chaCha.Encrypt(nonce, plaintext, ciphertext, tag, header);
        else
            _aes!.Encrypt(nonce, plaintext, ciphertext, tag, header);
    }

    /// <summary>Decrypts one record.</summary>
    /// <param name="ciphertext">The ciphertext, without the tag.</param>
    /// <param name="tag">The 16-byte tag.</param>
    /// <param name="plaintext">Receives the inner plaintext.</param>
    /// <param name="header">The outer record header, which is the additional data.</param>
    public void Unprotect(
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> header)
    {
        Span<byte> nonce = stackalloc byte[TlsCipherSuite.NonceLength];
        TlsKeySchedule.BuildNonce(nonce, _iv, _sequenceNumber++);

        if (_chaCha is not null)
            _chaCha.Decrypt(nonce, ciphertext, tag, plaintext, header);
        else
            _aes!.Decrypt(nonce, ciphertext, tag, plaintext, header);
    }

    public void Dispose()
    {
        _aes?.Dispose();
        _chaCha?.Dispose();
        CryptographicOperations.ZeroMemory(_iv);
    }
}

/// <summary>
/// Reads and writes TLS records over a transport stream, applying protection once keys exist.
/// </summary>
internal sealed class TlsRecordStream(Stream transport) : IDisposable
{
    /// <summary>Largest plaintext a record may carry (RFC 8446 §5.1).</summary>
    public const int MaxPlaintext = 16384;

    /// <summary>Largest ciphertext a record may carry: plaintext, content type, tag and slack.</summary>
    public const int MaxCiphertext = MaxPlaintext + 256;

    private readonly byte[] _header = new byte[5];
    private readonly byte[] _body = ArrayPool<byte>.Shared.Rent(MaxCiphertext);
    private readonly byte[] _plaintext = ArrayPool<byte>.Shared.Rent(MaxCiphertext);

    /// <summary>The record being written: header, ciphertext and tag, contiguous for one write.</summary>
    private readonly byte[] _outbound =
        ArrayPool<byte>.Shared.Rent(5 + MaxPlaintext + 1 + TlsCipherSuite.TagLength);

    /// <summary>The inner plaintext being staged: the payload plus its content-type byte.</summary>
    private readonly byte[] _outboundPlain = ArrayPool<byte>.Shared.Rent(MaxPlaintext + 1);

    private bool _disposed;

    /// <summary>Protection for outgoing records, or null while still in the clear.</summary>
    public TlsRecordProtection? Write { get; set; }

    /// <summary>Protection for incoming records, or null while still in the clear.</summary>
    public TlsRecordProtection? Read { get; set; }

    /// <summary>One record's worth of content.</summary>
    /// <param name="Type">The real content type, after any inner-type unwrapping.</param>
    /// <param name="Payload">The content; a slice of an internal buffer, valid until the next read.</param>
    public readonly record struct Record(TlsContentType Type, ReadOnlyMemory<byte> Payload);

    /// <summary>Reads one record, decrypting it when read protection is installed.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    public async ValueTask<Record> ReadAsync(CancellationToken cancellationToken)
    {
        await transport.ReadExactlyAsync(_header, cancellationToken).ConfigureAwait(false);

        var type = (TlsContentType)_header[0];
        int length = (_header[3] << 8) | _header[4];

        if (length > MaxCiphertext)
            throw new InvalidOperationException($"The peer sent a {length}-byte record, over the {MaxCiphertext} limit.");

        await transport.ReadExactlyAsync(_body.AsMemory(0, length), cancellationToken).ConfigureAwait(false);

        // ChangeCipherSpec is never encrypted and carries no meaning in TLS 1.3; it exists only so
        // middleboxes see a familiar handshake. Passing it through as content would corrupt the
        // handshake transcript, so it is surfaced as-is for the caller to drop.
        if (Read is null || type == TlsContentType.ChangeCipherSpec)
            return new Record(type, _body.AsMemory(0, length));

        if (length < TlsCipherSuite.TagLength)
            throw new InvalidOperationException("The peer sent an encrypted record shorter than its own tag.");

        int contentLength = length - TlsCipherSuite.TagLength;
        Read.Unprotect(
            _body.AsSpan(0, contentLength),
            _body.AsSpan(contentLength, TlsCipherSuite.TagLength),
            _plaintext.AsSpan(0, contentLength),
            _header);

        // The real content type is the last non-zero byte: TLS 1.3 hides it behind zero padding.
        // LastIndexOfAnyExcept is vectorised in the BCL; the byte loop it replaces was O(padding),
        // which a peer could make 16 KiB long. Returns -1 for an all-zero record, so the
        // no-content-type case below is reached identically.
        int end = _plaintext.AsSpan(0, contentLength).LastIndexOfAnyExcept((byte)0) + 1;

        if (end == 0)
            throw new InvalidOperationException("The peer sent a record with no content type.");

        return new Record((TlsContentType)_plaintext[end - 1], _plaintext.AsMemory(0, end - 1));
    }

    /// <summary>Writes one record, encrypting it when write protection is installed.</summary>
    /// <param name="type">The content type.</param>
    /// <param name="payload">The content.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Not reentrant: one record is staged in shared buffers, and the protection's sequence
    /// number advances per call. Two concurrent writers already produced records the peer could
    /// not order, so this narrows an existing hazard rather than adding one — but it is worth
    /// stating, because the symptom changes from a bad sequence number to interleaved plaintext.
    /// </remarks>
    public async ValueTask WriteAsync(
        TlsContentType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        // The staging buffers hold exactly one record. A larger payload would silently truncate
        // the length field, so it is refused rather than corrected.
        if (payload.Length > MaxPlaintext)
            throw new ArgumentOutOfRangeException(
                nameof(payload), payload.Length, $"A TLS record carries at most {MaxPlaintext} bytes.");

        if (Write is null)
        {
            Span<byte> plain = _outbound.AsSpan(0, 5 + payload.Length);
            plain[0] = (byte)type;
            plain[1] = 3;
            plain[2] = payload.Length > 0 && type == TlsContentType.Handshake ? (byte)1 : (byte)3;
            plain[3] = (byte)(payload.Length >> 8);
            plain[4] = (byte)payload.Length;
            payload.Span.CopyTo(plain[5..]);

            await transport.WriteAsync(_outbound.AsMemory(0, 5 + payload.Length), cancellationToken)
                .ConfigureAwait(false);
            await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        // An encrypted record always announces itself as application_data; the real type rides
        // inside, after the content.
        int inner = payload.Length + 1;
        _outbound[0] = (byte)TlsContentType.ApplicationData;
        _outbound[1] = 3;
        _outbound[2] = 3;
        _outbound[3] = (byte)((inner + TlsCipherSuite.TagLength) >> 8);
        _outbound[4] = (byte)(inner + TlsCipherSuite.TagLength);

        // Staged in a second buffer rather than encrypted in place: .NET does not document
        // whether an AEAD may overlap its input and output, and the record layer is the wrong
        // place to discover the answer.
        payload.Span.CopyTo(_outboundPlain);
        _outboundPlain[payload.Length] = (byte)type;

        Write.Protect(
            _outboundPlain.AsSpan(0, inner),
            _outbound.AsSpan(5, inner),
            _outbound.AsSpan(5 + inner, TlsCipherSuite.TagLength),
            _outbound.AsSpan(0, 5));

        await transport
            .WriteAsync(_outbound.AsMemory(0, 5 + inner + TlsCipherSuite.TagLength), cancellationToken)
            .ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Releases the pooled buffers and the AEAD instances.</summary>
    /// <remarks>
    /// The guard is load-bearing now that the buffers are rented: this type is disposed twice on
    /// the failure path — once by the handshake's catch, once by the stream that wraps it — and
    /// returning the same array to the pool twice would hand one connection's buffer to another.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        Read?.Dispose();
        Write?.Dispose();

        // Cleared on return: these held decrypted application data.
        ArrayPool<byte>.Shared.Return(_plaintext, clearArray: true);
        ArrayPool<byte>.Shared.Return(_outboundPlain, clearArray: true);
        ArrayPool<byte>.Shared.Return(_body, clearArray: true);
        ArrayPool<byte>.Shared.Return(_outbound, clearArray: true);
    }
}
