using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace QuickProxyNet.Reality;

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
        _iv = new byte[TlsCipherSuite.NonceLength];

        // On the stack rather than the heap: this is a record-protection key, and the largest a
        // TLS 1.3 suite uses is 32 bytes. A fixed frame keeps it out of the GC heap entirely, so
        // there is no copy for a collection to move and no window before the clearing below.
        Span<byte> key = stackalloc byte[32];
        key = key[..suite.KeyLength];

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
    /// Encrypts one record's inner plaintext, producing the ciphertext and tag.
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

        try
        {
            if (_chaCha is not null)
                _chaCha.Decrypt(nonce, ciphertext, tag, plaintext, header);
            else
                _aes!.Decrypt(nonce, ciphertext, tag, plaintext, header);
        }
        catch (CryptographicException ex)
        {
            // A record that does not authenticate is either corruption or a peer writing under
            // keys we do not share. Either way the bytes are not from the session we set up.
            throw new RealityHandshakeException(
                "A TLS record from the peer failed authentication, so it was not produced under " +
                "this session's keys. The connection cannot be trusted past this point.", ex);
        }
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
/// <remarks>
/// <para>
/// Both directions are buffered, and for the same reason: a TLS record is a 5-byte header
/// followed by a body, and a transport asked for those separately pays two reads per record.
/// Reads pull as much as the transport has and hand out whole records from the buffer, so a
/// segment carrying four records costs one read rather than eight. Writes stage several records
/// into one buffer and hand the transport a single contiguous write.
/// </para>
/// <para>
/// Neither direction is safe for concurrent use — see <see cref="WriteAsync"/>.
/// </para>
/// </remarks>
internal sealed class TlsRecordStream(Stream transport) : IDisposable
{
    /// <summary>Largest plaintext a record may carry (RFC 8446 §5.1).</summary>
    public const int MaxPlaintext = 16384;

    /// <summary>Largest ciphertext a record may carry: plaintext, content type, tag and slack.</summary>
    public const int MaxCiphertext = MaxPlaintext + 256;

    private const int HeaderLength = 5;

    /// <summary>Bytes a record costs beyond its plaintext: header, inner content type, tag.</summary>
    private const int RecordOverhead = HeaderLength + 1 + TlsCipherSuite.TagLength;

    /// <summary>
    /// Capacity of each staging buffer, chosen so several full-size records fit in one.
    /// </summary>
    /// <remarks>
    /// 64 KiB is a pool bucket exactly, and it holds three maximum-size records with room to
    /// spare — which is what makes one write per caller's write, and one read per several
    /// records, the normal case rather than the lucky one. It must stay at or above
    /// <see cref="MaxCiphertext"/> plus a header, or a maximum-size record could never be
    /// assembled at all.
    /// </remarks>
    private const int BufferCapacity = 64 * 1024;

    /// <summary>Bytes received from the transport and not yet handed out as records.</summary>
    private readonly byte[] _inbound = ArrayPool<byte>.Shared.Rent(BufferCapacity);

    /// <summary>Records being staged for the next write: headers, ciphertexts and tags.</summary>
    private readonly byte[] _outbound = ArrayPool<byte>.Shared.Rent(BufferCapacity);

    /// <summary>Where an inbound record is opened: the plaintext handed back to the caller.</summary>
    /// <remarks>
    /// <para>
    /// Records could be opened in place, over the ciphertext in <see cref="_inbound"/> — an AEAD
    /// writes one byte of output per byte of input, and .NET's implementations do tolerate an
    /// output span that is exactly the input. They are not documented to:
    /// <see cref="AesGcm.Decrypt(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte},
    /// Span{byte}, ReadOnlySpan{byte})"/> specifies only that plaintext and ciphertext are the
    /// same length and says nothing about overlap. That is a bet on an implementation detail of
    /// every platform's crypto library, and measured against this record layer it bought about
    /// one percent — the AEAD itself is the other ninety-nine.
    /// </para>
    /// <para>
    /// It also keeps the promise on <see cref="Record"/> cheap: the payload points here, and here
    /// is not the buffer that the next transport read compacts.
    /// </para>
    /// </remarks>
    private readonly byte[] _plaintext = ArrayPool<byte>.Shared.Rent(MaxCiphertext);

    /// <summary>Where an outbound record's plaintext is staged before it is sealed.</summary>
    /// <remarks>
    /// Separate from <see cref="_plaintext"/> rather than one shared scratch buffer, because the
    /// two directions are independent: a relay writes while a record it has read is still being
    /// consumed, and sharing would let a write overwrite a payload the reader is holding — data
    /// corruption on exactly the traffic pattern a proxy exists to serve.
    /// </remarks>
    private readonly byte[] _outboundPlain = ArrayPool<byte>.Shared.Rent(MaxPlaintext + 1);

    /// <summary>Start of the unconsumed span of <see cref="_inbound"/>.</summary>
    private int _start;

    /// <summary>End of the unconsumed span of <see cref="_inbound"/>.</summary>
    private int _end;

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
    /// <remarks>
    /// Completes synchronously whenever the record is already buffered, which within a burst it
    /// usually is: that path never touches the transport and never builds an async state machine,
    /// so a segment carrying four records costs one awaited read and three returns that do not
    /// yield.
    /// </remarks>
    public ValueTask<Record> ReadAsync(CancellationToken cancellationToken)
    {
        if (TryReadBuffered(out Record record))
            return new ValueTask<Record>(record);

        return ReadFromTransportAsync(cancellationToken);
    }

    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<Record> ReadFromTransportAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            // Compacted before a transport read, never after handing a record out: the payload
            // just returned aliases this buffer, and moving it early would pull the ground out
            // from under a caller that has not finished with it.
            if (_start > 0)
            {
                _inbound.AsSpan(_start, _end - _start).CopyTo(_inbound);
                _end -= _start;
                _start = 0;
            }

            int read = await transport
                .ReadAsync(_inbound.AsMemory(_end, _inbound.Length - _end), cancellationToken)
                .ConfigureAwait(false);

            // Reported the way ReadExactlyAsync used to report it, because the layer above treats
            // EndOfStreamException as an orderly end of stream.
            if (read == 0)
                throw new EndOfStreamException("The peer closed the connection mid-record.");

            _end += read;

            if (TryReadBuffered(out Record record))
                return record;
        }
    }

    /// <summary>Takes one whole record out of the inbound buffer, if a whole one is there.</summary>
    private bool TryReadBuffered(out Record record)
    {
        record = default;

        int available = _end - _start;
        if (available < HeaderLength)
            return false;

        ReadOnlySpan<byte> header = _inbound.AsSpan(_start, HeaderLength);
        int length = (header[3] << 8) | header[4];

        // Refused as soon as the header is readable rather than after the body arrives: an
        // oversized record is the peer's error either way, and waiting for bytes we would throw
        // away only delays the failure — and, on a hostile peer, only buys it more of our time.
        if (length > MaxCiphertext)
            throw new RealityHandshakeException(
                $"The peer sent a {length}-byte TLS record, over the {MaxCiphertext}-byte limit of RFC 8446.");

        if (available < HeaderLength + length)
            return false;

        var type = (TlsContentType)header[0];
        int bodyStart = _start + HeaderLength;
        _start += HeaderLength + length;

        // ChangeCipherSpec is never encrypted and carries no meaning in TLS 1.3; it exists only so
        // middleboxes see a familiar handshake. Passing it through as content would corrupt the
        // handshake transcript, so it is surfaced as-is for the caller to drop.
        if (Read is null || type == TlsContentType.ChangeCipherSpec)
        {
            record = new Record(type, _inbound.AsMemory(bodyStart, length));
            return true;
        }

        if (length < TlsCipherSuite.TagLength)
            throw new RealityHandshakeException("The peer sent an encrypted TLS record shorter than its own tag.");

        int contentLength = length - TlsCipherSuite.TagLength;

        Read.Unprotect(
            _inbound.AsSpan(bodyStart, contentLength),
            _inbound.AsSpan(bodyStart + contentLength, TlsCipherSuite.TagLength),
            _plaintext.AsSpan(0, contentLength),
            header);

        // The real content type is the last non-zero byte: TLS 1.3 hides it behind zero padding.
        // LastIndexOfAnyExcept is vectorised in the BCL; the byte loop it replaces was O(padding),
        // which a peer could make 16 KiB long. Returns -1 for an all-zero record, so the
        // no-content-type case below is reached identically.
        int end = _plaintext.AsSpan(0, contentLength).LastIndexOfAnyExcept((byte)0) + 1;

        if (end == 0)
            throw new RealityHandshakeException("The peer sent a TLS record with no content type.");

        record = new Record((TlsContentType)_plaintext[end - 1], _plaintext.AsMemory(0, end - 1));
        return true;
    }

    /// <summary>Writes one record, encrypting it when write protection is installed.</summary>
    /// <param name="type">The content type.</param>
    /// <param name="payload">The content.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Not reentrant: records are staged in a shared buffer, and the protection's sequence
    /// number advances per record. Two concurrent writers already produced records the peer could
    /// not order, so this narrows an existing hazard rather than adding one — but it is worth
    /// stating, because the symptom changes from a bad sequence number to interleaved plaintext.
    /// </remarks>
    public ValueTask WriteAsync(
        TlsContentType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        // The staging buffer holds exactly one record of this size. A larger payload would
        // silently truncate the length field, so it is refused rather than corrected.
        if (payload.Length > MaxPlaintext)
            throw new ArgumentOutOfRangeException(
                nameof(payload), payload.Length, $"A TLS record carries at most {MaxPlaintext} bytes.");

        int staged = StageRecord(type, payload.Span, _outbound);

        return SendStagedAsync(staged, cancellationToken);
    }

    /// <summary>
    /// Writes application data as as few transport writes as the staging buffer allows.
    /// </summary>
    /// <param name="payload">The content, split across records when it exceeds one.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// The record split is forced by RFC 8446 §5.1; the write split is not. A 64 KiB write becomes
    /// four records, and handing those to the transport one at a time is four writes and four
    /// flushes to satisfy one caller — so they are staged contiguously and sent together.
    /// </remarks>
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder))]
    public async ValueTask WriteApplicationDataAsync(
        ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        while (!payload.IsEmpty)
        {
            int staged = 0;

            while (!payload.IsEmpty && _outbound.Length - staged > RecordOverhead)
            {
                int chunk = Math.Min(
                    Math.Min(payload.Length, MaxPlaintext),
                    _outbound.Length - staged - RecordOverhead);

                staged += StageRecord(
                    TlsContentType.ApplicationData, payload.Span[..chunk], _outbound.AsSpan(staged));

                payload = payload[chunk..];
            }

            await transport.WriteAsync(_outbound.AsMemory(0, staged), cancellationToken).ConfigureAwait(false);
        }

        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder))]
    private async ValueTask SendStagedAsync(int staged, CancellationToken cancellationToken)
    {
        await transport.WriteAsync(_outbound.AsMemory(0, staged), cancellationToken).ConfigureAwait(false);
        await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Frames one record into <paramref name="destination"/>; returns the bytes written.</summary>
    private int StageRecord(TlsContentType type, ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        if (Write is null)
        {
            destination[0] = (byte)type;
            destination[1] = 3;
            destination[2] = payload.Length > 0 && type == TlsContentType.Handshake ? (byte)1 : (byte)3;
            destination[3] = (byte)(payload.Length >> 8);
            destination[4] = (byte)payload.Length;
            payload.CopyTo(destination[HeaderLength..]);

            return HeaderLength + payload.Length;
        }

        // An encrypted record always announces itself as application_data; the real type rides
        // inside, after the content.
        int inner = payload.Length + 1;
        destination[0] = (byte)TlsContentType.ApplicationData;
        destination[1] = 3;
        destination[2] = 3;
        destination[3] = (byte)((inner + TlsCipherSuite.TagLength) >> 8);
        destination[4] = (byte)(inner + TlsCipherSuite.TagLength);

        // Staged where the AEAD's input and output cannot overlap — see _plaintext for why that
        // is worth a copy — and sealed straight into the outbound buffer at the offset this
        // record occupies, so the batch stays contiguous for one write.
        payload.CopyTo(_outboundPlain);
        _outboundPlain[payload.Length] = (byte)type;

        Write.Protect(
            _outboundPlain.AsSpan(0, inner),
            destination.Slice(HeaderLength, inner),
            destination.Slice(HeaderLength + inner, TlsCipherSuite.TagLength),
            destination[..HeaderLength]);

        return HeaderLength + inner + TlsCipherSuite.TagLength;
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

        // Cleared on return: these held decrypted application data, and the pool hands the same
        // array to whoever rents next.
        ArrayPool<byte>.Shared.Return(_inbound, clearArray: true);
        ArrayPool<byte>.Shared.Return(_outbound, clearArray: true);
        ArrayPool<byte>.Shared.Return(_plaintext, clearArray: true);
        ArrayPool<byte>.Shared.Return(_outboundPlain, clearArray: true);
    }
}
