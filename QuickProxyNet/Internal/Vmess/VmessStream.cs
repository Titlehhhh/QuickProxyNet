using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The body cipher negotiated in the VMess request header's security nibble.
/// </summary>
internal enum VmessSecurity : byte
{
    /// <summary>AES-128-GCM (security type 3): the 16-byte body key is used directly.</summary>
    Aes128Gcm = VmessRequest.SecurityAes128Gcm,

    /// <summary>
    /// ChaCha20-Poly1305 (security type 4): the body key is MD5-expanded to 32 bytes
    /// (<see cref="VmessBodyKeys.ExpandChaCha20Key"/>).
    /// </summary>
    ChaCha20Poly1305 = VmessRequest.SecurityChaCha20Poly1305,
}

/// <summary>
/// The VMessAEAD (<c>alterId = 0</c>) encrypted body stream: a <see cref="Stream"/> that
/// seals everything written and opens everything read, using the baseline chunk framing
/// (request option <c>S</c> set; <c>M</c>, <c>P</c> and <c>A</c> cleared).
/// </summary>
/// <remarks>
/// <para>
/// Wire format of one chunk (<c>common/crypto/auth.go</c> with <c>PlainChunkSizeParser</c>):
/// </para>
/// <code>
/// length(2, big-endian) ‖ sealed(plaintextLen + 16)
/// </code>
/// The length field carries the <b>sealed</b> size — the plaintext length <em>plus</em> the
/// 16-byte AEAD tag — not the plaintext length. Associated data is empty.
/// <para>
/// The 12-byte nonce of a chunk is <c>uint16BE(counter) ‖ bodyIV[2:12]</c>
/// (<c>GenerateChunkNonce</c>): only the first two bytes ever change, and the counter is a
/// <c>ushort</c> that wraps at <c>0xFFFF</c>. The read and write directions are fully
/// independent — separate keys, IVs and counters — so the two halves can be closed at
/// different times.
/// </para>
/// <para>
/// End of stream is <b>in band</b>: an authenticated empty chunk (<c>00 10</c> followed by
/// the 16-byte tag of an empty plaintext). <see cref="ReadAsync(Memory{byte},CancellationToken)"/>
/// returns <c>0</c> only after opening such a chunk. A short read of the length prefix or
/// of a chunk body is truncation and raises <see cref="EndOfStreamException"/>; a failed
/// tag check raises <see cref="ProxyProtocolException"/> with
/// <see cref="ProxyErrorCode.InvalidResponse"/> (the AEAD exception is its inner). Neither is
/// ever reported as a clean end of stream.
/// </para>
/// </remarks>
internal sealed class VmessStream : Stream
{
    /// <summary>Size of every AEAD tag, in bytes.</summary>
    public const int TagSize = 16;

    /// <summary>Size of the plain <c>uint16</c> chunk length prefix, in bytes.</summary>
    public const int LengthPrefixSize = 2;

    /// <summary>Largest sealed chunk the <c>uint16</c> length field can express.</summary>
    public const int MaxSealedChunkSize = ushort.MaxValue;

    /// <summary>
    /// Largest plaintext a peer may put in one chunk (<c>65535 − 16</c>). This is the
    /// wire-format hard cap the reader must tolerate; it is deliberately <b>not</b> the
    /// smaller value this implementation emits.
    /// </summary>
    public const int MaxReceivePlaintextSize = MaxSealedChunkSize - TagSize;

    /// <summary>Size of the send buffer — Xray's <c>buf.Size</c>.</summary>
    public const int SendBufferSize = 8192;

    /// <summary>
    /// Largest plaintext this implementation puts in one chunk:
    /// <c>buf.Size − Overhead(16) − SizeBytes(2)</c> = 8174, matching Xray-core.
    /// </summary>
    public const int MaxSendPlaintextSize = SendBufferSize - TagSize - LengthPrefixSize;

    private const int InitialReceiveBufferSize = 8192;

    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly ChunkCipher _writer;
    private readonly ChunkCipher _reader;

    private byte[]? _sendBuffer;
    private byte[]? _receiveSealed;
    private byte[]? _receivePlain;
    private int _plainOffset;
    private int _plainCount;

    private bool _readEof;
    private bool _writeCompleted;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="innerStream"/> in the VMess body framing.
    /// </summary>
    /// <param name="innerStream">The transport, positioned after the request header / response header.</param>
    /// <param name="writeKey">The 16-byte body key for the client→server direction (the request body key).</param>
    /// <param name="writeIv">The 16-byte body IV for the client→server direction (the request body IV).</param>
    /// <param name="readKey">The 16-byte body key for the server→client direction (the response body key).</param>
    /// <param name="readIv">The 16-byte body IV for the server→client direction (the response body IV).</param>
    /// <param name="security">The negotiated body cipher.</param>
    /// <param name="leaveInnerOpen">When <c>true</c>, disposing this stream does not dispose the transport.</param>
    /// <exception cref="ArgumentNullException"><paramref name="innerStream"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">A key or IV is not exactly 16 bytes.</exception>
    /// <exception cref="NotSupportedException">
    /// <paramref name="security"/> is not a supported body cipher, or ChaCha20-Poly1305 was
    /// requested but the platform does not provide it.
    /// </exception>
    public VmessStream(
        Stream innerStream,
        ReadOnlySpan<byte> writeKey,
        ReadOnlySpan<byte> writeIv,
        ReadOnlySpan<byte> readKey,
        ReadOnlySpan<byte> readIv,
        VmessSecurity security,
        bool leaveInnerOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);

        _inner = innerStream;
        _leaveInnerOpen = leaveInnerOpen;
        _writer = new ChunkCipher(writeKey, writeIv, security, nameof(writeKey), nameof(writeIv));
        try
        {
            _reader = new ChunkCipher(readKey, readIv, security, nameof(readKey), nameof(readIv));
        }
        catch
        {
            _writer.Dispose();
            throw;
        }
    }

    /// <summary>The number of chunks sealed so far (the next write uses this as its nonce counter).</summary>
    public ushort WriteChunkCounter => _writer.Counter;

    /// <summary>The number of chunks opened so far (the next read uses this as its nonce counter).</summary>
    public ushort ReadChunkCounter => _reader.Counter;

    /// <summary>Whether the terminating empty chunk has already been written.</summary>
    public bool IsWriteCompleted => _writeCompleted;

    /// <summary>Whether the peer's terminating empty chunk has been received and verified.</summary>
    public bool IsReadCompleted => _readEof;

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed && !_writeCompleted;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    // ================================ reading ================================

    /// <inheritdoc/>
    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_plainCount == 0)
        {
            if (_readEof || buffer.IsEmpty)
                return 0;

            // Skip zero-length plaintext chunks other than the terminator? There are none:
            // a length of 16 *is* the terminator, so one chunk always yields data or EOF.
            int sealedLength = await ReceiveSealedChunkAsync(cancellationToken);
            int plaintextLength = sealedLength - TagSize;

            if (plaintextLength == 0)
            {
                // The terminator must still be opened: that authenticates its tag and
                // advances the nonce counter exactly like any other chunk.
                OpenChunk(sealedLength, Memory<byte>.Empty);
                _readEof = true;
                return 0;
            }

            // Fast path: the caller's buffer can hold the whole chunk, so the AEAD
            // writes the plaintext straight into it — no intermediate buffer, no copy.
            if (buffer.Length >= plaintextLength)
            {
                OpenChunk(sealedLength, buffer[..plaintextLength]);
                return plaintextLength;
            }

            EnsurePlainCapacity(plaintextLength);
            OpenChunk(sealedLength, _receivePlain.AsMemory(0, plaintextLength));
            _plainOffset = 0;
            _plainCount = plaintextLength;
        }

        int count = Math.Min(buffer.Length, _plainCount);
        _receivePlain!.AsMemory(_plainOffset, count).CopyTo(buffer);
        _plainOffset += count;
        _plainCount -= count;
        return count;
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override int Read(Span<byte> buffer)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(buffer.Length, 1));
        try
        {
            int read = ReadAsync(rented.AsMemory(0, buffer.Length), CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
            rented.AsSpan(0, read).CopyTo(buffer);
            return read;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();

    // Reads one sealed chunk (length prefix + ciphertext + tag) into _receiveSealed and
    // returns the sealed length. The chunk is not opened yet.
    private async ValueTask<int> ReceiveSealedChunkAsync(CancellationToken cancellationToken)
    {
        _receiveSealed ??= ArrayPool<byte>.Shared.Rent(InitialReceiveBufferSize);

        // A short read of the prefix is truncation, never a clean end of stream: end of stream
        // is in band (the authenticated empty chunk), and a FIN in its place is exactly what a
        // truncation attack looks like. Xray's own reader is more lenient here; this one keeps
        // the documented contract.
        await _inner.ReadExactlyAsync(_receiveSealed.AsMemory(0, LengthPrefixSize), cancellationToken);
        int sealedLength = BinaryPrimitives.ReadUInt16BigEndian(_receiveSealed.AsSpan(0, LengthPrefixSize));

        if (sealedLength < TagSize)
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                $"VMess chunk length {sealedLength} is smaller than the {TagSize}-byte AEAD tag.");

        // The 2-byte prefix has already been decoded, so the buffer can be swapped freely.
        if (_receiveSealed.Length < sealedLength)
        {
            ArrayPool<byte>.Shared.Return(_receiveSealed, clearArray: true);
            _receiveSealed = ArrayPool<byte>.Shared.Rent(sealedLength);
        }

        await _inner.ReadExactlyAsync(_receiveSealed.AsMemory(0, sealedLength), cancellationToken);
        return sealedLength;
    }

    // The leftover buffer is only needed when the caller's buffer is smaller than the
    // incoming chunk; large-buffer readers never rent it.
    [System.Diagnostics.CodeAnalysis.MemberNotNull(nameof(_receivePlain))]
    private void EnsurePlainCapacity(int plaintextLength)
    {
        if (_receivePlain is null)
        {
            _receivePlain = ArrayPool<byte>.Shared.Rent(Math.Max(plaintextLength, InitialReceiveBufferSize));
        }
        else if (_receivePlain.Length < plaintextLength)
        {
            ArrayPool<byte>.Shared.Return(_receivePlain, clearArray: true);
            _receivePlain = ArrayPool<byte>.Shared.Rent(plaintextLength);
        }
    }

    // Opens the sealed chunk currently in _receiveSealed into `plaintext`, which must be
    // exactly sealedLength - TagSize bytes (possibly empty for the terminator).
    private void OpenChunk(int sealedLength, Memory<byte> plaintext)
    {
        int plaintextLength = sealedLength - TagSize;
        try
        {
            _reader.Open(
                _receiveSealed!.AsSpan(0, plaintextLength),
                _receiveSealed.AsSpan(plaintextLength, TagSize),
                plaintext.Span);
        }
        catch (CryptographicException ex)
        {
            // The nonce has already advanced, so nothing after this chunk can be opened either:
            // the stream is over. A caller reading a Stream expects a proxy error here, not an
            // AEAD primitive's exception.
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                "A VMess data chunk failed authentication: it was not sealed with this session's keys " +
                "or was altered in transit. The stream cannot continue.", ex);
        }
    }

    // ================================ writing ================================

    /// <inheritdoc/>
    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_writeCompleted)
            throw new InvalidOperationException(
                "The VMess write direction is closed: the terminating chunk has already been sent.");

        while (!buffer.IsEmpty)
        {
            int count = Math.Min(buffer.Length, MaxSendPlaintextSize);
            int length = SealChunk(buffer.Span.Slice(0, count));
            await _inner.WriteAsync(_sendBuffer!.AsMemory(0, length), cancellationToken);
            buffer = buffer.Slice(count);
        }
    }

    /// <inheritdoc/>
    public override Task WriteAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(buffer.Length, 1));
        try
        {
            buffer.CopyTo(rented);
            WriteAsync(rented.AsMemory(0, buffer.Length), CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// Half-closes the write direction by sending the authenticated empty chunk
    /// (<c>00 10</c> ‖ tag). Idempotent; the read direction keeps working afterwards.
    /// </summary>
    /// <param name="cancellationToken">Cancels the write.</param>
    public async ValueTask CompleteWriteAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_writeCompleted)
            return;

        _writeCompleted = true;
        int length = SealChunk(ReadOnlySpan<byte>.Empty);
        await _inner.WriteAsync(_sendBuffer!.AsMemory(0, length), cancellationToken);
        await _inner.FlushAsync(cancellationToken);
    }

    // Frames and seals one chunk into _sendBuffer; returns the number of wire bytes.
    private int SealChunk(ReadOnlySpan<byte> plaintext)
    {
        byte[] buffer = _sendBuffer ??= ArrayPool<byte>.Shared.Rent(SendBufferSize);

        int sealedLength = plaintext.Length + TagSize;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, LengthPrefixSize), (ushort)sealedLength);
        _writer.Seal(
            plaintext,
            buffer.AsSpan(LengthPrefixSize, plaintext.Length),
            buffer.AsSpan(LengthPrefixSize + plaintext.Length, TagSize));

        return LengthPrefixSize + sealedLength;
    }

    // ================================ disposal ================================

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        try
        {
            if (!_writeCompleted)
            {
                try
                {
                    await CompleteWriteAsync(CancellationToken.None);
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException
                                            or OperationCanceledException or ProxyProtocolException)
                {
                    // A broken transport must not turn disposal into a failure. The WebSocket
                    // transport reports a dead socket as ProxyProtocolException, so that is
                    // as much "broken transport" here as an IOException is.
                }
            }
        }
        finally
        {
            _disposed = true;
            // Transport first: a read still in flight on another thread targets these buffers,
            // and closing the transport is what faults it. Returning the arrays to the pool
            // before that lets a late completion write into someone else's rental.
            if (!_leaveInnerOpen)
                await _inner.DisposeAsync();
            ReleaseResources();
        }

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            base.Dispose(disposing);
            return;
        }

        if (disposing)
        {
            try
            {
                if (!_writeCompleted)
                {
                    _writeCompleted = true;
                    try
                    {
                        int length = SealChunk(ReadOnlySpan<byte>.Empty);
                        _inner.Write(_sendBuffer!.AsSpan(0, length));
                        _inner.Flush();
                    }
                    catch (Exception ex) when (ex is IOException or ObjectDisposedException or ProxyProtocolException)
                    {
                        // See DisposeAsync.
                    }
                }
            }
            finally
            {
                _disposed = true;
                if (!_leaveInnerOpen)
                    _inner.Dispose();
                ReleaseResources();
            }
        }
        else
        {
            _disposed = true;
        }

        base.Dispose(disposing);
    }

    private void ReleaseResources()
    {
        _writer.Dispose();
        _reader.Dispose();

        if (_sendBuffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_sendBuffer, clearArray: true);
            _sendBuffer = null;
        }

        if (_receiveSealed is not null)
        {
            ArrayPool<byte>.Shared.Return(_receiveSealed, clearArray: true);
            _receiveSealed = null;
        }

        if (_receivePlain is not null)
        {
            ArrayPool<byte>.Shared.Return(_receivePlain, clearArray: true);
            _receivePlain = null;
        }

        _plainOffset = 0;
        _plainCount = 0;
    }

    // ================================ chunk cipher ================================

    /// <summary>
    /// One direction of the body stream: the AEAD instance plus the rolling
    /// <c>uint16BE(counter) ‖ bodyIV[2:12]</c> nonce.
    /// </summary>
    private sealed class ChunkCipher : IDisposable
    {
        private const int NonceSize = 12;
        private const int BodyKeySize = 16;

        private readonly byte[] _nonce = new byte[NonceSize];
        private readonly AesGcm? _aes;
        private readonly ChaCha20Poly1305? _chacha;
        private ushort _counter;

        public ChunkCipher(
            ReadOnlySpan<byte> bodyKey, ReadOnlySpan<byte> bodyIv,
            VmessSecurity security, string keyName, string ivName)
        {
            if (bodyKey.Length != BodyKeySize)
                throw new ArgumentException($"Body key must be exactly {BodyKeySize} bytes.", keyName);
            if (bodyIv.Length != BodyKeySize)
                throw new ArgumentException($"Body IV must be exactly {BodyKeySize} bytes.", ivName);

            // Bytes [2..12) of the IV are the constant tail of every chunk nonce.
            bodyIv.Slice(2, NonceSize - 2).CopyTo(_nonce.AsSpan(2));

            switch (security)
            {
                case VmessSecurity.Aes128Gcm:
                    _aes = new AesGcm(bodyKey, TagSize);
                    break;

                case VmessSecurity.ChaCha20Poly1305:
                    if (!ChaCha20Poly1305.IsSupported)
                        throw new NotSupportedException(
                            "VMess security 'chacha20-poly1305' requires ChaCha20-Poly1305, which this " +
                            "platform does not provide. Use 'aes-128-gcm' instead.");

                    Span<byte> expanded = stackalloc byte[VmessBodyKeys.ChaCha20KeySize];
                    try
                    {
                        VmessBodyKeys.ExpandChaCha20Key(bodyKey, expanded);
                        _chacha = new ChaCha20Poly1305(expanded);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(expanded);
                    }
                    break;

                default:
                    throw new NotSupportedException(
                        $"VMess security type {(byte)security} is not a supported body cipher; " +
                        "only aes-128-gcm and chacha20-poly1305 are implemented.");
            }
        }

        public ushort Counter => _counter;

        public void Seal(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
        {
            NextNonce();
            if (_aes is not null)
                _aes.Encrypt(_nonce, plaintext, ciphertext, tag);
            else
                _chacha!.Encrypt(_nonce, plaintext, ciphertext, tag);
        }

        public void Open(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
        {
            NextNonce();
            if (_aes is not null)
                _aes.Decrypt(_nonce, ciphertext, tag, plaintext);
            else
                _chacha!.Decrypt(_nonce, ciphertext, tag, plaintext);
        }

        // Writes the current counter into nonce[0..2) and advances it; a ushort wraps
        // 0xFFFF -> 0x0000 exactly like Go's uint16, and nonce[2..12) never changes.
        private void NextNonce()
        {
            BinaryPrimitives.WriteUInt16BigEndian(_nonce.AsSpan(0, 2), _counter);
            _counter++;
        }

        public void Dispose()
        {
            _aes?.Dispose();
            _chacha?.Dispose();
            CryptographicOperations.ZeroMemory(_nonce);
        }
    }
}
