using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The Shadowsocks AEAD (SIP004/SIP007) TCP stream: a <see cref="Stream"/> that seals everything
/// written and opens everything read, with a lazily consumed server salt.
/// </summary>
/// <remarks>
/// <para>
/// Wire format. Each direction starts with a salt of the cipher's key size, then any number of
/// chunks:
/// </para>
/// <code>
/// salt(keyLen) ‖ [ sealed(len BE 2) ‖ tag(16) ‖ sealed(payload) ‖ tag(16) ] …
/// </code>
/// <para>
/// The 2-byte length is the <b>plaintext</b> payload length, big-endian, and is itself the
/// plaintext of its own AEAD operation — the opposite of VMess, whose prefix carries the
/// <em>sealed</em> size in the clear. That is why this class shares no code with
/// <c>VmessStream</c>: the frames look alike and mean different things. The cap is
/// <c>0x3FFF</c>; a decrypted length above it is refused, not masked (go-shadowsocks2 and
/// shadowsocks-libev mask and desynchronise; shadowsocks-rust refuses; this refuses).
/// </para>
/// <para>
/// The nonce is the whole 12 bytes as a little-endian counter from 0, advanced after
/// <b>every</b> AEAD operation — two per chunk. Read and write counters are independent.
/// Associated data is empty.
/// </para>
/// <para>
/// The write direction's subkey is derived at construction from the caller's salt, which is
/// sent in front of the first chunk. The read direction is keyed <b>on the first read</b>: the
/// server sends its salt only once the target has replied (Xray buffers it behind the target's
/// first bytes, shadowsocks-rust and go-shadowsocks2 write it from their first
/// <c>Write</c>), so reading it inside <c>ConnectAsync</c> would deadlock every
/// client-speaks-first protocol — the same trap as the VLESS and VMess response headers.
/// </para>
/// <para>
/// Buffering. A <c>Write</c> is cut into chunks of at most <see cref="MaxPayloadSize"/>, and
/// consecutive chunks are sealed back-to-back into one send buffer and handed to the transport
/// in as few writes as the buffer allows; everything sealed by one <c>Write</c> is on the
/// transport before it returns, so a request/response protocol never waits on a byte held here.
/// A <c>Read</c> fills a 32 KiB window with whatever the transport has and parses chunks out of
/// it, opening exactly one non-empty chunk per call: the nonce never advances past what the
/// caller asked for, and a chunk that arrives whole in the window costs no second transport read.
/// </para>
/// <para>
/// There is no in-band terminator. A FIN exactly at a chunk boundary is the only clean end of
/// stream and returns <c>0</c>. A FIN inside the salt, the length block or a payload is
/// truncation and raises <see cref="ProxyProtocolException"/>; so does a failed tag. Neither is
/// ever reported as a clean end of stream.
/// </para>
/// </remarks>
internal sealed class ShadowsocksStream : Stream
{
    /// <summary>Size of every AEAD tag, in bytes.</summary>
    public const int TagSize = ShadowsocksCipher.TagSize;

    /// <summary>Size of the encrypted length field's plaintext, in bytes.</summary>
    public const int LengthSize = 2;

    /// <summary>Size of the sealed length block on the wire: the 2-byte length plus its tag.</summary>
    public const int LengthBlockSize = LengthSize + TagSize;

    /// <summary>The largest payload one chunk may carry: <c>0x3FFF</c>, the two high bits reserved.</summary>
    public const int MaxPayloadSize = 0x3FFF;

    /// <summary>The largest chunk on the wire: <c>2 + 16 + 0x3FFF + 16</c> = 16 417 bytes.</summary>
    public const int MaxWireChunkSize = LengthBlockSize + MaxPayloadSize + TagSize;

    /// <summary>
    /// The send buffer while every <c>Write</c> fits one chunk: the salt plus one full chunk,
    /// 16 449 bytes — the 32 KiB pool bucket.
    /// </summary>
    private const int SmallSendBufferSize = ShadowsocksCipher.MaxKeySize + MaxWireChunkSize;

    /// <summary>
    /// The send buffer once a <c>Write</c> has spanned more than one chunk: the salt plus seven
    /// full chunks, 114 951 bytes — the 128 KiB pool bucket. Seven chunks carry 114 681 bytes of
    /// payload, so <c>CopyToAsync</c>'s 81 920-byte buffer leaves as exactly one transport write.
    /// </summary>
    private const int LargeSendBufferSize = ShadowsocksCipher.MaxKeySize + 7 * MaxWireChunkSize;

    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly ShadowsocksMethod _method;
    private readonly int _saltSize;

    private readonly Direction _writer;
    private Direction? _reader;
    private byte[]? _masterKey;

    // This side's salt, held inline until the first write carries it out in front of the first chunk.
    private SaltBuffer _pendingSalt;
    private int _pendingSaltLength;

    private byte[]? _sendBuffer;

    // The receive window: wire bytes not yet parsed sit at [_start, _end) of _receiveBuffer.
    private byte[]? _receiveBuffer;
    private int _start;
    private int _end;

    // The plaintext length of the chunk whose length block has been opened but whose payload has
    // not fully arrived; -1 between chunks. Opening the length block consumes it from the window,
    // so the length has to survive the next transport read here.
    private int _pendingLength = -1;

    private byte[]? _receivePlain;
    private int _plainOffset;
    private int _plainCount;

    private bool _readEof;
    private bool _readFaulted;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="innerStream"/> in the Shadowsocks AEAD framing.
    /// </summary>
    /// <param name="innerStream">The transport, positioned before the first byte of either direction.</param>
    /// <param name="method">The cipher.</param>
    /// <param name="masterKey">The master key (<see cref="ShadowsocksCipher.DeriveMasterKey"/>); copied.</param>
    /// <param name="clientSalt">
    /// This side's salt, sent in front of the first chunk. Callers pass a fresh random salt
    /// (<see cref="ShadowsocksCipher.FillSalt"/>); tests pass a fixed one.
    /// </param>
    /// <param name="leaveInnerOpen">When <c>true</c>, disposing this stream does not dispose the transport.</param>
    /// <exception cref="ArgumentNullException"><paramref name="innerStream"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">The key or salt is not the method's key size.</exception>
    /// <exception cref="NotSupportedException">The platform does not provide the cipher.</exception>
    public ShadowsocksStream(
        Stream innerStream,
        ShadowsocksMethod method,
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> clientSalt,
        bool leaveInnerOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);

        int keySize = ShadowsocksCipher.KeySize(method);
        if (masterKey.Length != keySize)
            throw new ArgumentException(
                $"Master key for {ShadowsocksCipher.Name(method)} must be exactly {keySize} bytes.", nameof(masterKey));
        if (clientSalt.Length != keySize)
            throw new ArgumentException(
                $"Salt for {ShadowsocksCipher.Name(method)} must be exactly {keySize} bytes.", nameof(clientSalt));

        ShadowsocksCipher.EnsurePlatformSupport(method);

        _inner = innerStream;
        _leaveInnerOpen = leaveInnerOpen;
        _method = method;
        _saltSize = keySize;
        _masterKey = masterKey.ToArray();

        Span<byte> pendingSalt = _pendingSalt;
        clientSalt.CopyTo(pendingSalt);
        _pendingSaltLength = keySize;

        Span<byte> subkey = stackalloc byte[ShadowsocksCipher.MaxKeySize];
        subkey = subkey.Slice(0, keySize);
        try
        {
            ShadowsocksCipher.DeriveSubkey(masterKey, clientSalt, subkey);
            _writer = new Direction(method, subkey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_masterKey);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
        }
    }

    /// <summary>
    /// The write nonce as a counter (its low 64 bits): the number of AEAD operations performed
    /// so far in that direction, two per chunk.
    /// </summary>
    public ulong WriteNonceCounter => _writer.Counter;

    /// <summary>
    /// The read nonce as a counter (its low 64 bits): the number of AEAD operations performed
    /// so far in that direction, two per chunk. Zero until the server salt has been read.
    /// </summary>
    public ulong ReadNonceCounter => _reader?.Counter ?? 0;

    /// <summary>Whether the server salt has been read and the read direction keyed.</summary>
    public bool IsServerSaltRead => _reader is not null;

    /// <summary>Whether the peer closed its direction cleanly, at a chunk boundary.</summary>
    public bool IsReadCompleted => _readEof;

    /// <summary>
    /// Whether an earlier read hit truncation, an oversized length or a failed tag. Once set,
    /// every further read throws; the stream never reports a clean end after a failure.
    /// </summary>
    public bool IsReadFaulted => _readFaulted;

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed;
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
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // A truncation or a failed tag is final. Without this latch a caller that swallows the
        // first exception and reads again would find the transport already at FIN and get a 0 —
        // truncation reported as a clean end of stream, which is exactly what must never happen.
        if (_readFaulted)
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                "The Shadowsocks read direction failed earlier and cannot continue.");

        if (_plainCount > 0)
            return CopyLeftover(buffer);

        if (buffer.IsEmpty || _readEof)
            return 0;

        try
        {
            while (true)
            {
                // What the window must hold before the next step can run: the salt, then a
                // length block, then the payload and tag of the chunk whose length is known.
                int available = _end - _start;
                int need = _reader is null ? _saltSize
                    : _pendingLength < 0 ? LengthBlockSize
                    : _pendingLength + TagSize;

                if (available >= need)
                {
                    if (_reader is null)
                    {
                        KeyReader();
                        continue;
                    }

                    if (_pendingLength < 0)
                    {
                        _pendingLength = OpenLength();
                        continue;
                    }

                    int plaintextLength = _pendingLength;
                    _pendingLength = -1;

                    if (plaintextLength == 0)
                    {
                        // Legal on the wire and carrying nothing. It must still be opened — that
                        // checks its tag and advances the nonce — and it must NOT be reported as end
                        // of stream: 0 from Read means the peer closed, and it has not.
                        OpenPayload(0, Memory<byte>.Empty);
                        continue;
                    }

                    // Fast path: the caller's buffer can hold the whole chunk, so the AEAD writes
                    // the plaintext straight into it.
                    if (buffer.Length >= plaintextLength)
                    {
                        OpenPayload(plaintextLength, buffer.Slice(0, plaintextLength));
                        return plaintextLength;
                    }

                    EnsurePlainCapacity(plaintextLength);
                    OpenPayload(plaintextLength, _receivePlain.AsMemory(0, plaintextLength));
                    _plainOffset = 0;
                    _plainCount = plaintextLength;
                    return CopyLeftover(buffer);
                }

                int read = await _inner.ReadAsync(FreeSpace(need - available), cancellationToken);
                if (read == 0)
                {
                    if (_reader is null)
                        throw SaltTruncated(available);

                    if (_pendingLength >= 0)
                        throw Truncated($"inside a chunk whose payload is {_pendingLength} bytes plus a {TagSize}-byte tag");

                    if (available == 0)
                    {
                        // A FIN exactly at a chunk boundary: the one clean end of stream.
                        _readEof = true;
                        return 0;
                    }

                    throw Truncated($"{available} bytes into the {LengthBlockSize}-byte length block of a chunk");
                }

                _end += read;
            }
        }
        catch (ProxyProtocolException)
        {
            _readFaulted = true;
            throw;
        }
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

    private int CopyLeftover(Memory<byte> buffer)
    {
        int count = Math.Min(buffer.Length, _plainCount);
        _receivePlain!.AsMemory(_plainOffset, count).CopyTo(buffer);
        _plainOffset += count;
        _plainCount -= count;
        return count;
    }

    // The free tail of the receive buffer for the next transport read, which takes whatever
    // arrives. The window is moved to the front only when `missing` more bytes would not fit
    // behind it; a compacted buffer always holds a whole chunk, so this happens at most once per
    // chunk and never for the salt or a length block alone.
    private Memory<byte> FreeSpace(int missing)
    {
        byte[] buffer = _receiveBuffer ??= ArrayPool<byte>.Shared.Rent(MaxWireChunkSize);

        if (_start == _end)
        {
            _start = 0;
            _end = 0;
        }
        else if (buffer.Length - _end < missing)
        {
            buffer.AsSpan(_start, _end - _start).CopyTo(buffer);
            _end -= _start;
            _start = 0;
        }

        return buffer.AsMemory(_end);
    }

    // Keys the read direction from the salt at the front of the window and consumes it. A server
    // that cannot open the first chunk sends nothing at all, so a FIN before this is how a wrong
    // password looks — and also how a dead target looks; the two are indistinguishable by design
    // of the protocol.
    private void KeyReader()
    {
        _reader = CreateReader(_receiveBuffer!.AsSpan(_start, _saltSize));
        _start += _saltSize;
    }

    // Split out so the subkey can live on the stack: stackalloc is not allowed in an async method.
    private Direction CreateReader(ReadOnlySpan<byte> serverSalt)
    {
        byte[] masterKey = _masterKey
            ?? throw new InvalidOperationException("The Shadowsocks master key is no longer available.");

        Span<byte> subkey = stackalloc byte[ShadowsocksCipher.MaxKeySize];
        subkey = subkey.Slice(0, _saltSize);
        try
        {
            ShadowsocksCipher.DeriveSubkey(masterKey, serverSalt, subkey);
            return new Direction(_method, subkey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            // Both subkeys exist now; the master key has done its work.
            CryptographicOperations.ZeroMemory(masterKey);
            _masterKey = null;
        }
    }

    private ProxyProtocolException SaltTruncated(int got) =>
        new(ProxyErrorCode.ConnectionFailed,
            got == 0
                ? "The Shadowsocks server closed the connection without sending its salt. A server that " +
                  "cannot open the first chunk sends nothing, so a wrong password or cipher looks exactly like " +
                  "a target the server could not reach."
                : $"The Shadowsocks server closed the connection {got} bytes into its {_saltSize}-byte salt.",
            new EndOfStreamException());

    // Opens the sealed length block at the front of the window, validates the cap and consumes
    // the block.
    private int OpenLength()
    {
        byte[] buffer = _receiveBuffer!;
        Span<byte> length = stackalloc byte[LengthSize];
        try
        {
            _reader!.Open(buffer.AsSpan(_start, LengthSize), buffer.AsSpan(_start + LengthSize, TagSize), length);
        }
        catch (CryptographicException ex)
        {
            throw BadTag("length block", ex);
        }

        _start += LengthBlockSize;

        int plaintextLength = BinaryPrimitives.ReadUInt16BigEndian(length);
        if (plaintextLength > MaxPayloadSize)
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                $"Shadowsocks chunk length 0x{plaintextLength:X4} ({plaintextLength}) exceeds the protocol maximum " +
                $"0x{MaxPayloadSize:X4} ({MaxPayloadSize}): the two reserved high bits are set. The chunk is " +
                $"rejected rather than masked to {plaintextLength & MaxPayloadSize}, because a masked length " +
                "silently desynchronises the stream.");

        return plaintextLength;
    }

    // Opens the sealed payload and tag at the front of the window into `plaintext`, which must
    // be exactly plaintextLength bytes (possibly empty), and consumes them.
    private void OpenPayload(int plaintextLength, Memory<byte> plaintext)
    {
        byte[] buffer = _receiveBuffer!;
        try
        {
            _reader!.Open(
                buffer.AsSpan(_start, plaintextLength),
                buffer.AsSpan(_start + plaintextLength, TagSize),
                plaintext.Span);
        }
        catch (CryptographicException ex)
        {
            throw BadTag("payload", ex);
        }

        _start += plaintextLength + TagSize;
    }

    private static ProxyProtocolException BadTag(string what, CryptographicException inner) =>
        // The nonce has already advanced, so nothing after this chunk can be opened either.
        new(ProxyErrorCode.InvalidResponse,
            $"A Shadowsocks chunk {what} failed authentication: it was not sealed with this session's key or was " +
            "altered in transit. The stream cannot continue.", inner);

    private static ProxyProtocolException Truncated(string where) =>
        new(ProxyErrorCode.InvalidResponse,
            $"The Shadowsocks stream ended {where}. Only a close exactly at a chunk boundary is a clean end of " +
            "stream; this is truncation.", new EndOfStreamException());

    // The leftover buffer is only needed when the caller's buffer is smaller than the incoming
    // chunk; large-buffer readers never rent it.
    [System.Diagnostics.CodeAnalysis.MemberNotNull(nameof(_receivePlain))]
    private void EnsurePlainCapacity(int plaintextLength)
    {
        if (_receivePlain is null)
            _receivePlain = ArrayPool<byte>.Shared.Rent(Math.Max(plaintextLength, 4096));
        else if (_receivePlain.Length < plaintextLength)
        {
            ArrayPool<byte>.Shared.Return(_receivePlain, clearArray: true);
            _receivePlain = ArrayPool<byte>.Shared.Rent(plaintextLength);
        }
    }

    // ================================ writing ================================

    /// <inheritdoc/>
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder))]
    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (!buffer.IsEmpty)
        {
            int length = SealRun(buffer.Span, out int consumed);
            buffer = buffer.Slice(consumed);
            await _inner.WriteAsync(_sendBuffer!.AsMemory(0, length), cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override Task WriteAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (!buffer.IsEmpty)
        {
            int length = SealRun(buffer, out int consumed);
            buffer = buffer.Slice(consumed);
            _inner.Write(_sendBuffer!.AsSpan(0, length));
        }
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    /// <summary>
    /// Seals <paramref name="payload"/> as exactly one chunk and writes it, prefixed with this
    /// side's salt if that has not been sent yet. An empty payload produces an empty chunk —
    /// legal on the wire, and the one case <see cref="WriteAsync(ReadOnlyMemory{byte},CancellationToken)"/>
    /// never emits.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="payload"/> exceeds <see cref="MaxPayloadSize"/>.</exception>
    public async ValueTask WriteChunkAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (payload.Length > MaxPayloadSize)
            throw new ArgumentOutOfRangeException(nameof(payload), payload.Length,
                $"A Shadowsocks chunk carries at most {MaxPayloadSize} bytes.");

        // At most one chunk's worth, so the run is exactly one chunk — an empty one for an empty payload.
        int length = SealRun(payload.Span, out _);
        await _inner.WriteAsync(_sendBuffer!.AsMemory(0, length), cancellationToken);
    }

    // Frames and seals a run into _sendBuffer: the salt first if still pending, then consecutive
    // chunks of `payload` (each at most MaxPayloadSize) for as long as the next one fits. Returns
    // the wire length and reports how much of `payload` went in. The buffer always holds the salt
    // plus one full chunk, so a run is never empty: an empty payload seals one empty chunk.
    private int SealRun(ReadOnlySpan<byte> payload, out int consumed)
    {
        byte[] buffer = EnsureSendBuffer(payload.Length);

        int offset = 0;
        if (_pendingSaltLength > 0)
        {
            // In the same buffer as the first chunk, so salt and header leave in one write.
            Span<byte> salt = _pendingSalt;
            salt.Slice(0, _pendingSaltLength).CopyTo(buffer);
            offset = _pendingSaltLength;
            _pendingSaltLength = 0;
        }

        consumed = 0;
        do
        {
            int count = Math.Min(payload.Length - consumed, MaxPayloadSize);
            if (offset + LengthBlockSize + count + TagSize > buffer.Length)
                break;

            offset = SealChunk(payload.Slice(consumed, count), buffer, offset);
            consumed += count;
        }
        while (consumed < payload.Length);

        return offset;
    }

    // Seals one chunk of `plaintext` at `offset` and returns the offset after it.
    private int SealChunk(ReadOnlySpan<byte> plaintext, byte[] buffer, int offset)
    {
        Span<byte> length = stackalloc byte[LengthSize];
        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)plaintext.Length);
        _writer.Seal(length, buffer.AsSpan(offset, LengthSize), buffer.AsSpan(offset + LengthSize, TagSize));
        offset += LengthBlockSize;

        _writer.Seal(plaintext, buffer.AsSpan(offset, plaintext.Length), buffer.AsSpan(offset + plaintext.Length, TagSize));
        return offset + plaintext.Length + TagSize;
    }

    // The small buffer serves every Write of at most one chunk; the first Write that spans more
    // than one chunk trades it for the large one, and a tunnel that never writes that much never
    // touches the larger bucket.
    private byte[] EnsureSendBuffer(int payloadLength)
    {
        int size = payloadLength > MaxPayloadSize ? LargeSendBufferSize : SmallSendBufferSize;
        byte[]? buffer = _sendBuffer;
        if (buffer is null || buffer.Length < size)
        {
            if (buffer is not null)
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            buffer = _sendBuffer = ArrayPool<byte>.Shared.Rent(size);
        }

        return buffer;
    }

    // ================================ disposal ================================

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;
        try
        {
            // Transport first: a read still in flight on another thread targets these buffers,
            // and closing the transport is what faults it.
            if (!_leaveInnerOpen)
                await _inner.DisposeAsync();
        }
        finally
        {
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

        _disposed = true;
        if (disposing)
        {
            try
            {
                if (!_leaveInnerOpen)
                    _inner.Dispose();
            }
            finally
            {
                ReleaseResources();
            }
        }

        base.Dispose(disposing);
    }

    private void ReleaseResources()
    {
        _writer.Dispose();
        _reader?.Dispose();
        _reader = null;

        if (_masterKey is not null)
        {
            CryptographicOperations.ZeroMemory(_masterKey);
            _masterKey = null;
        }

        Span<byte> pendingSalt = _pendingSalt;
        pendingSalt.Clear();
        _pendingSaltLength = 0;

        if (_sendBuffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_sendBuffer, clearArray: true);
            _sendBuffer = null;
        }

        if (_receiveBuffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_receiveBuffer, clearArray: true);
            _receiveBuffer = null;
        }

        if (_receivePlain is not null)
        {
            ArrayPool<byte>.Shared.Return(_receivePlain, clearArray: true);
            _receivePlain = null;
        }

        _start = 0;
        _end = 0;
        _pendingLength = -1;
        _plainOffset = 0;
        _plainCount = 0;
    }

    // ================================ one direction ================================

    /// <summary>Inline storage for a salt of up to <see cref="ShadowsocksCipher.MaxKeySize"/> bytes.</summary>
    [InlineArray(ShadowsocksCipher.MaxKeySize)]
    private struct SaltBuffer
    {
        private byte _element0;
    }

    /// <summary>
    /// One direction of the stream: the AEAD instance keyed with that direction's subkey plus
    /// its 12-byte little-endian counting nonce.
    /// </summary>
    private sealed class Direction : IDisposable
    {
        private readonly byte[] _nonce = new byte[ShadowsocksCipher.NonceSize];
        private readonly AesGcm? _aes;
        private readonly ChaCha20Poly1305? _chacha;

        public Direction(ShadowsocksMethod method, ReadOnlySpan<byte> subkey)
        {
            if (method == ShadowsocksMethod.ChaCha20Poly1305)
                _chacha = new ChaCha20Poly1305(subkey);
            else
                _aes = new AesGcm(subkey, ShadowsocksCipher.TagSize);
        }

        /// <summary>The low 64 bits of the nonce, i.e. the operations performed so far.</summary>
        public ulong Counter => BinaryPrimitives.ReadUInt64LittleEndian(_nonce);

        public void Seal(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag)
        {
            if (_aes is not null)
                _aes.Encrypt(_nonce, plaintext, ciphertext, tag);
            else
                _chacha!.Encrypt(_nonce, plaintext, ciphertext, tag);
            Increment();
        }

        public void Open(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
        {
            // Advance even when the open fails: the spec counts operations, not successes, and a
            // failed tag ends the stream anyway.
            try
            {
                if (_aes is not null)
                    _aes.Decrypt(_nonce, ciphertext, tag, plaintext);
                else
                    _chacha!.Decrypt(_nonce, ciphertext, tag, plaintext);
            }
            finally
            {
                Increment();
            }
        }

        // The nonce "is incremented by one as if it were an unsigned little-endian integer".
        private void Increment()
        {
            for (int i = 0; i < _nonce.Length; i++)
            {
                if (++_nonce[i] != 0)
                    return;
            }
        }

        public void Dispose()
        {
            _aes?.Dispose();
            _chacha?.Dispose();
            CryptographicOperations.ZeroMemory(_nonce);
        }
    }
}
