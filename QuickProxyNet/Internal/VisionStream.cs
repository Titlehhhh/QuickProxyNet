using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The <c>xtls-rprx-vision</c> framing that sits between the VLESS response header and the
/// payload: a stream that strips the server's padding frames and pads its own first write.
/// </summary>
/// <remarks>
/// <para>
/// A server whose user is configured with <c>flow=xtls-rprx-vision</c> does not answer in plain
/// VLESS. After the two-byte response header it sends the user's UUID once, then a run of
/// frames — <c>command(1) + contentLen(2) + paddingLen(2)</c>, content, padding — until a frame
/// arrives with the <i>end</i> command, after which the connection is raw. Reading such a stream
/// as if it were plain VLESS appears to work: the first response usually still contains a
/// recognisable <c>HTTP/1.1 200</c> a few bytes in. It is the reads after it that are quietly
/// corrupted, which is exactly the failure that looks like a server problem.
/// </para>
/// <para>
/// <b>What this implements and what it does not.</b> The padding protocol, in both directions.
/// Not the other half of Vision — the TLS-in-TLS detection that lets Xray splice a connection
/// into a raw copy after a few packets. That is a throughput optimisation with no effect on the
/// wire format either peer must accept, and leaving it out costs nothing but the optimisation.
/// </para>
/// <para>
/// The uplink is padded once, with the <i>end</i> command, and then runs raw. The server's
/// unpadding is driven by whether the first sixteen bytes it receives are the user's UUID, so a
/// single closing frame is a complete, legal conversation. Xray keeps padding for a few packets
/// while it decides whether it is carrying TLS; since this stream never claims to do the
/// splicing that decision feeds, the extra frames would be padding for its own sake.
/// </para>
/// </remarks>
internal sealed class VisionStream : Stream
{
    /// <summary>The flow identifier this stream implements. Any other flow is not this class's.</summary>
    public const string FlowName = "xtls-rprx-vision";

    private const int UuidSize = 16;
    private const int HeaderSize = 5;

    private const byte CommandPaddingContinue = 0x00;
    private const byte CommandPaddingEnd = 0x01;

    /// <summary>
    /// "Stop padding, the rest of this connection is a direct copy." Xray sends it instead of
    /// <see cref="CommandPaddingEnd"/> once it has decided the connection carries TLS, and real
    /// servers reach that decision far more often than they send the end command — a client that
    /// only honours <c>end</c> stays in framed mode forever and dies on the next header.
    /// </summary>
    private const byte CommandPaddingDirect = 0x02;

    /// <summary>Xray's <c>buf.Size</c>, which bounds one padded frame.</summary>
    private const int MaxFrame = 8192;

    /// <summary>
    /// Consecutive frames carrying padding and no content before the stream is declared
    /// broken. Xray sends one or two; a peer sending them without end would otherwise keep a
    /// read from ever returning.
    /// </summary>
    private const int MaxPaddingOnlyFrames = 64;

    private enum Mode
    {
        /// <summary>Nothing read yet: the leading UUID decides whether this stream is framed.</summary>
        Undecided,

        /// <summary>Inside the padded frames.</summary>
        Framed,

        /// <summary>Past the closing frame — everything from here is payload.</summary>
        Raw
    }

    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly byte[] _uuid;

    private byte[] _buffer;
    private int _start;
    private int _end;

    private Mode _mode = Mode.Undecided;
    private byte _command = CommandPaddingContinue;
    private int _remainingContent;
    private int _remainingPadding;
    private int _paddingOnlyFrames;

    private bool _uplinkPadded;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="innerStream"/>, which must be positioned where the payload would
    /// begin in a plain VLESS session — that is, after the response header.
    /// </summary>
    /// <param name="innerStream">The VLESS session.</param>
    /// <param name="uuid">The user id, big-endian, as it went out in the request header.</param>
    /// <param name="leaveInnerOpen">When <c>true</c>, disposing this stream leaves the session open.</param>
    public VisionStream(Stream innerStream, ReadOnlySpan<byte> uuid, bool leaveInnerOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);

        if (uuid.Length != UuidSize)
            throw new ArgumentException($"A VLESS user id is {UuidSize} bytes.", nameof(uuid));

        _inner = innerStream;
        _uuid = uuid.ToArray();
        _leaveInnerOpen = leaveInnerOpen;
        _buffer = ArrayPool<byte>.Shared.Rent(MaxFrame);
    }

    private int Buffered => _end - _start;

    public override bool CanRead => !_disposed && _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed && _inner.CanWrite;
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

        if (buffer.IsEmpty)
            return 0;

        while (true)
        {
            // Anything already unpadded and waiting is returned before touching the transport.
            if (_mode == Mode.Raw)
                return Buffered > 0 ? DrainInto(buffer.Span) : await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

            if (_mode == Mode.Undecided)
            {
                // Decide from as few bytes as settle it. A full first frame header is needed to
                // enter framed mode, but one byte that is not the UUID is enough to know the
                // server is not framing — and waiting for 21 bytes from a server that sent a
                // 5-byte greeting and is now waiting for us would be a deadlock.
                while (!TryDecideMode())
                {
                    if (await FillSomeAsync(cancellationToken).ConfigureAwait(false) == 0)
                    {
                        _mode = Mode.Raw; // ended before a frame could exist: whatever came is payload
                        break;
                    }
                }

                continue;
            }

            if (_remainingContent == 0 && _remainingPadding == 0)
            {
                if (EndsFraming(_command))
                {
                    _mode = Mode.Raw;
                    continue;
                }

                await FillAsync(HeaderSize, throwOnEof: false, cancellationToken).ConfigureAwait(false);
                if (Buffered == 0)
                    return 0; // a clean close on a frame boundary is the end of the stream

                if (Buffered < HeaderSize)
                    throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame header, mid-response.");

                ReadFrameHeader();
                continue;
            }

            if (Buffered == 0 && await FillSomeAsync(cancellationToken).ConfigureAwait(false) == 0)
                throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame, mid-response.");

            if (_remainingContent > 0)
            {
                int taken = Math.Min(Math.Min(_remainingContent, Buffered), buffer.Length);
                _buffer.AsSpan(_start, taken).CopyTo(buffer.Span);
                _start += taken;
                _remainingContent -= taken;
                return taken;
            }

            int skipped = Math.Min(_remainingPadding, Buffered);
            _start += skipped;
            _remainingPadding -= skipped;
        }
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
            return 0;

        while (true)
        {
            if (_mode == Mode.Raw)
                return Buffered > 0 ? DrainInto(buffer) : _inner.Read(buffer);

            if (_mode == Mode.Undecided)
            {
                while (!TryDecideMode())
                {
                    if (FillSome() == 0)
                    {
                        _mode = Mode.Raw;
                        break;
                    }
                }

                continue;
            }

            if (_remainingContent == 0 && _remainingPadding == 0)
            {
                if (EndsFraming(_command))
                {
                    _mode = Mode.Raw;
                    continue;
                }

                Fill(HeaderSize, throwOnEof: false);
                if (Buffered == 0)
                    return 0;

                if (Buffered < HeaderSize)
                    throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame header, mid-response.");

                ReadFrameHeader();
                continue;
            }

            if (Buffered == 0 && FillSome() == 0)
                throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame, mid-response.");

            if (_remainingContent > 0)
            {
                int taken = Math.Min(Math.Min(_remainingContent, Buffered), buffer.Length);
                _buffer.AsSpan(_start, taken).CopyTo(buffer);
                _start += taken;
                _remainingContent -= taken;
                return taken;
            }

            int skipped = Math.Min(_remainingPadding, Buffered);
            _start += skipped;
            _remainingPadding -= skipped;
        }
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    /// <summary>
    /// Tries to decide, from the bytes buffered so far, whether the peer is speaking Vision
    /// framing. Returns false when more bytes are needed to tell.
    /// </summary>
    private bool TryDecideMode()
    {
        int compared = Math.Min(Buffered, UuidSize);
        if (compared > 0 && !_buffer.AsSpan(_start, compared).SequenceEqual(_uuid.AsSpan(0, compared)))
        {
            // Not our UUID — the server answered in plain VLESS despite the flow, which is what
            // a non-Vision server does. Everything buffered is payload, and nothing more needs
            // to arrive to know that.
            _mode = Mode.Raw;
            return true;
        }

        if (Buffered < UuidSize + HeaderSize)
            return false; // the UUID matches so far; framed mode needs the whole first header

        _start += UuidSize;
        _mode = Mode.Framed;
        return true;
    }

    /// <summary>Whether <paramref name="command"/> was the last framed packet.</summary>
    private static bool EndsFraming(byte command) =>
        command is CommandPaddingEnd or CommandPaddingDirect;

    private void ReadFrameHeader()
    {
        ReadOnlySpan<byte> header = _buffer.AsSpan(_start, HeaderSize);
        _command = header[0];
        _remainingContent = BinaryPrimitives.ReadUInt16BigEndian(header[1..]);
        _remainingPadding = BinaryPrimitives.ReadUInt16BigEndian(header[3..]);
        _start += HeaderSize;

        if (_remainingContent > 0)
            _paddingOnlyFrames = 0;
        else if (++_paddingOnlyFrames > MaxPaddingOnlyFrames)
            throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                $"The VLESS server sent {MaxPaddingOnlyFrames} consecutive xtls-rprx-vision frames with no content.");
    }

    private int DrainInto(Span<byte> destination)
    {
        int taken = Math.Min(Buffered, destination.Length);
        _buffer.AsSpan(_start, taken).CopyTo(destination);
        _start += taken;
        return taken;
    }

    /// <summary>Buffers at least <paramref name="count"/> bytes, compacting first if needed.</summary>
    private async ValueTask FillAsync(int count, bool throwOnEof, CancellationToken cancellationToken)
    {
        Compact(count);

        while (Buffered < count)
        {
            int read = await _inner.ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                if (throwOnEof)
                    throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame header, mid-response.");
                return;
            }

            _end += read;
        }
    }

    private void Fill(int count, bool throwOnEof)
    {
        Compact(count);

        while (Buffered < count)
        {
            int read = _inner.Read(_buffer.AsSpan(_end));
            if (read == 0)
            {
                if (throwOnEof)
                    throw new EndOfStreamException("The VLESS server closed the connection inside an xtls-rprx-vision frame header, mid-response.");
                return;
            }

            _end += read;
        }
    }

    private async ValueTask<int> FillSomeAsync(CancellationToken cancellationToken)
    {
        Compact(1);
        int read = await _inner.ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), cancellationToken)
            .ConfigureAwait(false);
        _end += read;
        return read;
    }

    private int FillSome()
    {
        Compact(1);
        int read = _inner.Read(_buffer.AsSpan(_end));
        _end += read;
        return read;
    }

    /// <summary>Moves what is buffered to the front when <paramref name="count"/> would not fit.</summary>
    private void Compact(int count)
    {
        ObjectDisposedException.ThrowIf(_buffer.Length == 0, this);

        if (_start == _end)
        {
            _start = _end = 0;
            return;
        }

        if (_end + count <= _buffer.Length)
            return;

        _buffer.AsSpan(_start, Buffered).CopyTo(_buffer);
        _end -= _start;
        _start = 0;
    }

    // ================================ writing ================================

    /// <inheritdoc/>
    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_uplinkPadded)
        {
            _uplinkPadded = true;
            if (TryRentPaddedFrame(buffer.Span, out byte[]? frame, out int length))
            {
                try
                {
                    await _inner.WriteAsync(frame.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(frame, clearArray: true); // the caller's first packet
                }

                return;
            }
        }

        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_uplinkPadded)
        {
            _uplinkPadded = true;
            if (TryRentPaddedFrame(buffer, out byte[]? frame, out int length))
            {
                try
                {
                    _inner.Write(frame.AsSpan(0, length));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(frame, clearArray: true); // the caller's first packet
                }

                return;
            }
        }

        _inner.Write(buffer);
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    /// <summary>
    /// Builds the single closing frame the uplink sends: <c>uuid + end-command header + content
    /// + padding</c>. Returns false for content too large to frame, which then goes out raw —
    /// legal, because the server only enters framed mode if the first bytes are the UUID.
    /// </summary>
    private bool TryRentPaddedFrame(ReadOnlySpan<byte> content, out byte[] frame, out int length)
    {
        frame = null!;
        length = 0;

        int overhead = UuidSize + HeaderSize;
        if (content.Length > MaxFrame - overhead)
            return false;

        int padding = PaddingLength(content.Length);
        length = overhead + content.Length + padding;

        frame = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> span = frame.AsSpan(0, length);

        _uuid.CopyTo(span);
        span[UuidSize] = CommandPaddingEnd;
        BinaryPrimitives.WriteUInt16BigEndian(span[(UuidSize + 1)..], (ushort)content.Length);
        BinaryPrimitives.WriteUInt16BigEndian(span[(UuidSize + 3)..], (ushort)padding);
        content.CopyTo(span[overhead..]);
        span[(overhead + content.Length)..].Clear();

        return true;
    }

    /// <summary>
    /// Xray's rule: pad a short packet out past 900 bytes, and give a long one a small random
    /// tail. The point is to blur the length of the first records, so the number has to be
    /// unpredictable — hence the cryptographic RNG rather than <see cref="Random"/>.
    /// </summary>
    private static int PaddingLength(int contentLength)
    {
        int padding = contentLength < 900
            ? RandomNumberGenerator.GetInt32(500) + 900 - contentLength
            : RandomNumberGenerator.GetInt32(256);

        return Math.Min(padding, MaxFrame - UuidSize - HeaderSize - contentLength);
    }

    // ================================ disposal ================================

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;

        // Transport first, buffer second: a ReadAsync still in flight on another thread is
        // reading into _buffer, and closing the transport is what ends it. Returned first, the
        // array could be re-rented and written into by that late completion.
        if (!_leaveInnerOpen)
            await _inner.DisposeAsync().ConfigureAwait(false);
        ReturnBuffer();

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            if (!_leaveInnerOpen)
                _inner.Dispose();
            ReturnBuffer();
        }

        _disposed = true;
        base.Dispose(disposing);
    }

    private void ReturnBuffer()
    {
        byte[] buffer = _buffer;
        _buffer = [];

        // Cleared: this held decrypted tunnel payload, and the pool hands the array to whoever
        // rents next.
        if (buffer.Length > 0)
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
    }
}
