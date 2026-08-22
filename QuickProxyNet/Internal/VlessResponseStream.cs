namespace QuickProxyNet;

/// <summary>
/// A pass-through stream that consumes and validates the VLESS server response header
/// (<c>ver(1) + addonsLen(1) + addons(var)</c>) <b>lazily</b>, on the first read, and then
/// forwards every operation to the transport unchanged.
/// </summary>
/// <remarks>
/// <para>
/// This is the VLESS counterpart of <see cref="VmessResponseStream"/>, and it exists for the
/// same reason: <b>neither Xray-core nor sing-box flushes the VLESS response header until the
/// target has produced its first bytes.</b> Both write it into a buffered writer that is only
/// unbuffered once data comes back from the target. Reading it eagerly inside
/// <c>ConnectAsync</c> therefore deadlocks against every client-speaks-first protocol — HTTP,
/// TLS, the Minecraft handshake — because the client waits for a header the server will not
/// send until the client's request has reached the target, and the client cannot send that
/// request until <c>ConnectAsync</c> returns.
/// </para>
/// <para>
/// This was measured, not assumed: a raw probe that writes the VLESS request and then reads
/// two bytes hangs against both servers, while one that writes the request and an HTTP GET
/// together gets <c>00 00</c> followed immediately by the HTTP response.
/// </para>
/// <para>
/// The tradeoff is that a rejected handshake (wrong user id — both servers simply drop the
/// connection) surfaces on the first <c>Read</c> rather than from <c>ConnectAsync</c>. That is
/// inherent to VLESS, not a consequence of this design: the server sends nothing at connect
/// time either way, so there is no failure to observe earlier.
/// </para>
/// </remarks>
internal sealed class VlessResponseStream : Stream
{
    private const byte Version = 0x00;

    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly string _host;
    private readonly int _port;

    private bool _headerRead;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="innerStream"/>, which must be positioned at the start of the
    /// server response header.
    /// </summary>
    /// <param name="innerStream">The transport (the raw stream or the TLS session).</param>
    /// <param name="host">Target host, used only to build a useful error message.</param>
    /// <param name="port">Target port, used only to build a useful error message.</param>
    /// <param name="leaveInnerOpen">When <c>true</c>, disposing this stream leaves the transport open.</param>
    /// <exception cref="ArgumentNullException"><paramref name="innerStream"/> is <c>null</c>.</exception>
    public VlessResponseStream(Stream innerStream, string host, int port, bool leaveInnerOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);

        _inner = innerStream;
        _host = host;
        _port = port;
        _leaveInnerOpen = leaveInnerOpen;
    }

    /// <summary>Whether the response header has already been read and validated.</summary>
    public bool IsHeaderRead => _headerRead;

    /// <summary>
    /// Reads and validates the response header if that has not happened yet. Callers that want
    /// handshake failures reported before the first payload read can await this explicitly —
    /// at the cost of the deadlock described on the class.
    /// </summary>
    /// <exception cref="ProxyProtocolException">
    /// The version byte is not <c>0x00</c>, or the server closed the connection before
    /// completing the handshake.
    /// </exception>
    public async ValueTask ReadHeaderAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_headerRead)
            return;

        // ver(1) + addonsLen(1). Small and short-lived, and — unlike the request header —
        // it carries no credential material, so there is nothing to pool or to clear.
        byte[] header = new byte[2];
        try
        {
            await _inner.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

            if (header[0] != Version)
                throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                    $"Unexpected VLESS response version. Expected 0x00, got 0x{header[0]:X2}.");

            // addonsLen is a single byte. The content is unused for plain TCP; draining it
            // positions the stream at the target's first response byte.
            int addonsLength = header[1];
            if (addonsLength > 0)
            {
                byte[] addons = new byte[addonsLength];
                await _inner.ReadExactlyAsync(addons, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (EndOfStreamException ex)
        {
            // A short/closed response is the primary VLESS failure signal (e.g. wrong UUID:
            // both Xray and sing-box just drop the connection). Surface it like the HTTP path.
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"VLESS server closed the connection before completing the handshake for {_host}:{_port} (wrong UUID or rejected request?).",
                ex);
        }

        _headerRead = true;
    }

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

        if (!_headerRead)
            await ReadHeaderAsync(cancellationToken).ConfigureAwait(false);

        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_headerRead)
            ReadHeaderAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();

        return _inner.Read(buffer);
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    // ================================ writing ================================

    /// <inheritdoc/>
    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inner.WriteAsync(buffer, cancellationToken);
    }

    /// <inheritdoc/>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc/>
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _inner.Write(buffer);
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    // ================================ disposal ================================

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;
        if (!_leaveInnerOpen)
            await _inner.DisposeAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing && !_leaveInnerOpen)
            _inner.Dispose();

        _disposed = true;
        base.Dispose(disposing);
    }
}
