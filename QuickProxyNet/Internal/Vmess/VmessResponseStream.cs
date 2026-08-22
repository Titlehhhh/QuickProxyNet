using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// A pass-through stream that consumes and verifies the VMessAEAD server response header
/// (<see cref="VmessResponse"/>) <b>lazily</b>, on the first read, and then forwards every
/// operation to the transport unchanged.
/// </summary>
/// <remarks>
/// <para>
/// This shim exists because of when a real VMess server flushes its response header.
/// v2ray-core and Xray-core write it into a <c>buf.NewBufferedWriter</c> and only flush
/// after the <em>target</em> has produced its first bytes (the "optimize for small
/// response packet" read in <c>proxy/vmess/inbound</c> blocks before
/// <c>writer.SetBuffered(false)</c>). Reading the header eagerly inside
/// <c>ConnectAsync</c> would therefore deadlock against any client-speaks-first protocol
/// — HTTP, TLS, the Minecraft handshake — because the client would be blocked waiting for
/// a header the server will not send until the client's request reaches the target.
/// </para>
/// <para>
/// Placing the header read here instead of inside <see cref="VmessStream"/> keeps the body
/// framing and the response header as separate, separately testable layers: the transport
/// is wrapped as <c>transport → VmessResponseStream → VmessStream</c>, so the first chunk
/// read that <see cref="VmessStream"/> performs transparently pulls the header first.
/// </para>
/// <para>
/// The tradeoff is that a rejected handshake (wrong user id, a tampered response, a
/// response verifier mismatch) surfaces on the first <c>Read</c> rather than from
/// <c>ConnectAsync</c>. That is inherent to VMess rather than a consequence of this
/// design: a server that rejects the AuthID simply stops responding, so there is no
/// failure to observe at connect time either way.
/// </para>
/// </remarks>
internal sealed class VmessResponseStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly byte _expectedResponseVerifier;

    private byte[]? _responseBodyKey;
    private byte[]? _responseBodyIv;
    private VmessResponseHeader _header;
    private bool _headerRead;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="innerStream"/>, which must be positioned at the start of the
    /// server response header.
    /// </summary>
    /// <param name="innerStream">The transport (the raw stream or the TLS session).</param>
    /// <param name="responseBodyKey">The 16-byte response body key (<see cref="VmessResponse.DeriveBodyKeys"/>).</param>
    /// <param name="responseBodyIv">The 16-byte response body IV.</param>
    /// <param name="expectedResponseVerifier">The verifier byte the server must echo back.</param>
    /// <param name="leaveInnerOpen">When <c>true</c>, disposing this stream leaves the transport open.</param>
    /// <exception cref="ArgumentNullException"><paramref name="innerStream"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">A key or IV is not exactly 16 bytes.</exception>
    public VmessResponseStream(
        Stream innerStream,
        ReadOnlySpan<byte> responseBodyKey,
        ReadOnlySpan<byte> responseBodyIv,
        byte expectedResponseVerifier,
        bool leaveInnerOpen = false)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        if (responseBodyKey.Length != VmessResponse.KeySize)
            throw new ArgumentException(
                $"Response body key must be exactly {VmessResponse.KeySize} bytes.", nameof(responseBodyKey));
        if (responseBodyIv.Length != VmessResponse.KeySize)
            throw new ArgumentException(
                $"Response body IV must be exactly {VmessResponse.KeySize} bytes.", nameof(responseBodyIv));

        _inner = innerStream;
        _leaveInnerOpen = leaveInnerOpen;
        _expectedResponseVerifier = expectedResponseVerifier;
        _responseBodyKey = responseBodyKey.ToArray();
        _responseBodyIv = responseBodyIv.ToArray();
    }

    /// <summary>Whether the response header has already been read and verified.</summary>
    public bool IsHeaderRead => _headerRead;

    /// <summary>
    /// The parsed response header. Only meaningful once <see cref="IsHeaderRead"/> is true.
    /// </summary>
    public VmessResponseHeader Header => _header;

    /// <summary>
    /// Reads and verifies the response header if that has not happened yet. Callers that
    /// want handshake failures reported before the first payload read can await this
    /// explicitly — at the cost of the deadlock described on the class.
    /// </summary>
    public async ValueTask<VmessResponseHeader> ReadHeaderAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_headerRead)
            return _header;

        byte[]? key = _responseBodyKey;
        byte[]? iv = _responseBodyIv;
        if (key is null || iv is null)
            throw new InvalidOperationException("The VMess response header keys are no longer available.");

        _header = await VmessResponse.ReadAsync(
            _inner, key, iv, _expectedResponseVerifier, cancellationToken);
        _headerRead = true;

        // The header keys are single-use; the body keys live in VmessStream.
        ClearKeys();
        return _header;
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
            await ReadHeaderAsync(cancellationToken);

        return await _inner.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken)
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
        ClearKeys();
        if (!_leaveInnerOpen)
            await _inner.DisposeAsync();

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _disposed = true;
            ClearKeys();
            if (!_leaveInnerOpen)
                _inner.Dispose();
        }
        else
        {
            _disposed = true;
        }

        base.Dispose(disposing);
    }

    private void ClearKeys()
    {
        if (_responseBodyKey is not null)
        {
            CryptographicOperations.ZeroMemory(_responseBodyKey);
            _responseBodyKey = null;
        }

        if (_responseBodyIv is not null)
        {
            CryptographicOperations.ZeroMemory(_responseBodyIv);
            _responseBodyIv = null;
        }
    }
}
