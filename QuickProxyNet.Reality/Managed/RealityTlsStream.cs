namespace QuickProxyNet.Reality.Managed;

/// <summary>
/// The application-data stream of a completed managed REALITY handshake.
/// </summary>
/// <remarks>
/// <para>
/// Record boundaries are not message boundaries: a read returns whatever one record held, and a
/// write may become several records. Callers that need framing bring their own — which VLESS,
/// the only consumer here, does.
/// </para>
/// <para>
/// Post-handshake handshake messages are not an error. A TLS 1.3 server may send NewSessionTicket
/// at any time, and a client that treats one as data corrupts the stream at a point that looks
/// random from the outside.
/// </para>
/// </remarks>
internal sealed class RealityTlsStream : Stream
{
    private readonly Stream _transport;
    private readonly TlsRecordStream _records;

    private byte[] _pending;
    private int _pendingOffset;
    private bool _receivedCloseNotify;
    private bool _disposed;

    internal RealityTlsStream(Stream transport, TlsRecordStream records, List<byte> leftover)
    {
        _transport = transport;
        _records = records;
        _pending = leftover.Count > 0 ? leftover.ToArray() : [];
    }

    public override bool CanRead => !_disposed;
    public override bool CanWrite => !_disposed;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
            return 0;

        while (_pendingOffset >= _pending.Length)
        {
            if (_receivedCloseNotify)
                return 0;

            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
                return 0;
        }

        int count = Math.Min(buffer.Length, _pending.Length - _pendingOffset);
        _pending.AsSpan(_pendingOffset, count).CopyTo(buffer.Span);
        _pendingOffset += count;

        return count;
    }

    /// <summary>Reads records until one yields application data. Returns false at end of stream.</summary>
    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            TlsRecordStream.Record record;
            try
            {
                record = await _records.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (EndOfStreamException)
            {
                // The peer vanished without a close_notify. Common enough in practice that it is
                // reported as end of stream rather than as an error.
                _receivedCloseNotify = true;
                return false;
            }

            switch (record.Type)
            {
                case TlsContentType.ApplicationData when !record.Payload.IsEmpty:
                    _pending = record.Payload.ToArray();
                    _pendingOffset = 0;
                    return true;

                case TlsContentType.ApplicationData:
                case TlsContentType.ChangeCipherSpec:
                    continue;

                case TlsContentType.Handshake:
                    SkipPostHandshakeMessage(record.Payload.Span);
                    continue;

                case TlsContentType.Alert:
                    // description 0 is close_notify: an orderly shutdown, not a failure.
                    if (record.Payload.Length >= 2 && record.Payload.Span[1] == 0)
                    {
                        _receivedCloseNotify = true;
                        return false;
                    }

                    throw new RealityHandshakeException(
                        record.Payload.Length >= 2
                            ? $"The server sent a TLS alert, description {record.Payload.Span[1]}."
                            : "The server sent a malformed TLS alert.");

                default:
                    throw new RealityHandshakeException($"Unexpected record type {record.Type} after the handshake.");
            }
        }
    }

    private static void SkipPostHandshakeMessage(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 4)
            return;

        var type = (TlsHandshakeType)payload[0];
        if (type is TlsHandshakeType.NewSessionTicket)
            return;

        if (type is TlsHandshakeType.KeyUpdate)
            throw new RealityHandshakeException(
                "The server asked for a key update, which this client does not implement yet. Continuing " +
                "would send every later record under keys the server has already retired.");

        throw new RealityHandshakeException($"Unexpected post-handshake message {type}.");
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (!buffer.IsEmpty)
        {
            int chunk = Math.Min(buffer.Length, TlsRecordStream.MaxPlaintext);
            await _records.WriteAsync(TlsContentType.ApplicationData, buffer[..chunk], cancellationToken)
                .ConfigureAwait(false);

            buffer = buffer[chunk..];
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Flush() => _transport.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _transport.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        _disposed = true;

        if (disposing)
        {
            _records.Dispose();
            _transport.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;
        _records.Dispose();
        await _transport.DisposeAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
    }
}
