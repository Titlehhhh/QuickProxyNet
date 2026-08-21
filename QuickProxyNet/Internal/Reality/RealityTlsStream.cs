using System.Runtime.CompilerServices;

namespace QuickProxyNet.Reality;

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

    /// <summary>
    /// What is left of the last record read, as a slice of the record layer's own buffer.
    /// </summary>
    /// <remarks>
    /// Not a copy. <see cref="TlsRecordStream.Record"/> promises its payload stays valid until
    /// the next read, and the read loop only reads again once this is
    /// empty — so the lifetime already lines up exactly, and copying each record cost a full
    /// memcpy of the payload for nothing.
    /// </remarks>
    private ReadOnlyMemory<byte> _pending;
    private bool _receivedCloseNotify;
    private bool _disposed;

    internal RealityTlsStream(Stream transport, TlsRecordStream records, List<byte> leftover)
    {
        _transport = transport;
        _records = records;

        // The one case that must be copied: the leftover comes from the handshake reader's list,
        // which does not survive.
        _pending = leftover.Count > 0 ? leftover.ToArray() : ReadOnlyMemory<byte>.Empty;
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

    /// <summary>Reads decrypted application data.</summary>
    /// <param name="buffer">Receives the data.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// Not an <c>async</c> method, so that draining a record already in hand costs a copy and a
    /// return rather than an async state machine. A 16 KiB record read 4 KiB at a time takes that
    /// path three times out of four, and the record layer underneath takes its own synchronous
    /// path whenever the next record is already buffered.
    /// </remarks>
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.IsEmpty)
            return new ValueTask<int>(0);

        if (!_pending.IsEmpty)
            return new ValueTask<int>(TakePending(buffer));

        if (_receivedCloseNotify)
            return new ValueTask<int>(0);

        return ReadFromRecordsAsync(buffer, cancellationToken);
    }

    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<int> ReadFromRecordsAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (_pending.IsEmpty)
        {
            if (_receivedCloseNotify)
                return 0;

            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
                return 0;
        }

        return TakePending(buffer);
    }

    /// <summary>Copies out of the record in hand and advances past what was taken.</summary>
    private int TakePending(Memory<byte> buffer)
    {
        int count = Math.Min(buffer.Length, _pending.Length);
        _pending.Span[..count].CopyTo(buffer.Span);
        _pending = _pending[count..];

        return count;
    }

    /// <summary>Reads records until one yields application data. Returns false at end of stream.</summary>
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
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
                    _pending = record.Payload;
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

    /// <summary>Writes application data, splitting it across records as RFC 8446 §5.1 requires.</summary>
    /// <param name="buffer">The data to send.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// The split into records happens inside the record layer rather than here, so that a write
    /// larger than one record still reaches the transport as few writes — the loop this replaces
    /// handed down one record at a time, and each of those was its own write and its own flush.
    /// </remarks>
    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return buffer.IsEmpty
            ? ValueTask.CompletedTask
            : _records.WriteApplicationDataAsync(buffer, cancellationToken);
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

        // Dropped before the record layer returns its buffers to the pool: this aliases one of
        // them, and a slice outliving its array is how a pooled buffer ends up shared.
        _pending = ReadOnlyMemory<byte>.Empty;

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
        _pending = ReadOnlyMemory<byte>.Empty;
        _records.Dispose();
        await _transport.DisposeAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
    }
}
