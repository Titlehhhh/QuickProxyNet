namespace QuickProxyNet.Tests.Helpers;

/// <summary>
/// A bidirectional in-memory transport whose inbound script can be extended <b>after</b>
/// construction, so a test can act as the server: observe what the client wrote, derive
/// the session keys from it, and only then queue the matching response bytes.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DuplexTestStream"/> fixes its inbound buffer up front, which is enough when
/// the response does not depend on the request. The VMess handshake is the opposite case:
/// the response header is sealed with keys the client generated randomly inside
/// <c>ConnectAsync</c>.
/// </para>
/// <para>
/// Reads return <c>0</c> when the queue is drained rather than blocking, so a client that
/// reads earlier than expected fails deterministically (as truncation) instead of hanging
/// the test run.
/// </para>
/// </remarks>
internal sealed class ScriptedDuplexStream(int maxReadSize = int.MaxValue) : Stream
{
    private readonly List<byte> _inbound = [];
    private readonly List<byte> _outbound = [];
    private int _position;

    /// <summary>Every byte written by the client so far, in order.</summary>
    public byte[] Written => [.. _outbound];

    /// <summary>Bytes of the inbound script not yet consumed.</summary>
    public int Unread => _inbound.Count - _position;

    /// <summary>How many times a read was attempted (0 proves nothing was read yet).</summary>
    public int ReadCount { get; private set; }

    /// <summary>How many times <see cref="Stream.Dispose()"/>/<see cref="DisposeAsync"/> ran.</summary>
    public int DisposeCount { get; private set; }

    /// <summary>Appends bytes the client will see on subsequent reads.</summary>
    public void Enqueue(ReadOnlySpan<byte> data) => _inbound.AddRange(data);

    /// <summary>Discards everything written so far, to isolate a later exchange.</summary>
    public void ClearWritten() => _outbound.Clear();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(Span<byte> buffer)
    {
        ReadCount++;

        int count = Math.Min(Math.Min(buffer.Length, maxReadSize), _inbound.Count - _position);
        if (count <= 0)
            return 0;

        for (int i = 0; i < count; i++)
            buffer[i] = _inbound[_position + i];

        _position += count;
        return count;
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(ReadOnlySpan<byte> buffer) => _outbound.AddRange(buffer);

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            DisposeCount++;
        base.Dispose(disposing);
    }
}
