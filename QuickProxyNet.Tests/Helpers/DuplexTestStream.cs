namespace QuickProxyNet.Tests.Helpers;

/// <summary>
/// A bidirectional in-memory transport: reads drain a scripted inbound buffer, writes
/// accumulate in a list that stays readable after disposal.
/// </summary>
/// <remarks>
/// <paramref name="maxReadSize"/> caps how many bytes a single read may return, which
/// forces callers to loop and exercises <c>ReadExactlyAsync</c>-style reassembly.
/// </remarks>
internal sealed class DuplexTestStream(byte[] inbound, int maxReadSize = int.MaxValue) : Stream
{
    private readonly List<byte> _outbound = [];
    private int _position;

    /// <summary>Every byte written so far, in order.</summary>
    public byte[] Written => [.. _outbound];

    /// <summary>Bytes of the scripted inbound buffer not yet read.</summary>
    public byte[] Unread => inbound[_position..];

    /// <summary>How many times <see cref="Stream.Dispose()"/>/<see cref="DisposeAsync"/> ran.</summary>
    public int DisposeCount { get; private set; }

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
        int count = Math.Min(Math.Min(buffer.Length, maxReadSize), inbound.Length - _position);
        if (count <= 0)
            return 0;

        inbound.AsSpan(_position, count).CopyTo(buffer);
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

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        foreach (byte b in buffer)
            _outbound.Add(b);
    }

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
