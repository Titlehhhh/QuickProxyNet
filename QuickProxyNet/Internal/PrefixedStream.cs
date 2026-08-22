namespace QuickProxyNet;

/// <summary>
/// Serves <paramref name="prefix"/> before delegating to <paramref name="inner"/>.
/// </summary>
/// <remarks>
/// Every handshake that reads a header block off a socket can overread: the reader asks for
/// a buffer's worth and the server has already pipelined tunnel bytes behind the header. Those
/// bytes belong to the caller and are gone once the header parser's buffer is returned to the
/// pool, so they are re-prepended here instead.
/// </remarks>
internal sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
{
    private int _offset;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(Span<byte> buffer)
    {
        if (_offset < prefix.Length)
        {
            int count = Math.Min(buffer.Length, prefix.Length - _offset);
            prefix.AsSpan(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }
        return inner.Read(buffer);
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_offset < prefix.Length)
        {
            int count = Math.Min(buffer.Length, prefix.Length - _offset);
            prefix.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }
        return await inner.ReadAsync(buffer, ct).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        inner.WriteAsync(buffer, ct);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        inner.WriteAsync(buffer, offset, count, ct);

    protected override void Dispose(bool disposing)
    {
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync() => inner.DisposeAsync();

    /// <summary>
    /// Wraps <paramref name="inner"/> only when <paramref name="overread"/> actually has bytes,
    /// so the common case adds no layer to the stream stack.
    /// </summary>
    public static Stream WrapIfNeeded(ReadOnlySpan<byte> overread, Stream inner) =>
        overread.IsEmpty ? inner : new PrefixedStream(overread.ToArray(), inner);
}
