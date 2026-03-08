namespace QuickProxyNet.Tests.Helpers;

/// <summary>
/// A stream backed by a MemoryStream that supports scripted responses.
/// Write calls go into a sink; Read calls return pre-loaded response bytes.
/// </summary>
internal sealed class FakeProxyStream : Stream
{
    private readonly MemoryStream _response;
    private readonly MemoryStream _written = new();

    public FakeProxyStream(byte[] responseBytes)
    {
        _response = new MemoryStream(responseBytes);
    }

    /// <summary>All bytes written by the client (the CONNECT command, etc.).</summary>
    public byte[] WrittenBytes => _written.ToArray();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) =>
        _response.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        _response.ReadAsync(buffer, ct);

    public override void Write(byte[] buffer, int offset, int count) =>
        _written.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        _written.WriteAsync(buffer, ct);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _response.Dispose();
            _written.Dispose();
        }
        base.Dispose(disposing);
    }
}
