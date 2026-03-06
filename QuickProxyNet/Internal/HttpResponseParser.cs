using System.Buffers;
using System.Text;

namespace QuickProxyNet;

internal struct HttpResponseParser : IDisposable
{
    private const int BufferSize = 1024;

    private byte[] _buffer;
    private int _writtenCount;
    private int _indexEnd; // absolute index of '\r\n\r\n' start, or -1

    public ReadOnlySpan<byte> Span => _buffer.AsSpan(0, _writtenCount);

    public HttpResponseParser()
    {
        _buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        _writtenCount = 0;
        _indexEnd = -1;
    }

    public Memory<byte> GetMemory()
    {
        if (_writtenCount < _buffer.Length)
            return _buffer.AsMemory(_writtenCount);

        // Grow: rent a larger buffer, copy, return old
        byte[] next = ArrayPool<byte>.Shared.Rent(_writtenCount + BufferSize);
        _buffer.AsSpan(0, _writtenCount).CopyTo(next);
        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = next;
        return _buffer.AsMemory(_writtenCount);
    }


    public bool Parse(int count)
    {
        _writtenCount += count;
        return FindEndOfHeaders(count);
    }

    private static readonly byte[] s_endOfHeaders = "\r\n\r\n"u8.ToArray();


    private bool FindEndOfHeaders(int newBytes)
    {
        // Search the new bytes plus up to 3 preceding bytes (to catch \r\n\r\n split across reads)
        int start = _writtenCount - newBytes;
        int lookback = Math.Min(3, start);
        start -= lookback;
        int length = newBytes + lookback;

        int index = _buffer.AsSpan(start, length).IndexOf(s_endOfHeaders);
        if (index < 0)
            return false;

        _indexEnd = index + start;
        return true;
    }

    /// <summary>Returns HTTP status code (e.g. 200, 407), or -1 if response is malformed.</summary>
    public int GetStatusCode()
    {
        ReadOnlySpan<byte> span = Span;

        // Minimum: "HTTP/1.x NNN" = 12 bytes
        if (span.Length < 12) return -1;
        if (!span.StartsWith("HTTP/1."u8)) return -1;

        // Status code occupies bytes 9..11
        ReadOnlySpan<byte> code = span.Slice(9, 3);
        if (code[0] < (byte)'0' || code[0] > (byte)'9') return -1;
        if (code[1] < (byte)'0' || code[1] > (byte)'9') return -1;
        if (code[2] < (byte)'0' || code[2] > (byte)'9') return -1;

        return (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
    }

    /// <summary>
    /// True if bytes were read beyond the end of the HTTP response headers.
    /// These bytes belong to the tunneled connection and must be re-prepended to the stream.
    /// </summary>
    public bool HasOverreadBytes => _indexEnd >= 0 && _writtenCount > _indexEnd + 4;

    /// <summary>Returns the bytes read beyond the end of HTTP response headers.</summary>
    public ReadOnlySpan<byte> OverreadBytes
    {
        get
        {
            if (!HasOverreadBytes) return ReadOnlySpan<byte>.Empty;
            int start = _indexEnd + 4;
            return _buffer.AsSpan(start, _writtenCount - start);
        }
    }


    public override string ToString() =>
        _indexEnd >= 0
            ? Encoding.UTF8.GetString(_buffer, 0, _indexEnd + 4)
            : Encoding.UTF8.GetString(_buffer, 0, _writtenCount);

    public void Dispose()
    {
        byte[] buf = _buffer;
        _buffer = null!;
        if (buf is not null)
            ArrayPool<byte>.Shared.Return(buf);
    }
}
