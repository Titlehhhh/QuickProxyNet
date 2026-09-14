namespace QuickProxyNet;

/// <summary>
/// A minimal writer for TLS's length-prefixed wire format.
/// </summary>
/// <remarks>
/// TLS nests variable-length vectors whose length is written before the contents are known, so
/// every serialiser needs the same backpatching dance. Doing it by hand at each call site is how
/// off-by-one length bugs get in — and a ClientHello with a wrong inner length is rejected with
/// no useful diagnostic, because the peer simply sees a malformed record.
/// </remarks>
internal sealed class TlsWriter(int capacity = 512)
{
    private byte[] _buffer = new byte[capacity];
    private int _position;

#if DEBUG
    /// <summary>The vectors begun and not yet ended, innermost last, with their prefix sizes.</summary>
    private readonly Stack<(int Marker, int PrefixSize)> _openVectors = new();
#endif

    /// <summary>Number of bytes written so far.</summary>
    public int Length => _position;

    /// <summary>The bytes written so far, as a span into the internal buffer.</summary>
    public Span<byte> Written => _buffer.AsSpan(0, _position);

    public void WriteByte(byte value)
    {
        Ensure(1);
        _buffer[_position++] = value;
    }

    public void WriteUInt16(ushort value)
    {
        Ensure(2);
        _buffer[_position++] = (byte)(value >> 8);
        _buffer[_position++] = (byte)value;
    }

    public void Write(ReadOnlySpan<byte> value)
    {
        Ensure(value.Length);
        value.CopyTo(_buffer.AsSpan(_position));
        _position += value.Length;
    }

    /// <summary>Writes <paramref name="count"/> zero bytes.</summary>
    public void WriteZeros(int count)
    {
        Ensure(count);
        _buffer.AsSpan(_position, count).Clear();
        _position += count;
    }

    /// <summary>Reserves a one-byte length prefix; pass the result to <see cref="EndVector"/>.</summary>
    public int BeginVector8()
    {
        WriteByte(0);
        return Opened(1);
    }

    /// <summary>Reserves a two-byte length prefix; pass the result to <see cref="EndVector"/>.</summary>
    public int BeginVector16()
    {
        WriteUInt16(0);
        return Opened(2);
    }

    /// <summary>Reserves a three-byte length prefix; pass the result to <see cref="EndVector"/>.</summary>
    public int BeginVector24()
    {
        WriteByte(0);
        WriteUInt16(0);
        return Opened(3);
    }

    /// <summary>The marker for the vector whose length prefix was just reserved.</summary>
    private int Opened(int prefixSize)
    {
#if DEBUG
        _openVectors.Push((_position, prefixSize));
#endif
        return _position;
    }

    /// <summary>Backpatches the length of the vector that started at <paramref name="marker"/>.</summary>
    /// <param name="marker">The value returned by the matching <c>BeginVector*</c>.</param>
    /// <param name="prefixSize">1, 2 or 3 — must match the <c>BeginVector*</c> that was used.</param>
    public void EndVector(int marker, int prefixSize)
    {
#if DEBUG
        // Vectors nest, so the one ending must be the innermost still open, with the prefix size it
        // began with. A second EndVector for one marker, a mismatched size or an out-of-order end would
        // patch a length over the wrong bytes, and the peer would only see a malformed hello. Checking
        // that the prefix still reads zero catches few of these: a size one short lands on a zero byte
        // of the same placeholder, and an empty vector's length is zero either way.
        bool anyOpen = _openVectors.TryPop(out (int Marker, int PrefixSize) innermost);
        System.Diagnostics.Debug.Assert(anyOpen && innermost == (marker, prefixSize));
#endif

        int length = _position - marker;
        int start = marker - prefixSize;

        switch (prefixSize)
        {
            case 1:
                if (length > byte.MaxValue)
                    throw new InvalidOperationException($"A one-byte vector cannot hold {length} bytes.");
                _buffer[start] = (byte)length;
                break;

            case 2:
                if (length > ushort.MaxValue)
                    throw new InvalidOperationException($"A two-byte vector cannot hold {length} bytes.");
                _buffer[start] = (byte)(length >> 8);
                _buffer[start + 1] = (byte)length;
                break;

            case 3:
                if (length > 0xFFFFFF)
                    throw new InvalidOperationException($"A three-byte vector cannot hold {length} bytes.");
                _buffer[start] = (byte)(length >> 16);
                _buffer[start + 1] = (byte)(length >> 8);
                _buffer[start + 2] = (byte)length;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(prefixSize), prefixSize, "Prefixes are 1, 2 or 3 bytes.");
        }
    }

    /// <summary>Copies the written bytes into a new array.</summary>
    public byte[] ToArray()
    {
#if DEBUG
        // A vector never ended still carries a zero length.
        System.Diagnostics.Debug.Assert(_openVectors.Count == 0);
#endif
        return _buffer.AsSpan(0, _position).ToArray();
    }

    private void Ensure(int additional)
    {
        if (_position + additional <= _buffer.Length)
            return;

        int capacity = Math.Max(_buffer.Length * 2, _position + additional);
        Array.Resize(ref _buffer, capacity);
    }
}
