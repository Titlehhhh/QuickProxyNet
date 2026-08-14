using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet.Tests.Helpers;

/// <summary>
/// An in-memory server end for the <c>ws</c> and <c>httpupgrade</c> transports: it answers the
/// HTTP upgrade and then speaks RFC 6455 frames.
/// </summary>
/// <remarks>
/// The handshake response cannot be scripted up front the way
/// <see cref="ScriptedDuplexStream"/> allows, because <c>Sec-WebSocket-Accept</c> is derived
/// from a key the client generates randomly inside <c>ConnectAsync</c>. So the response is
/// built lazily, on the first read after a complete request has been written — which is also
/// what a real server does.
/// <para>
/// Server-to-client frames are unmasked and client-to-server frames must be masked; RFC 6455
/// requires exactly that asymmetry, so decoding here doubles as an assertion that the client
/// masks its frames.
/// </para>
/// </remarks>
internal sealed class FakeWebSocketServer : Stream
{
    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private readonly List<byte> _clientBytes = [];
    private readonly List<byte> _toClient = [];
    private readonly List<byte> _payloadFromClient = [];
    private readonly bool _framed;

    private int _position;
    private bool _upgraded;

    /// <summary>Length of the client's HTTP request, fixed once the header block is complete.</summary>
    private int _handshakeLength;

    /// <summary>How far into the client's bytes the frame decoder has consumed.</summary>
    private int _decodeCursor;

    /// <param name="framed">
    /// True for <c>ws</c> (RFC 6455 framing after the 101); false for <c>httpupgrade</c>, where
    /// the upgraded connection carries raw bytes.
    /// </param>
    public FakeWebSocketServer(bool framed = true) => _framed = framed;

    /// <summary>Status line to answer the upgrade with. Override to test a refusal.</summary>
    public string StatusLine { get; init; } = "HTTP/1.1 101 Switching Protocols";

    /// <summary>When set, sent instead of the correct <c>Sec-WebSocket-Accept</c>.</summary>
    public string? AcceptOverride { get; init; }

    /// <summary>When true, no <c>Sec-WebSocket-Accept</c> header is sent at all.</summary>
    public bool OmitAccept { get; init; }

    /// <summary>
    /// Bytes appended to the 101 response, simulating a server that pipelines tunnel data
    /// immediately behind the header block.
    /// </summary>
    public byte[] PipelinedAfterHandshake { get; init; } = [];

    /// <summary>The raw HTTP upgrade request the client sent.</summary>
    public string Request => Encoding.UTF8.GetString(_clientBytes.ToArray(), 0, _handshakeLength);

    /// <summary>Application payload received from the client, with framing removed.</summary>
    public byte[] PayloadFromClient => [.. _payloadFromClient];

    /// <summary>True once the upgrade response has been produced.</summary>
    public bool Upgraded => _upgraded;

    /// <summary>Queues an application message for the client to read.</summary>
    public void SendToClient(ReadOnlySpan<byte> payload)
    {
        if (_framed)
            _toClient.AddRange(EncodeServerFrame(payload));
        else
            _toClient.AddRange(payload);
    }

    /// <summary>Queues a WebSocket close frame.</summary>
    public void SendClose()
    {
        // 0x88 = FIN + close opcode, with a 2-byte status code payload (1000 = normal).
        _toClient.AddRange([0x88, 0x02, 0x03, 0xE8]);
    }

    public static byte[] EncodeServerFrame(ReadOnlySpan<byte> payload)
    {
        var frame = new List<byte> { 0x82 }; // FIN + binary opcode

        if (payload.Length < 126)
        {
            frame.Add((byte)payload.Length);
        }
        else if (payload.Length <= ushort.MaxValue)
        {
            frame.Add(126);
            Span<byte> len = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)payload.Length);
            frame.AddRange(len);
        }
        else
        {
            frame.Add(127);
            Span<byte> len = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(len, (ulong)payload.Length);
            frame.AddRange(len);
        }

        frame.AddRange(payload);
        return [.. frame];
    }

    // ---- Stream ----

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
        TryCompleteHandshake();

        // Nothing is readable before the upgrade — a server does not leak tunnel bytes ahead
        // of its own response, and neither should the queue a test filled in advance.
        if (!_upgraded)
            return 0;

        int count = Math.Min(buffer.Length, _toClient.Count - _position);
        if (count <= 0)
            return 0;

        for (int i = 0; i < count; i++)
            buffer[i] = _toClient[_position + i];

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
        _clientBytes.AddRange(buffer);

        if (_upgraded)
            DecodeClientBytes();
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

    // ---- handshake ----

    private void TryCompleteHandshake()
    {
        if (_upgraded)
            return;

        byte[] request = [.. _clientBytes];
        int end = IndexOf(request, "\r\n\r\n"u8);
        if (end < 0)
            return;

        _handshakeLength = end + 4;
        _decodeCursor = _handshakeLength;

        var response = new StringBuilder();
        response.Append(StatusLine).Append("\r\n");

        if (StatusLine.Contains("101"))
        {
            response.Append("Upgrade: websocket\r\nConnection: Upgrade\r\n");
            if (!OmitAccept)
                response.Append("Sec-WebSocket-Accept: ")
                        .Append(AcceptOverride ?? ComputeAccept(Request))
                        .Append("\r\n");
        }

        response.Append("\r\n");

        // Inserted at the front: a test queues its application frames before ConnectAsync runs,
        // but on the wire the header block necessarily comes first.
        byte[] header = Encoding.UTF8.GetBytes(response.ToString());
        _toClient.InsertRange(0, PipelinedAfterHandshake);
        _toClient.InsertRange(0, header);
        _upgraded = true;

        // Anything written past the header block is already tunnel traffic.
        if (_clientBytes.Count > _handshakeLength)
            DecodeClientBytes();
    }

    private static string ComputeAccept(string request)
    {
        const string header = "Sec-WebSocket-Key:";
        int start = request.IndexOf(header, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
            return "missing-key";

        start += header.Length;
        int end = request.IndexOf("\r\n", start, StringComparison.Ordinal);
        string key = request[start..end].Trim();

#pragma warning disable CA5350 // RFC 6455 fixes SHA-1 as the handshake token.
        byte[] digest = SHA1.HashData(Encoding.ASCII.GetBytes(key + WebSocketGuid));
#pragma warning restore CA5350
        return Convert.ToBase64String(digest);
    }

    /// <summary>
    /// Consumes whole frames (or, for httpupgrade, raw bytes) from the client buffer into
    /// <see cref="PayloadFromClient"/>, leaving any partial frame for the next write.
    /// </summary>
    private void DecodeClientBytes()
    {
        if (!_framed)
        {
            for (int i = _decodeCursor; i < _clientBytes.Count; i++)
                _payloadFromClient.Add(_clientBytes[i]);
            _decodeCursor = _clientBytes.Count;
            return;
        }

        while (true)
        {
            int available = _clientBytes.Count - _decodeCursor;
            if (available < 2)
                return;

            byte[] frame = [.. _clientBytes.GetRange(_decodeCursor, available)];

            byte second = frame[1];
            bool masked = (second & 0x80) != 0;
            long length = second & 0x7F;
            int offset = 2;

            if (length == 126)
            {
                if (available < offset + 2) return;
                length = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(offset));
                offset += 2;
            }
            else if (length == 127)
            {
                if (available < offset + 8) return;
                length = (long)BinaryPrimitives.ReadUInt64BigEndian(frame.AsSpan(offset));
                offset += 8;
            }

            // A client that does not mask is a protocol violation; surface it as a test failure
            // rather than silently decoding it.
            if (!masked)
                throw new InvalidOperationException("The client sent an unmasked frame, which RFC 6455 forbids.");

            if (available < offset + 4 + length)
                return;

            ReadOnlySpan<byte> mask = frame.AsSpan(offset, 4);
            offset += 4;

            byte opcode = (byte)(frame[0] & 0x0F);
            for (long i = 0; i < length; i++)
            {
                byte unmasked = (byte)(frame[offset + i] ^ mask[(int)(i % 4)]);
                // Opcode 1/2 are text/binary data; 8/9/10 are control frames carrying no payload
                // the tunnel cares about.
                if (opcode is 0x00 or 0x01 or 0x02)
                    _payloadFromClient.Add(unmasked);
            }

            _decodeCursor += offset + (int)length;
        }
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) => haystack.IndexOf(needle);
}
