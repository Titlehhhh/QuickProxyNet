using System.Buffers;
using System.Buffers.Text;
using System.Net;
using System.Text;

namespace QuickProxyNet;

internal static class HttpHelper
{
    // Static byte literals — no allocation, shared across calls
    private static ReadOnlySpan<byte> S_connect     => "CONNECT "u8;
    private static ReadOnlySpan<byte> S_http11Host  => " HTTP/1.1\r\nHost: "u8;
    private static ReadOnlySpan<byte> S_proxyAuth   => "Proxy-Authorization: Basic "u8;
    private static ReadOnlySpan<byte> S_crlf        => "\r\n"u8;

    // Builds CONNECT command into a rented ArrayPool buffer.
    // Caller must return the buffer via ArrayPool<byte>.Shared.Return().
    private static (byte[] buffer, int length) BuildConnectionCommand(
        string host, int port, NetworkCredential? credentials)
    {
        int hostMaxBytes = Encoding.UTF8.GetMaxByteCount(host.Length);

        // CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n
        //   8      255    1  5   17       255    1  5  2  2  = ~551 bytes worst case
        int size = 8 + hostMaxBytes + 1 + 5 + 17 + hostMaxBytes + 1 + 5 + 4;

        if (credentials is not null)
        {
            int credMaxBytes = Encoding.UTF8.GetMaxByteCount(credentials.UserName.Length)
                             + 1
                             + Encoding.UTF8.GetMaxByteCount(credentials.Password.Length);
            // "Proxy-Authorization: Basic " (27) + base64(cred) + "\r\n" (2)
            size += 27 + (credMaxBytes + 2) / 3 * 4 + 2;
        }

        byte[] buf = ArrayPool<byte>.Shared.Rent(size);
        int pos = 0;

        // CONNECT {host}:{port} HTTP/1.1\r\n
        S_connect.CopyTo(buf.AsSpan(pos)); pos += S_connect.Length;
        pos += Encoding.UTF8.GetBytes(host, buf.AsSpan(pos));
        buf[pos++] = (byte)':';
        Utf8Formatter.TryFormat(port, buf.AsSpan(pos), out int portLen); pos += portLen;

        // Host: {host}:{port}\r\n
        S_http11Host.CopyTo(buf.AsSpan(pos)); pos += S_http11Host.Length;
        pos += Encoding.UTF8.GetBytes(host, buf.AsSpan(pos));
        buf[pos++] = (byte)':';
        Utf8Formatter.TryFormat(port, buf.AsSpan(pos), out portLen); pos += portLen;
        S_crlf.CopyTo(buf.AsSpan(pos)); pos += 2;

        if (credentials is not null)
        {
            // Proxy-Authorization: Basic {base64(user:pass)}\r\n
            S_proxyAuth.CopyTo(buf.AsSpan(pos)); pos += S_proxyAuth.Length;

            int userLen = Encoding.UTF8.GetByteCount(credentials.UserName);
            int passLen = Encoding.UTF8.GetByteCount(credentials.Password);
            int credLen = userLen + 1 + passLen;

            byte[] credBuf = ArrayPool<byte>.Shared.Rent(credLen);
            try
            {
                Encoding.UTF8.GetBytes(credentials.UserName, credBuf.AsSpan());
                credBuf[userLen] = (byte)':';
                Encoding.UTF8.GetBytes(credentials.Password, credBuf.AsSpan(userLen + 1));
                Base64.EncodeToUtf8(credBuf.AsSpan(0, credLen), buf.AsSpan(pos), out _, out int b64Len);
                pos += b64Len;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(credBuf);
            }

            S_crlf.CopyTo(buf.AsSpan(pos)); pos += 2;
        }

        // End of headers
        S_crlf.CopyTo(buf.AsSpan(pos)); pos += 2;

        return (buf, pos);
    }

    internal static async ValueTask<Stream> EstablishHttpTunnelAsync(Stream stream, Uri proxyUri, string host,
        int port, NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        var (cmd, cmdLen) = BuildConnectionCommand(host, port, credentials);
        try
        {
            await stream.WriteAsync(cmd.AsMemory(0, cmdLen), cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(cmd);
        }

        var parser = new HttpResponseParser();
        try
        {
            bool found;
            do
            {
                var memory = parser.GetMemory();
                int nread = await stream.ReadAsync(memory, cancellationToken);
                if (nread <= 0)
                    throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                        $"Proxy closed connection unexpectedly while establishing tunnel to {host}:{port}.");
                found = parser.Parse(nread);
            } while (!found);

            int statusCode = parser.GetStatusCode();
            switch (statusCode)
            {
                case 200:
                    if (parser.HasOverreadBytes)
                    {
                        byte[] overread = parser.OverreadBytes.ToArray();
                        return new PrefixedStream(overread, stream);
                    }
                    return stream;
                case 407:
                    throw new ProxyProtocolException(ProxyErrorCode.AuthRequired,
                        $"Proxy authentication required (407) for {host}:{port}.");
                case -1:
                    throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                        "Proxy returned an invalid HTTP response.");
                default:
                    throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                        $"Proxy CONNECT failed with HTTP {statusCode} for {host}:{port}.");
            }
        }
        finally
        {
            parser.Dispose();
        }
    }

    private sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
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
            return await inner.ReadAsync(buffer, ct);
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
    }
}
