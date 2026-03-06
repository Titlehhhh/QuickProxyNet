using System.Buffers;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;

namespace QuickProxyNet;

internal static class HttpHelper
{
    // Sync: builds the CONNECT command bytes.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] BuildConnectionCommand(string host, int port, NetworkCredential? credentials)
    {
        var sb = new StringBuilder(256);
        sb.Append("CONNECT ").Append(host).Append(':').Append(port)
          .Append(" HTTP/1.1\r\nHost: ").Append(host).Append(':').Append(port).Append("\r\n");

        if (credentials is not null)
        {
            byte[] credBytes = Encoding.UTF8.GetBytes($"{credentials.UserName}:{credentials.Password}");
            sb.Append("Proxy-Authorization: Basic ")
              .Append(Convert.ToBase64String(credBytes))
              .Append("\r\n");
        }

        sb.Append("\r\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    internal static async ValueTask<Stream> EstablishHttpTunnelAsync(Stream stream, Uri proxyUri, string host,
        int port, NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        byte[] cmd = BuildConnectionCommand(host, port, credentials);
        await stream.WriteAsync(cmd.AsMemory(), cancellationToken);

        var parser = new HttpResponseParser();
        try
        {
            bool found;
            do
            {
                var memory = parser.GetMemory();
                int nread = await stream.ReadAsync(memory, cancellationToken);
                if (nread <= 0)
                    throw new EndOfStreamException("Proxy closed connection unexpectedly.");
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
                    throw new ProxyProtocolException(
                        $"Proxy authentication required (407) for {host}:{port}.");
                case -1:
                    throw new ProxyProtocolException("Proxy returned an invalid HTTP response.");
                default:
                    throw new ProxyProtocolException(
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
