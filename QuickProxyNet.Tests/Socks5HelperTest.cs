using System.Buffers.Binary;
using System.Net;
using System.Text;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

public class Socks5HelperTest
{
    /// <summary>
    /// Builds a SOCKS5 success response for a domain-name connect request with no auth.
    /// </summary>
    private static byte[] BuildSocks5NoAuthSuccessResponse(string host, int port)
    {
        using var ms = new MemoryStream();
        // Method selection: version 5, method 0 (no auth)
        ms.Write([5, 0]);

        // Connect reply: VER=5, REP=0 (success), RSV=0, ATYP=3 (domain), len, domain, port
        ms.Write([5, 0, 0, 3]);
        var hostBytes = Encoding.UTF8.GetBytes(host);
        ms.WriteByte((byte)hostBytes.Length);
        ms.Write(hostBytes);
        Span<byte> portBuf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(portBuf, (ushort)port);
        ms.Write(portBuf);
        return ms.ToArray();
    }

    /// <summary>
    /// Builds a SOCKS5 success response for a connect with username/password auth.
    /// </summary>
    private static byte[] BuildSocks5AuthSuccessResponse(string host, int port)
    {
        using var ms = new MemoryStream();
        // Method selection: version 5, method 2 (username/password)
        ms.Write([5, 2]);

        // Auth sub-negotiation: version 1, status 0 (success)
        ms.Write([1, 0]);

        // Connect reply
        ms.Write([5, 0, 0, 3]);
        var hostBytes = Encoding.UTF8.GetBytes(host);
        ms.WriteByte((byte)hostBytes.Length);
        ms.Write(hostBytes);
        Span<byte> portBuf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(portBuf, (ushort)port);
        ms.Write(portBuf);
        return ms.ToArray();
    }

    [Fact]
    public async Task Socks5_NoAuth_Success()
    {
        var response = BuildSocks5NoAuthSuccessResponse("example.com", 443);
        var stream = new FakeProxyStream(response);

        await SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, null, CancellationToken.None);

        // Verify handshake was sent: VER=5, NMETHODS=1, METHOD=0
        var written = stream.WrittenBytes;
        Assert.Equal(5, written[0]); // version
        Assert.Equal(1, written[1]); // 1 method
        Assert.Equal(0, written[2]); // no-auth
    }

    [Fact]
    public async Task Socks5_WithAuth_Success()
    {
        var response = BuildSocks5AuthSuccessResponse("example.com", 443);
        var stream = new FakeProxyStream(response);
        var creds = new NetworkCredential("testuser", "testpass");

        await SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, creds, CancellationToken.None);

        var written = stream.WrittenBytes;
        // Verify handshake: VER=5, NMETHODS=2, METHOD_NO_AUTH=0, METHOD_USER_PASS=2
        Assert.Equal(5, written[0]);
        Assert.Equal(2, written[1]);
        Assert.Equal(0, written[2]);
        Assert.Equal(2, written[3]);

        // Verify auth sub-negotiation was sent after the 4-byte handshake
        // Format: VER=1, ULEN, UNAME, PLEN, PASSWD
        Assert.Equal(1, written[4]);          // sub-negotiation version
        Assert.Equal(8, written[5]);          // "testuser" length
        Assert.Equal("testuser", Encoding.UTF8.GetString(written, 6, 8));
        Assert.Equal(8, written[14]);         // "testpass" length
        Assert.Equal("testpass", Encoding.UTF8.GetString(written, 15, 8));
    }

    [Fact]
    public async Task Socks5_AuthFailed_Throws()
    {
        using var ms = new MemoryStream();
        // Method selection: pick username/password
        ms.Write([5, 2]);
        // Auth sub-negotiation: version 1, status 1 (failure)
        ms.Write([1, 1]);
        var response = ms.ToArray();

        var stream = new FakeProxyStream(response);
        var creds = new NetworkCredential("user", "wrong");

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, creds, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.AuthFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task Socks5_NoSuitableMethod_Throws()
    {
        // Server returns 0xFF (no acceptable methods)
        var response = new byte[] { 5, 0xFF };
        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, null, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.SocksNoAuthMethod, ex.ErrorCode);
    }

    [Fact]
    public async Task Socks5_ConnectFailed_Throws()
    {
        using var ms = new MemoryStream();
        // Method selection: no auth
        ms.Write([5, 0]);
        // Connect reply: VER=5, REP=5 (connection refused), RSV=0, ATYP=1 (IPv4), 0.0.0.0:0
        ms.Write([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        var response = ms.ToArray();

        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, null, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
    }

    // ArrayPool rounds the 520-byte request buffer up to 1024, so a string of 256 to about 1000
    // UTF-8 bytes fits the buffer but not the one-byte length field. It used to escape as a raw
    // OverflowException, outside ConnectAsync's exception contract.
    [Theory]
    [InlineData(256)]
    [InlineData(600)]
    [InlineData(2000)]
    public async Task Socks5_UsernameOver255Bytes_IsSocksStringTooLong(int length)
    {
        var stream = new FakeProxyStream([5, 2]);
        var creds = new NetworkCredential(new string('u', length), "pass");

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, creds, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.SocksStringTooLong, ex.ErrorCode);
    }

    [Fact]
    public async Task Socks5_HostUnder255CharsButOver255Bytes_IsSocksStringTooLong()
    {
        // 200 Cyrillic letters pass the 255-character argument check and encode to 400 bytes.
        var stream = new FakeProxyStream([5, 0]);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, new string('ж', 200), 443, null, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.SocksStringTooLong, ex.ErrorCode);
    }

    [Fact]
    public async Task Socks4_UserIdOver255Bytes_IsSocksStringTooLong()
    {
        var stream = new FakeProxyStream([]);
        var creds = new NetworkCredential(new string('u', 300), "");

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks4TunnelAsync(stream, false, "127.0.0.1", 443, creds, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.SocksStringTooLong, ex.ErrorCode);
    }

    /// <summary>
    /// The request buffer must hold the largest message the helper writes. It was sized for the
    /// SOCKS5 username and password message, 513 bytes, while a SOCKS4a request carrying a
    /// 255-byte user id and a 255-byte host is 520. Nothing failed only because ArrayPool hands
    /// out 1024 bytes for either size, which is also why the size is checked here directly.
    /// </summary>
    [Fact]
    public async Task BufferSize_HoldsTheLargestMessageTheHelperWrites()
    {
        string longest = new('x', 255);
        byte[] longestBytes = Encoding.ASCII.GetBytes(longest);

        var socks4a = new WriteRecordingStream([0, 90, 0, 0, 0, 0, 0, 0]);
        await SocksHelper.EstablishSocks4TunnelAsync(socks4a, true, longest, 443,
            new NetworkCredential(longest, ""), CancellationToken.None);

        byte[] request = [4, 1, 443 >> 8, 443 & 0xFF, 0, 0, 0, 255, .. longestBytes, 0, .. longestBytes, 0];
        Assert.Equal(request, socks4a.Written);

        var socks5 = new WriteRecordingStream([5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        await SocksHelper.EstablishSocks5TunnelAsync(socks5, longest, 443,
            new NetworkCredential(longest, longest), CancellationToken.None);

        Assert.Equal(520, socks4a.LargestWrite);
        Assert.Equal(513, socks5.LargestWrite);
        Assert.Equal(SocksHelper.BufferSize, Math.Max(socks4a.LargestWrite, socks5.LargestWrite));
    }

    /// <summary>Replays a scripted reply, and records what was written and the largest single write.</summary>
    private sealed class WriteRecordingStream(byte[] reply) : Stream
    {
        private readonly MemoryStream _reply = new(reply);
        private readonly MemoryStream _written = new();

        public byte[] Written => _written.ToArray();

        public int LargestWrite { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => _reply.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
            _reply.ReadAsync(buffer, ct);

        public override void Write(byte[] buffer, int offset, int count)
        {
            LargestWrite = Math.Max(LargestWrite, count);
            _written.Write(buffer, offset, count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            LargestWrite = Math.Max(LargestWrite, buffer.Length);
            return _written.WriteAsync(buffer, ct);
        }
    }

    [Fact]
    public async Task Socks5_WrongVersion_Throws()
    {
        // Server returns version 4 instead of 5
        var response = new byte[] { 4, 0 };
        var stream = new FakeProxyStream(response);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => SocksHelper.EstablishSocks5TunnelAsync(stream, "example.com", 443, null, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.SocksUnexpectedVersion, ex.ErrorCode);
    }

    [Fact]
    public async Task Socks5_IPv4Address_EncodesCorrectly()
    {
        var response = BuildSocks5NoAuthSuccessResponse("1.2.3.4", 80);
        var stream = new FakeProxyStream(response);

        await SocksHelper.EstablishSocks5TunnelAsync(stream, "1.2.3.4", 80, null, CancellationToken.None);

        var written = stream.WrittenBytes;
        // After handshake (3 bytes), connect request starts
        int offset = 3;
        Assert.Equal(5, written[offset]);     // VER
        Assert.Equal(1, written[offset + 1]); // CMD = CONNECT
        Assert.Equal(0, written[offset + 2]); // RSV
        Assert.Equal(1, written[offset + 3]); // ATYP = IPv4
        Assert.Equal(1, written[offset + 4]); // 1.
        Assert.Equal(2, written[offset + 5]); // 2.
        Assert.Equal(3, written[offset + 6]); // 3.
        Assert.Equal(4, written[offset + 7]); // 4
    }
}
