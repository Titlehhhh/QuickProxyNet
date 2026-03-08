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
