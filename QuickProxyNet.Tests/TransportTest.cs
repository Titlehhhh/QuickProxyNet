using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

/// <summary>
/// The <c>ws</c> and <c>httpupgrade</c> transport layers, exercised through
/// <see cref="VlessClient"/> — the transport has no public surface of its own, and driving it
/// through a real protocol is what proves the layering order is right.
/// </summary>
public class TransportTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";

    private static VlessClient WsClient(string query = "") =>
        VlessClient.FromShareLink($"vless://{Uuid}@example.com:443?type=ws&security=none{query}");

    /// <summary>A VLESS response header (ver=0, addonsLen=0) followed by the target's bytes.</summary>
    private static byte[] VlessResponse(params byte[] payload) => [0x00, 0x00, .. payload];

    /// <summary>
    /// Drives the first read. ConnectAsync deliberately defers the VLESS response header, so
    /// only a read forces the transport to actually carry traffic.
    /// </summary>
    private static async Task DriveFirstRead(Stream tunnel)
    {
        int read = await tunnel.ReadAsync(new byte[16]);
        Assert.True(read > 0, "the transport produced no payload");
    }

    // === handshake ===

    [Fact]
    public async Task Handshake_SendsWellFormedUpgradeRequest()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient("&path=%2Fchat&host=cdn.example.com")
            .ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        string request = server.Request;
        Assert.StartsWith("GET /chat HTTP/1.1\r\n", request);
        Assert.Contains("Host: cdn.example.com\r\n", request);
        Assert.Contains("Upgrade: websocket\r\n", request);
        Assert.Contains("Connection: Upgrade\r\n", request);
        Assert.Contains("Sec-WebSocket-Version: 13\r\n", request);
        Assert.Contains("Sec-WebSocket-Key: ", request);
        Assert.EndsWith("\r\n\r\n", request);
    }

    [Fact]
    public async Task Handshake_PathDefaultsToRoot()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        Assert.StartsWith("GET / HTTP/1.1\r\n", server.Request);
    }

    [Fact]
    public async Task Handshake_SendsPathQueryVerbatim()
    {
        // Xray's early-data feature rides on the path query. Stripping or re-encoding '?ed=2048'
        // makes the server answer 404, so it must survive the round trip untouched.
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient("&path=%2Fws%3Fed%3D2048")
            .ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        Assert.StartsWith("GET /ws?ed=2048 HTTP/1.1\r\n", server.Request);
    }

    [Fact]
    public async Task Handshake_HostHeaderFallsBackToSniThenServerHost()
    {
        var withSni = new FakeWebSocketServer();
        withSni.SendToClient(VlessResponse(0x41));
        var t1 = await WsClient("&sni=sni.example.com")
            .ConnectAsync(withSni, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(t1);
        Assert.Contains("Host: sni.example.com\r\n", withSni.Request);

        var bare = new FakeWebSocketServer();
        bare.SendToClient(VlessResponse(0x41));
        var t2 = await WsClient().ConnectAsync(bare, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(t2);
        Assert.Contains("Host: example.com\r\n", bare.Request);
    }

    [Fact]
    public async Task Handshake_NotUpgraded_Throws()
    {
        // The overwhelmingly common real failure: right server, wrong path.
        var server = new FakeWebSocketServer { StatusLine = "HTTP/1.1 404 Not Found" };

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => WsClient("&path=%2Fwrong")
                .ConnectAsync(server, "example.org", 443, CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.TransportUpgradeFailed, ex.ErrorCode);
        Assert.Contains("404", ex.Message);
    }

    [Fact]
    public async Task Handshake_WrongAccept_Throws()
    {
        var server = new FakeWebSocketServer { AcceptOverride = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" };

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.TransportUpgradeFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task Handshake_MissingAccept_Throws()
    {
        var server = new FakeWebSocketServer { OmitAccept = true };

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None).AsTask());

        Assert.Equal(ProxyErrorCode.TransportUpgradeFailed, ex.ErrorCode);
    }

    [Fact]
    public async Task Handshake_ServerClosesEarly_Throws()
    {
        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            () => WsClient().ConnectAsync(new FakeProxyStream([]), "example.org", 443, CancellationToken.None)
                .AsTask());

        Assert.Equal(ProxyErrorCode.TransportUpgradeFailed, ex.ErrorCode);
    }

    // === framing ===

    [Fact]
    public async Task Ws_WritesProtocolHeaderAsMaskedFrames()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        // FakeWebSocketServer throws on an unmasked frame, so reaching here proves the client
        // masked it. What arrives is the VLESS request with the framing removed.
        byte[] payload = server.PayloadFromClient;
        Assert.Equal(0x00, payload[0]);                       // VLESS version
        Assert.Equal(0x01, payload[18]);                      // TCP command
    }

    [Fact]
    public async Task Ws_ReadsPayloadAcrossFrames()
    {
        // The response header lands in one frame and the payload in another: a byte stream,
        // not a message stream, so the reader must not care where the boundary fell.
        var server = new FakeWebSocketServer();
        server.SendToClient([0x00, 0x00]);
        server.SendToClient([0x41, 0x42, 0x43]);

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal([0x41, 0x42, 0x43], buffer[..read]);
    }

    [Fact]
    public async Task Ws_EmptyFrame_IsNotEndOfStream()
    {
        // A zero-length binary frame is legal. Reporting its 0 as EOF would truncate the
        // tunnel silently — the reader must keep going until real bytes arrive.
        var server = new FakeWebSocketServer();
        server.SendToClient([0x00, 0x00]);
        server.SendToClient([]);
        server.SendToClient([0x5A]);

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal(1, read);
        Assert.Equal(0x5A, buffer[0]);
    }

    [Fact]
    public async Task Ws_CloseFrame_IsEndOfStream()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient([0x00, 0x00, 0x41]);
        server.SendClose();

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        Assert.Equal(1, await tunnel.ReadAsync(buffer));   // the payload byte
        Assert.Equal(0, await tunnel.ReadAsync(buffer));   // then a clean EOF
    }

    [Fact]
    public async Task Ws_LargePayload_SurvivesExtendedLengthFraming()
    {
        // Crosses the 126-byte boundary into 16-bit extended length.
        byte[] payload = new byte[5000];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i % 251);

        var server = new FakeWebSocketServer();
        server.SendToClient([0x00, 0x00]);
        server.SendToClient(payload);

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var received = new byte[payload.Length];
        int total = 0;
        while (total < payload.Length)
        {
            int read = await tunnel.ReadAsync(received.AsMemory(total));
            Assert.True(read > 0, "the stream ended before the payload was complete");
            total += read;
        }

        Assert.Equal(payload, received);

        // And the same size in the other direction.
        await tunnel.WriteAsync(payload);
        Assert.Equal(payload, server.PayloadFromClient[^payload.Length..]);
    }

    [Fact]
    public async Task Handshake_PipelinedBytes_AreNotLost()
    {
        // A server that flushes the first frame together with the 101 must not lose it to the
        // header parser's buffer.
        var server = new FakeWebSocketServer
        {
            PipelinedAfterHandshake = FakeWebSocketServer.EncodeServerFrame([0x00, 0x00, 0x37])
        };

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal(1, read);
        Assert.Equal(0x37, buffer[0]);
    }

    // === httpupgrade ===

    [Fact]
    public async Task HttpUpgrade_CarriesRawBytesWithoutFraming()
    {
        var server = new FakeWebSocketServer(framed: false);
        server.SendToClient(VlessResponse(0x41, 0x42));

        var client = VlessClient.FromShareLink(
            $"vless://{Uuid}@example.com:443?type=httpupgrade&security=none&path=%2Fup");
        var tunnel = await client.ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        int read = await tunnel.ReadAsync(buffer);
        Assert.Equal([0x41, 0x42], buffer[..read]);

        // The request went out unframed, so the VLESS header is the first thing on the wire.
        Assert.StartsWith("GET /up HTTP/1.1\r\n", server.Request);
        Assert.Equal(0x00, server.PayloadFromClient[0]);
        Assert.Equal(0x01, server.PayloadFromClient[18]);
    }

    [Fact]
    public async Task HttpUpgrade_SendsNoWebSocketKey()
    {
        // Not cosmetic: sing-box routes any request carrying Sec-WebSocket-Key to its WebSocket
        // handler, which an httpupgrade inbound does not have, and answers 404. Xray accepts
        // either form, so only running both servers caught it.
        var server = new FakeWebSocketServer(framed: false);
        server.SendToClient(VlessResponse(0x41));

        var client = VlessClient.FromShareLink(
            $"vless://{Uuid}@example.com:443?type=httpupgrade&security=none");
        var tunnel = await client.ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        Assert.DoesNotContain("Sec-WebSocket-Key", server.Request, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sec-WebSocket-Version", server.Request, StringComparison.OrdinalIgnoreCase);

        // The camouflage that does not break sing-box stays: the request still reads as an
        // ordinary upgrade to anything in the middle.
        Assert.Contains("Upgrade: websocket\r\n", server.Request);
        Assert.Contains("Connection: Upgrade\r\n", server.Request);
    }

    [Fact]
    public async Task Ws_SendsWebSocketKey()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient().ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        Assert.Contains("Sec-WebSocket-Key: ", server.Request);
    }

    [Fact]
    public async Task HttpUpgrade_AcceptsResponseWithoutAcceptHeader()
    {
        // An httpupgrade server is not a WebSocket endpoint and need not prove it is one.
        var server = new FakeWebSocketServer(framed: false) { OmitAccept = true };
        server.SendToClient(VlessResponse(0x41));

        var client = VlessClient.FromShareLink(
            $"vless://{Uuid}@example.com:443?type=httpupgrade&security=none");
        var tunnel = await client.ConnectAsync(server, "example.org", 443, CancellationToken.None);

        var buffer = new byte[16];
        Assert.Equal(1, await tunnel.ReadAsync(buffer));
    }

    // === parsing ===

    [Theory]
    [InlineData("vless://u@h:1?type=ws&path=%2Fa%2Fb", "/a/b")]
    [InlineData("vless://u@h:1?type=ws&path=a%2Fb", "a/b")]
    [InlineData("vless://u@h:1?type=ws", null)]
    public void Parse_CapturesPath(string link, string? expected)
    {
        Assert.Equal(expected, VlessShareLink.Parse(link).Path);
    }

    [Fact]
    public void Parse_CapturesHostHeader()
    {
        Assert.Equal("cdn.example.com",
            VlessShareLink.Parse("vless://u@h:1?type=ws&host=cdn.example.com").HostHeader);
    }

    [Fact]
    public void Parse_Trojan_CapturesPathAndHost()
    {
        var o = TrojanShareLink.Parse("trojan://pw@h:443?type=ws&path=%2Ftj&host=cdn.example.com");
        Assert.Equal("/tj", o.Path);
        Assert.Equal("cdn.example.com", o.HostHeader);
    }
}
