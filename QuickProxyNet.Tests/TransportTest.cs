using System.Text;
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

    // === what the configuration puts into the request ===

    /// <summary>
    /// The path and the Host header went into the upgrade request as they were, and a link decodes
    /// %0D%0A to CR LF, so each of these links sent its node's server, or the CDN in front of it, a
    /// header of the link's writing. Every family refuses them where the link is parsed, on both
    /// transports and in every field the Host header comes from.
    /// </summary>
    [Theory]
    [InlineData("vless://" + Uuid + "@example.com:443?type=ws&path=%2Fws%0D%0AX-Injected:%20yes")]
    [InlineData("vless://" + Uuid + "@example.com:443?type=httpupgrade&host=cdn.example.com%0D%0AX-Injected:%20yes")]
    [InlineData("vless://" + Uuid + "@example.com:443?type=ws&sni=cdn.example.com%0D%0AX-Injected:%20yes")]
    [InlineData("trojan://password@example.com:443?type=ws&path=%2Fws%0AX-Injected:%20yes")]
    [InlineData("trojan://password@example.com:443?type=httpupgrade&host=cdn.example.com%00X-Injected")]
    [InlineData("vmess://" + Uuid + "@example.com:443?type=ws&path=%2Fws%0D%0AX-Injected:%20yes")]
    [InlineData("vmess://" + Uuid + "@example.com:443?type=httpupgrade&host=cdn.example.com%7FX-Injected")]
    public void Parse_ControlCharacterInPathOrHostHeader_IsRefused(string link)
    {
        var ex = Assert.Throws<FormatException>(() => Proxy.Create(link));

        Assert.Contains("control character", ex.Message);
        Assert.DoesNotContain("Injected", ex.Message);
    }

    /// <summary>The JSON grammar carries the characters themselves rather than escapes of them.</summary>
    [Theory]
    [InlineData("\"path\":\"/ws\\r\\nX-Injected: yes\"")]
    [InlineData("\"host\":\"cdn.example.com\\r\\nX-Injected: yes\"")]
    [InlineData("\"sni\":\"cdn.example.com\\nX-Injected: yes\"")]
    public void Parse_VmessJsonWithControlCharacterInPathOrHostHeader_IsRefused(string field)
    {
        string json = $$"""{"add":"example.com","port":"443","id":"{{Uuid}}","aid":"0","net":"ws",{{field}}}""";
        string link = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

        Assert.False(VmessShareLink.TryParse(link, out _));
        var ex = Assert.Throws<FormatException>(() => Proxy.Create(link));

        // Refused by the check, not for JSON that could not be read.
        Assert.Contains("control character", ex.Message);
        Assert.DoesNotContain("Injected", ex.Message);
    }

    /// <summary>
    /// Options built by hand are refused by the constructor: each character that ends or breaks a
    /// request line or a header line, in the path and in each field the Host header comes from.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x09)]
    [InlineData(0x0A)]
    [InlineData(0x0D)]
    [InlineData(0x1F)]
    [InlineData(0x7F)]
    public void Client_ControlCharacterInPathOrHostHeader_IsRefusedByTheConstructor(int character)
    {
        string bad = $"cdn{(char)character}example.com";

        foreach (string transport in new[] { "ws", "httpupgrade" })
        {
            Func<object>[] constructors =
            [
                () => new VlessClient(new VlessOptions { Id = Uuid, Host = "example.com", Port = 443, Transport = transport, Path = "/" + bad }),
                () => new VlessClient(new VlessOptions { Id = Uuid, Host = "example.com", Port = 443, Transport = transport, HostHeader = bad }),
                () => new VlessClient(new VlessOptions { Id = Uuid, Host = "example.com", Port = 443, Transport = transport, Sni = bad }),
                () => new TrojanClient(new TrojanOptions { Password = "password", Host = "example.com", Port = 443, Transport = transport, Path = "/" + bad }),
                () => new TrojanClient(new TrojanOptions { Password = "password", Host = "example.com", Port = 443, Transport = transport, HostHeader = bad }),
                () => new VmessClient(new VmessOptions { Id = Uuid, Host = "example.com", Port = 443, Transport = transport, Path = "/" + bad }),
                () => new VmessClient(new VmessOptions { Id = Uuid, Host = "example.com", Port = 443, Transport = transport, Sni = bad }),
            ];

            foreach (Func<object> construct in constructors)
            {
                var ex = Assert.Throws<ArgumentException>(construct);
                Assert.Equal("options", ex.ParamName);
                Assert.Contains($"U+{character:X4} at index", ex.Message);
            }
        }
    }

    /// <summary>
    /// Only ws and httpupgrade write the path and the Host header. A raw-TCP link with junk in them
    /// sends neither, so it still parses and still builds a client.
    /// </summary>
    [Fact]
    public void Parse_ControlCharacterInFieldsTheTransportNeverSends_IsLeftAlone()
    {
        VlessOptions options = VlessShareLink.Parse($"vless://{Uuid}@example.com:443?type=tcp&path=%2Fws%0D%0A&host=a%00b");

        Assert.Equal("/ws\r\n", options.Path);
        _ = new VlessClient(options);
    }

    /// <summary>
    /// A request target cannot hold a space: the request line ends at it. A link's path is
    /// percent-decoded, so its %20 arrived as a space and went out raw. It goes out as %20 again,
    /// which is what Go's net/url writes for Xray's client and what the server decodes back.
    /// </summary>
    [Fact]
    public async Task Handshake_SpaceInPath_IsSentPercentEncoded()
    {
        var server = new FakeWebSocketServer();
        server.SendToClient(VlessResponse(0x41));

        var tunnel = await WsClient("&path=%2Fa%20b%3Fed%3D2048")
            .ConnectAsync(server, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(tunnel);

        Assert.StartsWith("GET /a%20b?ed=2048 HTTP/1.1\r\n", server.Request);

        // Built by hand too, over httpupgrade, and without the leading slash.
        var upgrade = new FakeWebSocketServer(framed: false);
        upgrade.SendToClient(VlessResponse(0x41));
        var client = new VlessClient(new VlessOptions
        {
            Id = Uuid, Host = "example.com", Port = 443, Transport = "httpupgrade", Path = "a b c"
        });

        var upgraded = await client.ConnectAsync(upgrade, "example.org", 443, CancellationToken.None);
        await DriveFirstRead(upgraded);

        Assert.StartsWith("GET /a%20b%20c HTTP/1.1\r\n", upgrade.Request);
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
