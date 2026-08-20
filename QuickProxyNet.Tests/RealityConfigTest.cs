using System.Diagnostics;
using System.Text.Json;
using QuickProxyNet.Reality;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the Xray client configuration that <see cref="RealityProxy"/> generates.
/// </summary>
/// <remarks>
/// These are the tests that can be exact. The configuration is a pure function of
/// <see cref="VlessOptions"/>, so every field can be asserted without a process, a port or a
/// network. What they cannot prove is that Xray <i>accepts</i> the document — that is what
/// <see cref="Config_IsAcceptedByXray"/> and the integration tests are for.
/// </remarks>
public class RealityConfigTest
{
    private const string Uuid = "6643f196-ae07-420a-b173-d909d20807c1";

    // Synthetic REALITY keypair, generated with 'xray x25519' for this test suite and committed
    // on purpose — same status as the repdigit UUIDs and the self-signed cert under
    // tests/docker/certs. It protects nothing and never guarded a real server.
    private const string PublicKey = "BhsV4NiigG9rrk98hJnJHPJ7TQ6Iy1WqUykGF0z9I2g";
    private const string ShortId = "ab12";

    private static JsonElement Build(string shareLink, int port = 21080)
    {
        byte[] json = XrayClientConfig.Build(VlessShareLink.Parse(shareLink), "127.0.0.1", port, "warning");
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static string RealityLink(string extra = "") =>
        $"vless://{Uuid}@example.com:443?security=reality&pbk={PublicKey}&sid={ShortId}" +
        $"&sni=www.cloudflare.com&fp=chrome{extra}#node";

    // REALITY runs only over raw TCP, so the transport tests use a plain TLS link instead.
    private static string TlsLink(string extra = "") =>
        $"vless://{Uuid}@example.com:443?security=tls&sni=www.cloudflare.com&fp=chrome{extra}#node";

    private static JsonElement Outbound(JsonElement root) =>
        root.GetProperty("outbounds")[0];

    private static JsonElement Stream(JsonElement root) =>
        Outbound(root).GetProperty("streamSettings");

    [Fact]
    public void Reality_RendersRealitySettings()
    {
        JsonElement stream = Stream(Build(RealityLink()));

        Assert.Equal("reality", stream.GetProperty("security").GetString());
        Assert.Equal("tcp", stream.GetProperty("network").GetString());

        JsonElement reality = stream.GetProperty("realitySettings");
        Assert.Equal("www.cloudflare.com", reality.GetProperty("serverName").GetString());
        Assert.Equal("chrome", reality.GetProperty("fingerprint").GetString());
        Assert.Equal(PublicKey, reality.GetProperty("publicKey").GetString());
        Assert.Equal(ShortId, reality.GetProperty("shortId").GetString());
    }

    [Fact]
    public void Reality_RendersVnextUser()
    {
        JsonElement vnext = Outbound(Build(RealityLink())).GetProperty("settings").GetProperty("vnext")[0];

        Assert.Equal("example.com", vnext.GetProperty("address").GetString());
        Assert.Equal(443, vnext.GetProperty("port").GetInt32());

        JsonElement user = vnext.GetProperty("users")[0];
        Assert.Equal(Uuid, user.GetProperty("id").GetString());
        Assert.Equal("none", user.GetProperty("encryption").GetString());
    }

    // An empty fingerprint makes Xray skip uTLS and emit Go's own ClientHello — the single most
    // recognisable handshake a REALITY client can produce. Defaulting it is a safety behaviour,
    // so it gets a test rather than being left to the reader of the source.
    [Fact]
    public void Reality_WithoutFingerprint_DefaultsToChrome()
    {
        string link = $"vless://{Uuid}@example.com:443?security=reality&pbk={PublicKey}&sid={ShortId}&sni=a.example#n";
        JsonElement reality = Stream(Build(link)).GetProperty("realitySettings");

        Assert.Equal("chrome", reality.GetProperty("fingerprint").GetString());
    }

    [Fact]
    public void Reality_WithoutSni_FallsBackToHost()
    {
        string link = $"vless://{Uuid}@example.com:443?security=reality&pbk={PublicKey}&sid={ShortId}#n";
        JsonElement reality = Stream(Build(link)).GetProperty("realitySettings");

        Assert.Equal("example.com", reality.GetProperty("serverName").GetString());
    }

    [Fact]
    public void Vision_FlowIsPassedThrough()
    {
        JsonElement user = Outbound(Build(RealityLink("&flow=xtls-rprx-vision")))
            .GetProperty("settings").GetProperty("vnext")[0].GetProperty("users")[0];

        Assert.Equal("xtls-rprx-vision", user.GetProperty("flow").GetString());
    }

    [Fact]
    public void NoFlow_OmitsFlowEntirely()
    {
        JsonElement user = Outbound(Build(RealityLink()))
            .GetProperty("settings").GetProperty("vnext")[0].GetProperty("users")[0];

        // Present-but-empty is not the same as absent: Xray rejects an unknown empty flow.
        Assert.False(user.TryGetProperty("flow", out _));
    }

    [Fact]
    public void WebSocket_RendersWsSettings()
    {
        JsonElement stream = Stream(Build(TlsLink("&type=ws&path=%2Fqpn-ws&host=cdn.example")));

        Assert.Equal("ws", stream.GetProperty("network").GetString());
        JsonElement ws = stream.GetProperty("wsSettings");
        Assert.Equal("/qpn-ws", ws.GetProperty("path").GetString());
        Assert.Equal("cdn.example", ws.GetProperty("host").GetString());
    }

    [Fact]
    public void HttpUpgrade_RendersHttpUpgradeSettings()
    {
        JsonElement stream = Stream(Build(TlsLink("&type=httpupgrade&path=%2Fqpn-hu")));

        Assert.Equal("httpupgrade", stream.GetProperty("network").GetString());
        Assert.Equal("/qpn-hu", stream.GetProperty("httpupgradeSettings").GetProperty("path").GetString());
    }

    [Fact]
    public void Inbound_IsLoopbackSocksWithoutAuth()
    {
        JsonElement inbound = Build(RealityLink(), port: 31234).GetProperty("inbounds")[0];

        Assert.Equal("socks", inbound.GetProperty("protocol").GetString());
        Assert.Equal("127.0.0.1", inbound.GetProperty("listen").GetString());
        Assert.Equal(31234, inbound.GetProperty("port").GetInt32());
        Assert.Equal("noauth", inbound.GetProperty("settings").GetProperty("auth").GetString());
        Assert.False(inbound.GetProperty("settings").GetProperty("udp").GetBoolean());
    }

    [Fact]
    public void Tls_RendersTlsSettingsInsteadOfReality()
    {
        string link = $"vless://{Uuid}@example.com:443?security=tls&sni=a.example&flow=xtls-rprx-vision#n";
        JsonElement stream = Stream(Build(link));

        Assert.Equal("tls", stream.GetProperty("security").GetString());
        Assert.Equal("a.example", stream.GetProperty("tlsSettings").GetProperty("serverName").GetString());
        Assert.False(stream.TryGetProperty("realitySettings", out _));
    }

    // The whole point of the package is that it never quietly does something weaker than the
    // link asked for. Each of these would otherwise connect with less protection than intended.
    [Fact]
    public void PlainVless_IsRefusedAndNamesTheAlternative()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => Build($"vless://{Uuid}@example.com:443?security=none#n"));

        Assert.Contains("VlessClient", ex.Message);
    }

    /// <summary>
    /// REALITY exists only over raw TCP (plus xhttp and gRPC in Xray). A link combining it with a
    /// WebSocket transport describes something no server can serve.
    /// </summary>
    /// <remarks>
    /// Learned the hard way: an earlier version of the builder happily rendered
    /// <c>security=reality</c> with <c>type=ws</c>, and Xray refused the document at startup with
    /// "REALITY only supports RAW, XHTTP and gRPC for now" — which reached the caller as an opaque
    /// launch failure.
    /// </remarks>
    [Theory]
    [InlineData("ws")]
    [InlineData("httpupgrade")]
    public void RealityOverAWebTransport_IsRefused(string transport)
    {
        var ex = Assert.Throws<NotSupportedException>(() => Build(RealityLink($"&type={transport}")));

        Assert.Contains("raw/tcp", ex.Message);
    }

    [Fact]
    public void Reality_WithoutPublicKey_IsRefused()
    {
        var options = new VlessOptions
        {
            Id = Uuid,
            Host = "example.com",
            Port = 443,
            Security = VlessSecurity.Reality
        };

        var ex = Assert.Throws<NotSupportedException>(
            () => XrayClientConfig.Build(options, "127.0.0.1", 21080, "warning"));

        Assert.Contains("public key", ex.Message);
    }

    [Fact]
    public void UnmodelledTransport_IsRefusedAndListsWhatWorks()
    {
        var ex = Assert.Throws<NotSupportedException>(() => Build(TlsLink("&type=grpc")));

        Assert.Contains("httpupgrade", ex.Message);
    }

    /// <summary>
    /// Feeds the generated document to the real Xray binary's own validator.
    /// </summary>
    /// <remarks>
    /// Every other test in this class checks the JSON against my belief about what Xray wants.
    /// This one checks it against Xray. It needs no network and no server — <c>run -test</c>
    /// parses the configuration and exits — so it is the cheapest test here that can falsify
    /// the field names.
    /// </remarks>
    [EnvFact(RealityProxyOptions.ExecutablePathVariable)]
    public async Task Config_IsAcceptedByXray()
    {
        byte[] config = XrayClientConfig.Build(
            VlessShareLink.Parse(RealityLink("&flow=xtls-rprx-vision")),
            "127.0.0.1", 21080, "warning");

        string executable = Environment.GetEnvironmentVariable(RealityProxyOptions.ExecutablePathVariable)!;
        var psi = new ProcessStartInfo(executable)
        {
            ArgumentList = { "run", "-test", "-c", "stdin:" },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)!;
        await process.StandardInput.BaseStream.WriteAsync(config);
        process.StandardInput.Close();

        string output = await process.StandardOutput.ReadToEndAsync() +
                        await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        Assert.True(process.ExitCode == 0, $"Xray rejected the generated configuration:\n{output}");
    }
}
