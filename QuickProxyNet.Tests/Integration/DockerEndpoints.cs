namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// The host-port map and the synthetic credentials of <c>tests/docker/docker-compose.yml</c>.
/// </summary>
/// <remarks>
/// Every value here is test data committed on purpose: the UUIDs are repdigit placeholders and
/// the Trojan password is a literal string. Nothing here is or ever was a real credential.
/// Keep this in sync with <c>tests/docker/README.md</c> and the two server configs.
/// </remarks>
public static class DockerEndpoints
{
    /// <summary>Server implementation under test.</summary>
    public enum Server
    {
        /// <summary>ghcr.io/xtls/xray-core</summary>
        Xray,

        /// <summary>ghcr.io/sagernet/sing-box</summary>
        SingBox
    }

    /// <summary>Host name of the HTTP target inside the compose network.</summary>
    public const string EchoHost = "echo";

    /// <summary>Port of the HTTP target inside the compose network.</summary>
    public const int EchoPort = 8080;

    /// <summary>The exact body the echo target answers a <c>GET /</c> with.</summary>
    public const string EchoBody = "QPN-ECHO-OK";

    /// <summary>SNI presented to the TLS inbounds; a SAN of the committed test certificate.</summary>
    public const string TlsSni = "qpn.test";

    /// <summary>Subject CN of the committed self-signed test certificate.</summary>
    public const string TestCertSubjectCn = "QuickProxyNet Test";

    public const string VlessNoneId = "11111111-1111-4111-8111-111111111111";
    public const string VlessTlsId = "22222222-2222-4222-8222-222222222222";
    public const string VmessAesId = "33333333-3333-4333-8333-333333333333";
    public const string VmessChachaId = "44444444-4444-4444-8444-444444444444";
    public const string VlessWsId = "55555555-5555-4555-8555-555555555555";
    public const string VmessWsId = "66666666-6666-4666-8666-666666666666";
    public const string VlessHttpUpgradeId = "77777777-7777-4777-8777-777777777777";
    public const string TrojanPassword = "qpn-test-trojan-password";
    public const string ShadowsocksPassword = "qpn-test-ss-password";

    /// <summary>
    /// Paths the ws/httpupgrade inbounds are configured with. A WebSocket server only upgrades
    /// on its exact configured path, so these must match the two server configs verbatim.
    /// </summary>
    public const string VlessWsPath = "/qpn-ws";
    public const string VmessWsPath = "/qpn-vmess-ws";
    public const string TrojanWsPath = "/qpn-trojan-ws";
    public const string HttpUpgradePath = "/qpn-hu";

    /// <summary>
    /// The short non-UUID VLESS id configured on the Xray inbound at
    /// <see cref="XrayVlessNonUuid"/>. Xray maps it to <c>UUIDv5(nil-namespace, utf8(id))</c>;
    /// <c>UuidCodec</c> must produce the same 16 bytes or the handshake is rejected.
    /// </summary>
    public const string NonUuidId = "not-a-uuid";

    // Xray: container ports 10001..10010 -> host 24801..24810.
    public const int XrayVlessNone = 24801;
    public const int XrayVlessTls = 24802;
    public const int XrayTrojan = 24803;
    public const int XrayVmessAes = 24804;
    public const int XrayVmessChacha = 24805;
    public const int XrayVlessNonUuid = 24806;
    public const int XrayVlessWs = 24807;
    public const int XrayVmessWs = 24808;
    public const int XrayTrojanWs = 24809;
    public const int XrayVlessHttpUpgrade = 24810;

    // sing-box: container ports 10001..10010 -> host 24811..24820.
    public const int SingBoxVlessNone = 24811;
    public const int SingBoxVlessTls = 24812;
    public const int SingBoxTrojan = 24813;
    public const int SingBoxVmessAes = 24814;
    public const int SingBoxVmessChacha = 24815;
    public const int SingBoxVlessWs = 24817;
    public const int SingBoxVmessWs = 24818;
    public const int SingBoxTrojanWs = 24819;
    public const int SingBoxVlessHttpUpgrade = 24820;

    // Shadowsocks: container ports 10011..10014. The +24800/+24810 arithmetic of the first decade
    // cannot hold for both servers past 10010, so each server gets a fresh decade: xray 2482x,
    // sing-box 2483x. aes-192-gcm exists on sing-box only — Xray has no such cipher.
    public const int XrayShadowsocksAes256 = 24821;
    public const int XrayShadowsocksChacha = 24822;
    public const int XrayShadowsocksAes128 = 24823;
    public const int SingBoxShadowsocksAes256 = 24831;
    public const int SingBoxShadowsocksChacha = 24832;
    public const int SingBoxShadowsocksAes128 = 24833;
    public const int SingBoxShadowsocksAes192 = 24834;

    /// <summary>Every mapped host port, used as the readiness probe list.</summary>
    public static readonly (int Port, string Description)[] All =
    [
        (XrayVlessNone, "xray vless security=none"),
        (XrayVlessTls, "xray vless security=tls"),
        (XrayTrojan, "xray trojan"),
        (XrayVmessAes, "xray vmess (aes-128-gcm)"),
        (XrayVmessChacha, "xray vmess (chacha20-poly1305)"),
        (XrayVlessNonUuid, "xray vless with non-UUID id"),
        (SingBoxVlessNone, "sing-box vless security=none"),
        (SingBoxVlessTls, "sing-box vless security=tls"),
        (SingBoxTrojan, "sing-box trojan"),
        (SingBoxVmessAes, "sing-box vmess (aes-128-gcm)"),
        (SingBoxVmessChacha, "sing-box vmess (chacha20-poly1305)"),
        (XrayVlessWs, "xray vless over ws"),
        (XrayVmessWs, "xray vmess over ws"),
        (XrayTrojanWs, "xray trojan over ws"),
        (XrayVlessHttpUpgrade, "xray vless over httpupgrade"),
        (SingBoxVlessWs, "sing-box vless over ws"),
        (SingBoxVmessWs, "sing-box vmess over ws"),
        (SingBoxTrojanWs, "sing-box trojan over ws"),
        (SingBoxVlessHttpUpgrade, "sing-box vless over httpupgrade"),
        (XrayShadowsocksAes256, "xray shadowsocks aes-256-gcm"),
        (XrayShadowsocksChacha, "xray shadowsocks chacha20-ietf-poly1305"),
        (XrayShadowsocksAes128, "xray shadowsocks aes-128-gcm"),
        (SingBoxShadowsocksAes256, "sing-box shadowsocks aes-256-gcm"),
        (SingBoxShadowsocksChacha, "sing-box shadowsocks chacha20-ietf-poly1305"),
        (SingBoxShadowsocksAes128, "sing-box shadowsocks aes-128-gcm"),
        (SingBoxShadowsocksAes192, "sing-box shadowsocks aes-192-gcm")
    ];

    public static int VlessNonePort(Server server) => server is Server.Xray ? XrayVlessNone : SingBoxVlessNone;
    public static int VlessTlsPort(Server server) => server is Server.Xray ? XrayVlessTls : SingBoxVlessTls;
    public static int TrojanPort(Server server) => server is Server.Xray ? XrayTrojan : SingBoxTrojan;
    public static int VmessAesPort(Server server) => server is Server.Xray ? XrayVmessAes : SingBoxVmessAes;
    public static int VmessChachaPort(Server server) => server is Server.Xray ? XrayVmessChacha : SingBoxVmessChacha;
    public static int VlessWsPort(Server server) => server is Server.Xray ? XrayVlessWs : SingBoxVlessWs;
    public static int VmessWsPort(Server server) => server is Server.Xray ? XrayVmessWs : SingBoxVmessWs;
    public static int TrojanWsPort(Server server) => server is Server.Xray ? XrayTrojanWs : SingBoxTrojanWs;

    public static int VlessHttpUpgradePort(Server server) =>
        server is Server.Xray ? XrayVlessHttpUpgrade : SingBoxVlessHttpUpgrade;

    public static int ShadowsocksAes256Port(Server server) =>
        server is Server.Xray ? XrayShadowsocksAes256 : SingBoxShadowsocksAes256;

    public static int ShadowsocksChachaPort(Server server) =>
        server is Server.Xray ? XrayShadowsocksChacha : SingBoxShadowsocksChacha;

    public static int ShadowsocksAes128Port(Server server) =>
        server is Server.Xray ? XrayShadowsocksAes128 : SingBoxShadowsocksAes128;
}
