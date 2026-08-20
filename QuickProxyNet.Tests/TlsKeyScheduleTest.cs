using System.Security.Cryptography;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests the TLS 1.3 key schedule against RFC 8448's published trace.
/// </summary>
/// <remarks>
/// RFC 8448 prints every intermediate value of a real handshake, which makes the key schedule one
/// of the few parts of this work that can be verified completely offline. The values below are
/// from §3, "Simple 1-RTT Handshake", with TLS_AES_128_GCM_SHA256.
/// </remarks>
public class TlsKeyScheduleTest
{
    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    private static byte[] Hex(string hex) =>
        Convert.FromHexString(hex.Replace(" ", "").Replace("\n", ""));

    private static string Show(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private const string EarlySecret = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    private const string DerivedForHandshake = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
    private const string EcdheSharedSecret = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    private const string HandshakeSecret = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    private const string DerivedForMaster = "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";
    private const string MasterSecret = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    private const string ClientHandshakeTraffic = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    private const string ServerHandshakeTraffic = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";

    /// <summary>SHA-256 of the empty string, the context for every "derived" step.</summary>
    private const string EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    [Fact]
    public void EarlySecret_MatchesRfc8448()
    {
        Span<byte> secret = stackalloc byte[32];
        TlsKeySchedule.Extract(Sha256, salt: new byte[32], inputKeyMaterial: new byte[32], secret);

        Assert.Equal(EarlySecret, Show(secret));
    }

    [Fact]
    public void DerivedForHandshake_MatchesRfc8448()
    {
        Span<byte> derived = stackalloc byte[32];
        TlsKeySchedule.DeriveSecret(Sha256, Hex(EarlySecret), "derived"u8, Hex(EmptyHash), derived);

        Assert.Equal(DerivedForHandshake, Show(derived));
    }

    [Fact]
    public void HandshakeSecret_MatchesRfc8448()
    {
        Span<byte> secret = stackalloc byte[32];
        TlsKeySchedule.Extract(Sha256, Hex(DerivedForHandshake), Hex(EcdheSharedSecret), secret);

        Assert.Equal(HandshakeSecret, Show(secret));
    }

    [Fact]
    public void MasterSecret_MatchesRfc8448()
    {
        Span<byte> derived = stackalloc byte[32];
        TlsKeySchedule.DeriveSecret(Sha256, Hex(HandshakeSecret), "derived"u8, Hex(EmptyHash), derived);
        Assert.Equal(DerivedForMaster, Show(derived));

        Span<byte> master = stackalloc byte[32];
        TlsKeySchedule.Extract(Sha256, derived, new byte[32], master);
        Assert.Equal(MasterSecret, Show(master));
    }

    [Fact]
    public void HandshakeTrafficKeys_MatchRfc8448()
    {
        Span<byte> key = stackalloc byte[16];
        Span<byte> iv = stackalloc byte[12];
        TlsKeySchedule.TrafficKeys(Sha256, Hex(ClientHandshakeTraffic), key, iv);

        Assert.Equal("dbfaa693d1762c5b666af5d950258d01", Show(key));
        Assert.Equal("5bd3c71b836e0b76bb73265f", Show(iv));
    }

    [Fact]
    public void ApplicationTrafficSecrets_MatchRfc8448()
    {
        const string transcript = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";

        Span<byte> clientApplication = stackalloc byte[32];
        TlsKeySchedule.DeriveSecret(Sha256, Hex(MasterSecret), "c ap traffic"u8, Hex(transcript), clientApplication);
        Assert.Equal("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5", Show(clientApplication));

        Span<byte> serverApplication = stackalloc byte[32];
        TlsKeySchedule.DeriveSecret(Sha256, Hex(MasterSecret), "s ap traffic"u8, Hex(transcript), serverApplication);
        Assert.Equal("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643", Show(serverApplication));

        Span<byte> key = stackalloc byte[16];
        Span<byte> iv = stackalloc byte[12];
        TlsKeySchedule.TrafficKeys(Sha256, serverApplication, key, iv);
        Assert.Equal("9f02283b6c9c07efc26bb9f2ac92e356", Show(key));
        Assert.Equal("cf782b88dd83549aadf1e984", Show(iv));
    }

    /// <summary>
    /// The finished key, from the same trace. RFC 8448 prints the intermediate expansion, so this
    /// pins <see cref="TlsKeySchedule.ExpandLabel"/> with an empty context independently.
    /// </summary>
    [Fact]
    public void FinishedKey_MatchesRfc8448()
    {
        Span<byte> finishedKey = stackalloc byte[32];
        TlsKeySchedule.ExpandLabel(Sha256, Hex(ServerHandshakeTraffic), "finished"u8, default, finishedKey);

        Assert.Equal("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8", Show(finishedKey));
    }

    /// <summary>
    /// The sequence number is xored into the low eight bytes of the IV, so record zero uses the
    /// IV unchanged. Getting this wrong produces a connection that decrypts exactly one record.
    /// </summary>
    [Fact]
    public void Nonce_XorsTheSequenceNumberIntoTheTail()
    {
        byte[] iv = Hex("5bd3c71b836e0b76bb73265f");

        Span<byte> nonce = stackalloc byte[12];
        TlsKeySchedule.BuildNonce(nonce, iv, 0);
        Assert.Equal("5bd3c71b836e0b76bb73265f", Show(nonce));

        TlsKeySchedule.BuildNonce(nonce, iv, 1);
        Assert.Equal("5bd3c71b836e0b76bb73265e", Show(nonce));

        // The eight sequence bytes line up with iv[4..], big-endian: 83^01, 6e^02, 0b^03, 76^04,
        // bb^05, 73^06, 26^07, 5f^08.
        TlsKeySchedule.BuildNonce(nonce, iv, 0x0102030405060708);
        Assert.Equal("5bd3c71b826c0872be752157", Show(nonce));
    }
}
