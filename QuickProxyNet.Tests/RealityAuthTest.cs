using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the REALITY authentication construction.
/// </summary>
/// <remarks>
/// <para>
/// Each test seals with our client code and opens with the <b>server</b> algorithm transcribed
/// from <c>XTLS/REALITY</c>'s <c>tls.go</c>, written out separately below. A round-trip against
/// our own sealing routine would prove only that the code agrees with itself; opening with the
/// server's steps is what pins the field layout, the nonce, and the AAD.
/// </para>
/// <para>
/// It is still not the same as talking to a real server — that is what the integration tests are
/// for — but it is the part that can be made exact without a network.
/// </para>
/// </remarks>
public class RealityAuthTest
{
    private static readonly byte[] ClientVersion = [26, 3, 27];

    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    /// <summary>
    /// Builds a buffer shaped like a raw ClientHello: handshake header, legacy version, random,
    /// and a 32-byte session id, followed by arbitrary trailing bytes that stand in for the rest
    /// of the message and are covered by the AAD.
    /// </summary>
    private static byte[] FakeClientHello(int trailingBytes = 200)
    {
        byte[] hello = new byte[RealityAuth.SessionIdOffset + RealityAuth.SessionIdSize + trailingBytes];

        hello[0] = 1; // handshake type: client_hello
        BinaryPrimitives.WriteUInt32BigEndian(hello.AsSpan(0), (uint)(hello.Length - 4));
        hello[0] = 1;
        hello[4] = 3;
        hello[5] = 3; // legacy_version

        RandomNumberGenerator.Fill(hello.AsSpan(6, 32));           // random
        hello[38] = RealityAuth.SessionIdSize;                     // session id length
        RandomNumberGenerator.Fill(hello.AsSpan(RealityAuth.SessionIdOffset + RealityAuth.SessionIdSize));

        return hello;
    }

    /// <summary>
    /// The server side, transcribed from <c>XTLS/REALITY</c> <c>tls.go</c>: derive the key from
    /// the server's private key and the client's <c>key_share</c>, then open the session id with
    /// the hello — session id zeroed — as additional data.
    /// </summary>
    private static bool TryOpenAsServer(
        ReadOnlySpan<byte> hello,
        ReadOnlySpan<byte> serverPrivateKey,
        ReadOnlySpan<byte> clientPublicKey,
        Span<byte> plaintext,
        out byte[] authKey)
    {
        authKey = new byte[RealityAuth.AuthKeySize];
        Span<byte> shared = stackalloc byte[32];
        X25519.Agree(shared, serverPrivateKey, clientPublicKey);

        ReadOnlySpan<byte> clientRandom = hello.Slice(6, 32);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, authKey, clientRandom[..20], "REALITY"u8);

        byte[] ciphertext = hello.Slice(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize).ToArray();

        byte[] additionalData = hello.ToArray();
        additionalData.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize).Clear();

        using var aes = new AesGcm(authKey, tagSizeInBytes: 16);
        try
        {
            aes.Decrypt(clientRandom[20..], ciphertext.AsSpan(0, 16), ciphertext.AsSpan(16), plaintext, additionalData);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    [Fact]
    public void SealedSessionId_OpensWithTheServerAlgorithm()
    {
        byte[] serverPrivate = Base64Url(Integration.LocalRealityServer.PrivateKey);
        byte[] serverPublic = Base64Url(Integration.LocalRealityServer.PublicKey);

        byte[] clientPrivate = new byte[32], clientPublic = new byte[32];
        X25519.GenerateKeyPair(clientPrivate, clientPublic);

        byte[] hello = FakeClientHello();
        byte[] clientAuthKey = new byte[RealityAuth.AuthKeySize];
        RealityAuth.DeriveAuthKey(clientAuthKey, clientPrivate, serverPublic, hello.AsSpan(6, 32));

        byte[] shortId = new byte[RealityAuth.ShortIdSize];
        RealityAuth.ParseShortId(shortId, Integration.LocalRealityServer.ShortId);

        uint timestamp = 1_760_000_000;
        RealityAuth.SealSessionId(hello, clientAuthKey, shortId, timestamp, ClientVersion);

        byte[] plaintext = new byte[16];
        Assert.True(TryOpenAsServer(hello, serverPrivate, clientPublic, plaintext, out byte[] serverAuthKey));

        // Both sides must land on the same key, or nothing downstream can work.
        Assert.Equal(clientAuthKey, serverAuthKey);

        Assert.Equal(ClientVersion, plaintext[..3]);
        Assert.Equal(0, plaintext[3]);
        Assert.Equal(timestamp, BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan(4)));
        Assert.Equal(shortId, plaintext[8..16]);
    }

    /// <summary>
    /// The AAD binds the blob to this exact ClientHello. Without it a censor could lift a sealed
    /// session id out of a recorded handshake and replay it inside a hello of its own choosing.
    /// </summary>
    [Fact]
    public void TamperingWithTheHello_BreaksTheTag()
    {
        byte[] serverPrivate = Base64Url(Integration.LocalRealityServer.PrivateKey);
        byte[] serverPublic = Base64Url(Integration.LocalRealityServer.PublicKey);

        byte[] clientPrivate = new byte[32], clientPublic = new byte[32];
        X25519.GenerateKeyPair(clientPrivate, clientPublic);

        byte[] hello = FakeClientHello();
        byte[] authKey = new byte[RealityAuth.AuthKeySize];
        RealityAuth.DeriveAuthKey(authKey, clientPrivate, serverPublic, hello.AsSpan(6, 32));

        byte[] shortId = new byte[RealityAuth.ShortIdSize];
        RealityAuth.ParseShortId(shortId, "ab12");
        RealityAuth.SealSessionId(hello, authKey, shortId, 1_760_000_000, ClientVersion);

        // A single flipped bit anywhere past the session id.
        hello[^1] ^= 0x01;

        byte[] plaintext = new byte[16];
        Assert.False(TryOpenAsServer(hello, serverPrivate, clientPublic, plaintext, out _));
    }

    [Fact]
    public void WrongServerKey_DoesNotOpen()
    {
        byte[] serverPrivate = Base64Url(Integration.LocalRealityServer.PrivateKey);

        // A different server key: the client seals for someone else, so this server cannot open it.
        byte[] otherPrivate = new byte[32], otherPublic = new byte[32];
        X25519.GenerateKeyPair(otherPrivate, otherPublic);

        byte[] clientPrivate = new byte[32], clientPublic = new byte[32];
        X25519.GenerateKeyPair(clientPrivate, clientPublic);

        byte[] hello = FakeClientHello();
        byte[] authKey = new byte[RealityAuth.AuthKeySize];
        RealityAuth.DeriveAuthKey(authKey, clientPrivate, otherPublic, hello.AsSpan(6, 32));

        byte[] shortId = new byte[RealityAuth.ShortIdSize];
        RealityAuth.ParseShortId(shortId, "ab12");
        RealityAuth.SealSessionId(hello, authKey, shortId, 1_760_000_000, ClientVersion);

        byte[] plaintext = new byte[16];
        Assert.False(TryOpenAsServer(hello, serverPrivate, clientPublic, plaintext, out _));
    }

    [Fact]
    public void SealSessionId_RequiresAFullLengthSessionId()
    {
        byte[] hello = FakeClientHello();
        hello[38] = 0; // a client that sends no session id

        byte[] authKey = new byte[RealityAuth.AuthKeySize];
        byte[] shortId = new byte[RealityAuth.ShortIdSize];

        var ex = Assert.Throws<ArgumentException>(
            () => RealityAuth.SealSessionId(hello, authKey, shortId, 0, ClientVersion));

        Assert.Contains("session id", ex.Message);
    }

    [Fact]
    public void VerifyCertificate_AcceptsTheServersHmac()
    {
        byte[] authKey = RandomNumberGenerator.GetBytes(32);
        byte[] publicKey = RandomNumberGenerator.GetBytes(32);
        byte[] signature = HMACSHA512.HashData(authKey, publicKey);

        Assert.True(RealityAuth.VerifyCertificate(authKey, publicKey, signature));
    }

    [Fact]
    public void VerifyCertificate_RejectsAnyoneElse()
    {
        byte[] authKey = RandomNumberGenerator.GetBytes(32);
        byte[] publicKey = RandomNumberGenerator.GetBytes(32);
        byte[] signature = HMACSHA512.HashData(RandomNumberGenerator.GetBytes(32), publicKey);

        Assert.False(RealityAuth.VerifyCertificate(authKey, publicKey, signature));
    }

    // A real certificate from the decoy site carries an ordinary signature of the wrong length;
    // that must be a plain "no", not an exception.
    [Fact]
    public void VerifyCertificate_RejectsAWrongLengthSignature()
    {
        byte[] authKey = RandomNumberGenerator.GetBytes(32);

        Assert.False(RealityAuth.VerifyCertificate(authKey, new byte[32], new byte[256]));
    }

    [Theory]
    [InlineData("", "0000000000000000")]
    [InlineData("ab12", "ab12000000000000")]
    [InlineData("0123456789abcdef", "0123456789abcdef")]
    public void ParseShortId_PadsToEightBytes(string hex, string expected)
    {
        byte[] shortId = new byte[RealityAuth.ShortIdSize];
        RealityAuth.ParseShortId(shortId, hex);

        Assert.Equal(expected, Convert.ToHexString(shortId).ToLowerInvariant());
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("zz")]
    [InlineData("0123456789abcdef00")]
    public void ParseShortId_RejectsMalformedInput(string hex)
    {
        byte[] shortId = new byte[RealityAuth.ShortIdSize];

        Assert.Throws<FormatException>(() => RealityAuth.ParseShortId(shortId, hex));
    }
}
