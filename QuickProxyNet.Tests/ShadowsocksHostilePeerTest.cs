using System.Buffers.Binary;
using System.Security.Cryptography;
using QuickProxyNet.Tests.Helpers;

// CA2022 ("avoid inexact reads") warns whenever a single ReadAsync is expected to fill a
// buffer. Chunk-at-a-time delivery is exactly what these tests assert.
#pragma warning disable CA2022

namespace QuickProxyNet.Tests;

/// <summary>
/// Drives <see cref="ShadowsocksStream"/> and <see cref="ShadowsocksClient"/> against a peer
/// that is malformed, truncating, tampering or silent.
/// </summary>
/// <remarks>
/// <para>
/// The wire bytes here are produced by <see cref="ServerSealer"/>, a deliberately separate
/// re-implementation of the server side (HKDF-SHA1, AES-GCM, a little-endian counting nonce)
/// that is first anchored to the pinned vectors of <see cref="ShadowsocksCryptoTest"/> and only
/// then bent. Everything runs in memory: no process, no socket, no timing.
/// </para>
/// <para>
/// The rules under test: a decrypted length above <c>0x3FFF</c> is refused, never masked; a FIN
/// anywhere but exactly at a chunk boundary is an error, never <c>0</c>; a failed tag is an
/// error; a server that says nothing fails on the first <c>Read</c> and never at connect.
/// </para>
/// </remarks>
public class ShadowsocksHostilePeerTest
{
    private const string Password = "quickproxynet-test-password";
    private const ShadowsocksMethod Method = ShadowsocksMethod.Aes256Gcm;

    private static readonly byte[] ServerSalt = ShadowsocksCryptoTest.FixedSalt(32);

    private static byte[] MasterKey(string password = Password)
    {
        byte[] key = new byte[32];
        ShadowsocksCipher.DeriveMasterKey(password, key);
        return key;
    }

    private static ShadowsocksStream ClientStream(byte[] inbound, int maxReadSize = int.MaxValue) =>
        new(new DuplexTestStream(inbound, maxReadSize), Method, MasterKey(), ShadowsocksCryptoTest.FixedSalt(32), leaveInnerOpen: true);

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach (byte[] p in parts)
            length += p.Length;

        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            p.CopyTo(result, offset);
            offset += p.Length;
        }

        return result;
    }

    private static async Task<ProxyProtocolException> ExpectReadFailureAsync(ShadowsocksStream stream, int bufferSize = 64)
    {
        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await stream.ReadAsync(new byte[bufferSize]));
        Assert.False(stream.IsReadCompleted, "a failure must never leave the stream marked as cleanly closed");
        Assert.True(stream.IsReadFaulted, "a failure must latch the read direction");

        // The failure is final. A caller that swallows the first exception and reads again must
        // get it again — never a 0 from the transport's FIN dressed up as a clean end of stream.
        var again = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await stream.ReadAsync(new byte[bufferSize]));
        Assert.Equal(ProxyErrorCode.InvalidResponse, again.ErrorCode);
        Assert.False(stream.IsReadCompleted);
        return ex;
    }

    // ================================ anchor ================================

    [Fact]
    public void ServerSealer_ReproducesThePinnedVector()
    {
        // aes-256-gcm one_byte from ShadowsocksCryptoTest: the sealer is only trustworthy if it
        // reproduces the independent vector before it is used to build hostile fixtures.
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        Assert.Equal(
            "6fac3aa79051d37a98130772dd2e8fd52904dfc714e2fecbf5596fe7d4ea31ecba37bf",
            Convert.ToHexStringLower(sealer.Chunk([0x41])));
    }

    // ================================ oversized length ================================

    [Theory]
    [InlineData(0x8000)] // a masking implementation turns this into 0 and desynchronises
    [InlineData(0x4000)] // the smallest illegal value
    [InlineData(0xFFFF)]
    public async Task DecryptedLengthAboveTheCap_IsRejectedNotMasked(int declared)
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] wire = Concat(ServerSalt, sealer.LengthBlock((ushort)declared), sealer.RawPayload(new byte[64]));

        var ex = await ExpectReadFailureAsync(ClientStream(wire));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.Contains($"0x{declared:X4}", ex.Message);
        Assert.Contains("16383", ex.Message);
        Assert.Contains("masked", ex.Message);
    }

    [Fact]
    public async Task DecryptedLengthAtTheCap_IsAccepted()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] payload = new byte[ShadowsocksStream.MaxPayloadSize];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i * 3);

        var stream = ClientStream(Concat(ServerSalt, sealer.Chunk(payload)));
        byte[] buffer = new byte[payload.Length];
        Assert.Equal(payload.Length, await stream.ReadAsync(buffer));
        Assert.Equal(payload, buffer);
    }

    // ================================ truncation ================================

    [Theory]
    [InlineData(0)]  // nothing at all: how a wrong password looks
    [InlineData(1)]
    [InlineData(31)] // one byte short of the salt
    public async Task FinInsideTheSalt_IsAnErrorNotEof(int saltBytes)
    {
        var ex = await ExpectReadFailureAsync(ClientStream(ServerSalt[..saltBytes]));

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
        Assert.IsType<EndOfStreamException>(ex.InnerException);
        if (saltBytes == 0)
            Assert.Contains("password", ex.Message);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]  // the two length bytes without their tag
    [InlineData(17)] // one byte short of the length block
    public async Task FinInsideTheLengthBlock_IsAnErrorNotEof(int keep)
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] chunk = sealer.Chunk("hello"u8.ToArray());

        var ex = await ExpectReadFailureAsync(ClientStream(Concat(ServerSalt, chunk[..keep])));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.Contains("length block", ex.Message);
    }

    [Theory]
    [InlineData(18)] // a complete length block and no payload
    [InlineData(20)]
    [InlineData(38)] // one byte short of the payload tag
    public async Task FinInsideThePayload_IsAnErrorNotEof(int keep)
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] chunk = sealer.Chunk("hello"u8.ToArray()); // 18 + 5 + 16 = 39 bytes

        var ex = await ExpectReadFailureAsync(ClientStream(Concat(ServerSalt, chunk[..keep])));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.IsType<EndOfStreamException>(ex.InnerException);
    }

    [Fact]
    public async Task FinAfterACompleteChunk_ThenMidChunk_FailsOnTheSecondRead()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] first = sealer.Chunk("hello"u8.ToArray());
        byte[] second = sealer.Chunk("world"u8.ToArray());

        var stream = ClientStream(Concat(ServerSalt, first, second[..10]), maxReadSize: 3);
        byte[] buffer = new byte[64];
        Assert.Equal(5, await stream.ReadAsync(buffer));
        Assert.Equal("hello"u8.ToArray(), buffer[..5]);

        var ex = await ExpectReadFailureAsync(stream);
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    // ================================ tampering ================================

    [Fact]
    public async Task TamperedPayloadTag_IsAnError()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] chunk = sealer.Chunk("hello"u8.ToArray());
        chunk[^1] ^= 0xFF;

        var ex = await ExpectReadFailureAsync(ClientStream(Concat(ServerSalt, chunk)));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.IsAssignableFrom<CryptographicException>(ex.InnerException);
        Assert.Contains("payload", ex.Message);
    }

    [Fact]
    public async Task TamperedLengthBlock_IsAnError()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        byte[] chunk = sealer.Chunk("hello"u8.ToArray());
        chunk[0] ^= 0x01;

        var ex = await ExpectReadFailureAsync(ClientStream(Concat(ServerSalt, chunk)));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.IsAssignableFrom<CryptographicException>(ex.InnerException);
        Assert.Contains("length block", ex.Message);
    }

    [Fact]
    public async Task ChunkSealedForALaterPosition_FailsTheNonceCheck()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        sealer.Chunk("skipped"u8.ToArray());
        byte[] second = sealer.Chunk("hello"u8.ToArray());

        // Presented as the first chunk, it was sealed with nonces 2 and 3 and cannot open under 0.
        var ex = await ExpectReadFailureAsync(ClientStream(Concat(ServerSalt, second)));
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task ServerWithAnotherPassword_FailsAuthentication()
    {
        // The rare server that does answer under the wrong key: its salt reads fine, the
        // subkey differs, the first tag fails.
        var sealer = new ServerSealer(MasterKey("some-other-password"), ServerSalt);
        byte[] wire = Concat(ServerSalt, sealer.Chunk("hello"u8.ToArray()));

        var ex = await ExpectReadFailureAsync(ClientStream(wire));
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task ServerReusingTheClientSalt_StillOpens_DifferentSaltsStillOpen()
    {
        // The read subkey comes from the salt actually received, whatever it is.
        byte[] otherSalt = new byte[32];
        for (int i = 0; i < otherSalt.Length; i++)
            otherSalt[i] = (byte)(200 - i);

        var sealer = new ServerSealer(MasterKey(), otherSalt);
        var stream = ClientStream(Concat(otherSalt, sealer.Chunk("hello"u8.ToArray())));

        byte[] buffer = new byte[64];
        Assert.Equal(5, await stream.ReadAsync(buffer));
        Assert.Equal("hello"u8.ToArray(), buffer[..5]);
    }

    // ================================ clean EOF ================================

    [Fact]
    public async Task FinExactlyAtAChunkBoundary_IsCleanEof_AndStaysEof()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        var stream = ClientStream(Concat(ServerSalt, sealer.Chunk("hello"u8.ToArray()), sealer.Chunk("!"u8.ToArray())));

        byte[] buffer = new byte[64];
        Assert.Equal(5, await stream.ReadAsync(buffer));
        Assert.Equal(1, await stream.ReadAsync(buffer));
        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.True(stream.IsReadCompleted);
        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.Equal(4UL, stream.ReadNonceCounter);
    }

    [Fact]
    public async Task FinRightAfterTheSalt_IsCleanEof()
    {
        // A server that keyed the stream and then closed without sending a chunk: the salt is
        // complete and the FIN sits on a chunk boundary, so this is a clean close.
        var stream = ClientStream(ServerSalt);
        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
        Assert.True(stream.IsServerSaltRead);
        Assert.True(stream.IsReadCompleted);
    }

    [Fact]
    public async Task EmptyChunks_AreOpenedAndSkipped_NeverReportedAsEof()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        var stream = ClientStream(Concat(
            ServerSalt,
            sealer.Chunk([]),
            sealer.Chunk([]),
            sealer.Chunk("data"u8.ToArray()),
            sealer.Chunk([])));

        byte[] buffer = new byte[64];
        Assert.Equal(4, await stream.ReadAsync(buffer));
        Assert.Equal("data"u8.ToArray(), buffer[..4]);
        Assert.Equal(6UL, stream.ReadNonceCounter); // three chunks opened so far
        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.Equal(8UL, stream.ReadNonceCounter); // the trailing empty chunk was opened, then the FIN
    }

    [Fact]
    public async Task SmallCallerBuffer_StopsAtTheChunkBoundary()
    {
        var sealer = new ServerSealer(MasterKey(), ServerSalt);
        var stream = ClientStream(Concat(ServerSalt, sealer.Chunk("hello"u8.ToArray()), sealer.Chunk("A"u8.ToArray())));

        byte[] two = new byte[2];
        var assembled = new List<byte>();
        for (int i = 0; i < 3; i++)
        {
            int read = await stream.ReadAsync(two);
            assembled.AddRange(two[..read]);
        }

        // 2 + 2 + 1: the third read stops at the chunk boundary and only one chunk is open.
        Assert.Equal("hello"u8.ToArray(), assembled);
        Assert.Equal(2UL, stream.ReadNonceCounter);
        Assert.Equal(1, await stream.ReadAsync(two));
        Assert.Equal((byte)'A', two[0]);
    }

    // ================================ the silent server ================================

    /// <summary>
    /// A Shadowsocks server that cannot open the first chunk sends nothing. ConnectAsync must
    /// still succeed — it reads nothing — and the first Read is where the failure surfaces.
    /// This is the in-memory proof of the lazy salt read that the docker tests prove for real.
    /// </summary>
    [Fact]
    public async Task SilentServer_ConnectSucceeds_FirstReadFails()
    {
        var transport = new ScriptedDuplexStream();
        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = "aes-256-gcm", Password = Password, Host = "proxy.example", Port = 8388
        });

        await using Stream tunnel = await client.ConnectAsync(transport, "example.com", 443);

        // salt(32) ‖ chunk(header of 15 bytes) = 32 + 18 + 15 + 16.
        Assert.Equal(81, transport.Written.Length);
        Assert.Equal(0, transport.ReadCount);

        // The caller speaks first, as HTTP does; nothing comes back.
        await tunnel.WriteAsync("GET / HTTP/1.0\r\n\r\n"u8.ToArray());
        Assert.Equal(0, transport.ReadCount);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () => await tunnel.ReadAsync(new byte[64]));
        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
        Assert.Contains("password", ex.Message);
        Assert.Equal(1, transport.ReadCount);
    }

    /// <summary>
    /// The full client path against a scripted server: connect, write, read back what the
    /// "server" sealed for us. Proves the client's read direction is keyed from the salt the
    /// server sends, not from its own.
    /// </summary>
    [Fact]
    public async Task ScriptedServer_RoundTripsThroughTheClient()
    {
        var transport = new ScriptedDuplexStream(maxReadSize: 5);
        var client = new ShadowsocksClient(ShadowsocksShareLink.Parse(
            "ss://YWVzLTI1Ni1nY206cXVpY2twcm94eW5ldC10ZXN0LXBhc3N3b3Jk@proxy.example:8388"));
        Assert.Equal(Password, client.Options.Password);

        await using Stream tunnel = await client.ConnectAsync(transport, "example.com", 80);

        byte[] otherSalt = new byte[32];
        for (int i = 0; i < otherSalt.Length; i++)
            otherSalt[i] = (byte)(i ^ 0x5A);
        var sealer = new ServerSealer(MasterKey(), otherSalt);
        transport.Enqueue(otherSalt);
        transport.Enqueue(sealer.Chunk("HTTP/1.0 200 OK\r\n"u8.ToArray()));
        transport.Enqueue(sealer.Chunk("\r\nQPN"u8.ToArray()));

        var received = new List<byte>();
        byte[] buffer = new byte[7];
        int read;
        while ((read = await tunnel.ReadAsync(buffer)) > 0)
            received.AddRange(buffer[..read]);

        Assert.Equal("HTTP/1.0 200 OK\r\n\r\nQPN"u8.ToArray(), received);
    }

    /// <summary>
    /// An independent server-side sealer: HKDF-SHA1 subkey, AES-256-GCM, 12-byte little-endian
    /// counting nonce advanced after every operation. Anchored to the pinned vectors by
    /// <see cref="ServerSealer_ReproducesThePinnedVector"/>.
    /// </summary>
    private sealed class ServerSealer
    {
        private readonly AesGcm _aes;
        private readonly byte[] _nonce = new byte[12];

        public ServerSealer(byte[] masterKey, byte[] salt)
        {
            byte[] subkey = HKDF.DeriveKey(HashAlgorithmName.SHA1, masterKey, 32, salt, "ss-subkey"u8.ToArray());
            _aes = new AesGcm(subkey, 16);
        }

        public byte[] Chunk(byte[] plaintext) => Concat(LengthBlock((ushort)plaintext.Length), RawPayload(plaintext));

        /// <summary>Seals a length block declaring <paramref name="declared"/>, whatever payload follows.</summary>
        public byte[] LengthBlock(ushort declared)
        {
            byte[] plain = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(plain, declared);
            return Seal(plain);
        }

        /// <summary>Seals a payload with the current nonce, independent of any length block.</summary>
        public byte[] RawPayload(byte[] plaintext) => Seal(plaintext);

        private byte[] Seal(byte[] plaintext)
        {
            byte[] wire = new byte[plaintext.Length + 16];
            _aes.Encrypt(_nonce, plaintext, wire.AsSpan(0, plaintext.Length), wire.AsSpan(plaintext.Length, 16));
            for (int i = 0; i < _nonce.Length && ++_nonce[i] == 0; i++)
            {
            }

            return wire;
        }
    }
}
