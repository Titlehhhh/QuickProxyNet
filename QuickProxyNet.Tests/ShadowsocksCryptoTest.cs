using System.Security.Cryptography;
using System.Text;
using QuickProxyNet.Tests.Helpers;

// CA2022 ("avoid inexact reads") warns whenever a single ReadAsync is expected to fill a
// buffer. Chunk-at-a-time delivery is exactly what these tests assert, so the analyzer is
// off for this file.
#pragma warning disable CA2022

namespace QuickProxyNet.Tests;

/// <summary>
/// Byte-exact vectors for the Shadowsocks AEAD (SIP004/SIP007) key schedule, chunk framing and
/// first client packet: <see cref="ShadowsocksCipher"/>, <see cref="ShadowsocksStream"/> and
/// <see cref="ShadowsocksClient"/>.
///
/// Every value below is GROUND TRUTH produced by an independent Python implementation
/// (scratchpad/ss/vectors.py, written from shadowsocks.org/doc/aead alone — `cryptography` for
/// the AEADs, hashlib/hmac for MD5 and HKDF). Before emitting a single vector that script
/// validates itself against published data: RFC 5869 HKDF-SHA1 test cases 4–7, RFC 8439 §2.8.2
/// for ChaCha20-Poly1305, NIST GCM test cases 3 (AES-128) and 16 (AES-256), and EVP_BytesToKey
/// against the actual OpenSSL 3.5.6 binary (`openssl enc -k pass -md md5 -nosalt -P`, three key
/// sizes, two passwords). There is no official end-to-end Shadowsocks AEAD vector anywhere —
/// neither the spec nor the reference implementations publish one — so this compositional
/// validation is the strongest available. A failure here means the code is wrong, not the test.
///
/// Fixed inputs: password "quickproxynet-test-password"; salt[i] = (i·37 + 11) mod 256;
/// payload pattern data[i] = i mod 256. The 0x3FFF fixtures are ~33 KB of hex each, so they are
/// pinned by the SHA-256 of the wire after the salt; everything else is pinned as full hex.
/// </summary>
public class ShadowsocksCryptoTest
{
    private const string Password = "quickproxynet-test-password";

    private const string Aes128 = "aes-128-gcm";
    private const string Aes192 = "aes-192-gcm";
    private const string Aes256 = "aes-256-gcm";
    private const string ChaCha = "chacha20-ietf-poly1305";

    // ---- pinned address headers (cipher-independent) ----
    private const string HeaderDomain443 = "030b6578616d706c652e636f6d01bb";
    private const string HeaderIpv4 = "01010203040050";
    private const string HeaderIpv6 = "0420010db80000000000000000000000011f90";
    private const string HeaderDomain80 = "030b6578616d706c652e636f6d0050";
    private const string InitialPayload = "474554202f20485454502f312e300d0a0d0a"; // "GET / HTTP/1.0\r\n\r\n"

    // ---- pinned payload digests for the oversize fixtures ----
    private const string PatternSha16383 = "fab82f1352405c22ca2953ff80a508e5567c51e1a9aeb57cf9a56447e40ba066";
    private const string PatternSha16384 = "a1f259d4365ed4320c377ce26f5c8c56dcdc9a89e7b641bfd8eabfbbeac86654";

    private sealed record Vector(
        string Name,
        int KeySize,
        string MasterKey,
        string Salt,
        string Subkey,
        string EmptyChunk,
        string OneByteChunk,
        string MaxChunkSha256,
        string MaxChunkPlusOneSha256,
        string PacketDomain,
        string PacketIpv4,
        string PacketIpv6,
        string PacketDomainWithPayload);

    // Emitted mechanically from vectors.json (a python one-liner), not transcribed by hand.
    private static readonly Dictionary<string, Vector> Vectors = new()
    {
        ["aes-128-gcm"] = new(
            Name: "aes-128-gcm",
            KeySize: 16,
            MasterKey: "58fa331ca37b32eadf1893359b65e3ca",
            Salt: "0b30557a9fc4e90e33587da2c7ec1136",
            Subkey: "c7ae681c327f172529a33539a9320d55",
            EmptyChunk: "377fbc0fdb661e461222a8844cb594476d1a77a4bf9e48325e514b87740b59ef37b0",
            OneByteChunk: "377eb914669adf115506ea7b59f2dc41dd20cdbf04b2414736ef4975013acb2ee144cd",
            MaxChunkSha256: "4c99ca649a6fe0f5a64e5c268d5022a5d1759ba0092f36657640353518a7c7f9",
            MaxChunkPlusOneSha256: "a9e14d3d7441fe13323622c64f9f6005da833cd76e1da3d2b6802a69508e174b",
            PacketDomain: "0b30557a9fc4e90e33587da2c7ec113637708f9005765258fefd73818c5b2c63fc6c8f4a221c73bf5b2ce8b3511a11e70e58a637a2332b006b98b278e63b7ac3ad",
            PacketIpv4: "0b30557a9fc4e90e33587da2c7ec11363778a74dea9058e2c7df647926616c567dbc8d40456716d27bc651756a316e943f0428b59f6ddbec91",
            PacketIpv6: "0b30557a9fc4e90e33587da2c7ec1136376ce298c2af48cba90a40742708cc27bef488614669aad22b408d9d32757ce6b5e59bc93a61874411e6760124d545ad26f3f62301",
            PacketDomainWithPayload: "0b30557a9fc4e90e33587da2c7ec1136375e1a63d902f5f9b18eb599f11bdc97da608f4a221c73bf5b2ce8b3511a11e6e5a2df828a2ae686f10c6bdb7e749ceb76605d64edcdd7a718d0c8dea9e5fbca708e7b"),
        ["aes-192-gcm"] = new(
            Name: "aes-192-gcm",
            KeySize: 24,
            MasterKey: "58fa331ca37b32eadf1893359b65e3ca03c988218e317c2e",
            Salt: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e",
            Subkey: "87deca5cda8d57c120edbc217e8b4d5de6241c6f79f25f38",
            EmptyChunk: "d4c487b8a2cda1f580de46ff530363e3be759d3f226be1277ff0377c5ac121e38cf0",
            OneByteChunk: "d4c543571fc220d6ab2c8fe3c405f2722cb54250ce5df7d8efc139e4762717d06baad8",
            MaxChunkSha256: "b054bf947a3df294ac1bce446eaa99a6cee2f9778a77a43ee93cc2a1627f670e",
            MaxChunkPlusOneSha256: "9b3788ebe17525088c72d15a874f00c16344bec7885fcd7ddafe04c516ed11ff",
            PacketDomain: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395ed4cb724b799f2f050c94714c0e261b9bd433001cc1dc3d54f84c449f1b1aad1e35a8c31188cf4434a0fa9e0bef1158216d",
            PacketIpv4: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395ed4c39f3691e3261c530239a8b612971742360216a6a75839d8a83e129a69cebd84fa20f39d20446bcb",
            PacketIpv6: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395ed4d71073b52530a243e58c139a61c848253f0737a5a9e439882021b17875c01f8e38bc321d262b8f2217ddbfe1be314a95da5c1a2e",
            PacketDomainWithPayload: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395ed4e572a0be3204b3d575ac7124d7c04074a3001cc1dc3d54f84c449f1b1aad1fde7ff879add328e0ab7b4450279ab296eb941e33bf9f75ba97a5ba207046bf6309fbb4"),
        ["aes-256-gcm"] = new(
            Name: "aes-256-gcm",
            KeySize: 32,
            MasterKey: "58fa331ca37b32eadf1893359b65e3ca03c988218e317c2e0b194f5a11876dda",
            Salt: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
            Subkey: "5ede2ce410b9cae4302a9adac4ba9c8bd2b7d8b1852e16528db3779fed55e30a",
            EmptyChunk: "6fad51a59b7e126d2ea494b7c8bfeb5d79e8af8880d92435b36887a8aa873a969428",
            OneByteChunk: "6fac3aa79051d37a98130772dd2e8fd52904dfc714e2fecbf5596fe7d4ea31ecba37bf",
            MaxChunkSha256: "b0e7533e7d48451729fbcc58df258e92cc03fbbba79b3501c31bde8326aa2b61",
            MaxChunkPlusOneSha256: "b73f9ae2ae797610798f05a890ea061a90e0e31ea9bd99fd92ccc2f3e6a0815a",
            PacketDomain: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61866fa25ebbf3cf5db69a1ef1c40cc2f0a64c0f9d62e968382724cec0b21602fb4088428dbb64c65536ca356e914104d7b7d1",
            PacketIpv4: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61866faa82abaab1550b2fa26feca049d4e4cb6d9f688e135d4a04695b3d63085c41e7fc029d8154e65d3d",
            PacketIpv6: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61866fbe968334f2402e9e051ca9af1a0e4086199a498d1de14a54a2a59c756d964133d4dbeaa9b97ce21b1425a3c9ac294994c52f2f43",
            PacketDomainWithPayload: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61866f8ccee6f5a9f18c4ee17fd06f021edf348e9d62e968382724cec0b21602fb4163939fa119079b6d5fac8e6d053f4d5b2e073a8972828fb822cd70d2978e4c0f0d79f9"),
        ["chacha20-ietf-poly1305"] = new(
            Name: "chacha20-ietf-poly1305",
            KeySize: 32,
            MasterKey: "58fa331ca37b32eadf1893359b65e3ca03c988218e317c2e0b194f5a11876dda",
            Salt: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
            Subkey: "5ede2ce410b9cae4302a9adac4ba9c8bd2b7d8b1852e16528db3779fed55e30a",
            EmptyChunk: "f40e92617f73950e0ef6c2d1952a45a38474b13aee3acdd4b26b1a56817a8ed68574",
            OneByteChunk: "f40f3e9eb189e9872eae3341d5e99babeabcf20afc3d3149bf21207735ee5f406f3a83",
            MaxChunkSha256: "69e027fd8eeea6eb6f4589d6c78042178ac36a7aabf833da1dfbd3124454bda9",
            MaxChunkPlusOneSha256: "c75a1b1398a0699566c846f1e8441a9457eeded2a0e6c084b1ce390f103b58a6",
            PacketDomain: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186f401e04cf25250e5679c09295d74dd3656c7b0f1fae15deaccbd5b6b7586251a2eed3a1cb59b734fa83635d6aa570ecbf6",
            PacketIpv4: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186f4093b328404f1af6b5d8fa4586e9379860ab2fb9d9a3887ec9734591bfcde443d9586d89cf0843879",
            PacketIpv6: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186f41d97ef70c0822af5bf5d594d5f5a207fb2b7da9e948487bcd13e4516e9481b9540a3803630f01e38b326db33ae1bf431404007e8",
            PacketDomainWithPayload: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186f42fa033f94f6cb23db24a2fc3d173b6abc9b0f1fae15deaccbd5b6b7586251bc507e7cb86bcb631d1923df9a65a0f19a572456eeecf41e29f4df9a0a69c263b60e8ae"),
    };

    // ================================ helpers ================================

    private static byte[] Hex(string h) => Convert.FromHexString(h);
    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(b);
    private static string Sha256Hex(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(SHA256.HashData(b));

    /// <summary>salt[i] = (i·37 + 11) mod 256 — the fixed salt the vectors were generated with.</summary>
    internal static byte[] FixedSalt(int length)
    {
        byte[] salt = new byte[length];
        for (int i = 0; i < length; i++)
            salt[i] = (byte)((i * 37 + 11) % 256);
        return salt;
    }

    /// <summary>data[i] = i mod 256.</summary>
    private static byte[] Pattern(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)i;
        return data;
    }

    private static byte[] MasterKey(Vector v)
    {
        byte[] key = new byte[v.KeySize];
        ShadowsocksCipher.DeriveMasterKey(Password, key);
        return key;
    }

    private static ShadowsocksStream Stream(Vector v, Stream transport) =>
        new(transport, ShadowsocksCipher.Resolve(v.Name), MasterKey(v), FixedSalt(v.KeySize), leaveInnerOpen: true);

    // ================================ key schedule ================================

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [InlineData(ChaCha)]
    public void FixedSalt_MatchesThePinnedSalt(string name)
    {
        Vector v = Vectors[name];
        Assert.Equal(v.Salt, Hex(FixedSalt(v.KeySize)));
        Assert.Equal(v.KeySize, ShadowsocksCipher.SaltSize(ShadowsocksCipher.Resolve(name)));
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [InlineData(ChaCha)]
    public void MasterKey_MatchesEvpBytesToKey(string name)
    {
        Vector v = Vectors[name];
        Assert.Equal(v.MasterKey, Hex(MasterKey(v)));
    }

    [Fact]
    public void MasterKey_ShorterKeysAreAPrefixOfLongerOnes()
    {
        // EVP_BytesToKey truncates one MD5 chain, so the 16-byte key is the head of the 32-byte one.
        Assert.StartsWith(Vectors[Aes128].MasterKey, Vectors[Aes256].MasterKey);
        Assert.StartsWith(Vectors[Aes192].MasterKey, Vectors[Aes256].MasterKey);
        Assert.Equal(Vectors[Aes256].MasterKey, Vectors[ChaCha].MasterKey);
    }

    [Fact]
    public void MasterKey_IsAnMd5Chain()
    {
        // Independent recomputation: D1 = MD5(pw), D2 = MD5(D1 ‖ pw), key = D1 ‖ D2.
        byte[] pw = Encoding.UTF8.GetBytes(Password);
        byte[] d1 = MD5.HashData(pw);
        byte[] d2 = MD5.HashData([.. d1, .. pw]);
        Assert.Equal(Vectors[Aes256].MasterKey, Hex(d1) + Hex(d2));
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [InlineData(ChaCha)]
    public void Subkey_MatchesHkdfSha1(string name)
    {
        Vector v = Vectors[name];
        byte[] subkey = new byte[v.KeySize];
        ShadowsocksCipher.DeriveSubkey(Hex(v.MasterKey), Hex(v.Salt), subkey);
        Assert.Equal(v.Subkey, Hex(subkey));
    }

    [Fact]
    public void Subkey_IsHkdfSha1WithTheSsSubkeyInfo()
    {
        Vector v = Vectors[Aes256];
        byte[] direct = HKDF.DeriveKey(HashAlgorithmName.SHA1, Hex(v.MasterKey), 32, Hex(v.Salt), "ss-subkey"u8.ToArray());
        Assert.Equal(v.Subkey, Hex(direct));

        // The info string and the hash are both load-bearing.
        Assert.NotEqual(v.Subkey, Hex(HKDF.DeriveKey(HashAlgorithmName.SHA1, Hex(v.MasterKey), 32, Hex(v.Salt), "ss-subkey\0"u8.ToArray())));
        Assert.NotEqual(v.Subkey, Hex(HKDF.DeriveKey(HashAlgorithmName.SHA256, Hex(v.MasterKey), 32, Hex(v.Salt), "ss-subkey"u8.ToArray())));
    }

    // ================================ chunk framing: write ================================

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task EmptyChunk_MatchesThePinnedWire(string name)
    {
        Vector v = Vectors[name];
        var transport = new DuplexTestStream([]);
        var stream = Stream(v, transport);

        await stream.WriteChunkAsync(ReadOnlyMemory<byte>.Empty);

        Assert.Equal(v.Salt + v.EmptyChunk, Hex(transport.Written));
        Assert.Equal(34 + v.KeySize, transport.Written.Length);
        Assert.Equal(2UL, stream.WriteNonceCounter); // two operations, even for an empty payload
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task OneByteChunk_MatchesThePinnedWire(string name)
    {
        Vector v = Vectors[name];
        var transport = new DuplexTestStream([]);
        var stream = Stream(v, transport);

        await stream.WriteAsync(new byte[] { 0x41 });

        Assert.Equal(v.Salt + v.OneByteChunk, Hex(transport.Written));
        Assert.Equal(2UL, stream.WriteNonceCounter);
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task MaxChunk_MatchesThePinnedDigest(string name)
    {
        Vector v = Vectors[name];
        byte[] payload = Pattern(ShadowsocksStream.MaxPayloadSize);
        Assert.Equal(PatternSha16383, Sha256Hex(payload));

        var transport = new DuplexTestStream([]);
        var stream = Stream(v, transport);
        await stream.WriteAsync(payload);

        byte[] wire = transport.Written;
        Assert.Equal(v.Salt, Hex(wire.AsSpan(0, v.KeySize)));
        Assert.Equal(16417, wire.Length - v.KeySize);
        Assert.Equal(v.MaxChunkSha256, Sha256Hex(wire.AsSpan(v.KeySize)));
        Assert.Equal(2UL, stream.WriteNonceCounter);
    }

    /// <summary>
    /// The one test that catches a wrong nonce increment: the second chunk is sealed with
    /// nonce 2 and 3, and a per-chunk (rather than per-operation) counter, or a big-endian one,
    /// passes every single-chunk vector and fails here.
    /// </summary>
    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task MaxChunkPlusOne_SplitsIntoTwoChunks_AndMatchesThePinnedDigest(string name)
    {
        Vector v = Vectors[name];
        byte[] payload = Pattern(ShadowsocksStream.MaxPayloadSize + 1);
        Assert.Equal(PatternSha16384, Sha256Hex(payload));

        var transport = new DuplexTestStream([]);
        var stream = Stream(v, transport);
        await stream.WriteAsync(payload);

        byte[] wire = transport.Written;
        Assert.Equal(16452, wire.Length - v.KeySize); // (16383 + 34) + (1 + 34)
        Assert.Equal(v.MaxChunkPlusOneSha256, Sha256Hex(wire.AsSpan(v.KeySize)));
        Assert.Equal(4UL, stream.WriteNonceCounter);
    }

    // ================================ chunk framing: read ================================

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task Reader_OpensThePinnedOneByteChunk(string name)
    {
        // The read direction is keyed from the salt it receives; the vector salt keys it exactly
        // like the write direction, so the same wire opens on either side.
        Vector v = Vectors[name];
        var transport = new DuplexTestStream(Hex(v.Salt + v.OneByteChunk));
        var stream = Stream(v, transport);

        byte[] buffer = new byte[16];
        Assert.False(stream.IsServerSaltRead);
        Assert.Equal(1, await stream.ReadAsync(buffer));
        Assert.Equal(0x41, buffer[0]);
        Assert.True(stream.IsServerSaltRead);
        Assert.Equal(2UL, stream.ReadNonceCounter);

        // FIN exactly at the chunk boundary: the clean end of stream.
        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.True(stream.IsReadCompleted);
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task Reader_OpensThePinnedEmptyChunk_WithoutReportingEof(string name)
    {
        Vector v = Vectors[name];
        var transport = new DuplexTestStream(Hex(v.Salt + v.EmptyChunk));
        var stream = Stream(v, transport);

        // The only bytes are an empty chunk followed by a FIN. The chunk must be opened (counter
        // advances to 2) and the FIN, not the chunk, is what ends the stream.
        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
        Assert.Equal(2UL, stream.ReadNonceCounter);
        Assert.True(stream.IsReadCompleted);
    }

    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task Reader_RoundTripsTheDigestPinnedTwoChunkStream(string name)
    {
        // The writer's output is anchored by the pinned digest above; feeding it back proves the
        // reader opens two consecutive chunks with the right nonces and reassembles them.
        Vector v = Vectors[name];
        byte[] payload = Pattern(ShadowsocksStream.MaxPayloadSize + 1);

        var outbound = new DuplexTestStream([]);
        await Stream(v, outbound).WriteAsync(payload);
        byte[] wire = outbound.Written;
        Assert.Equal(v.MaxChunkPlusOneSha256, Sha256Hex(wire.AsSpan(v.KeySize)));

        var reader = Stream(v, new DuplexTestStream(wire, maxReadSize: 1000));
        byte[] received = new byte[payload.Length];
        int offset = 0;
        while (offset < received.Length)
        {
            int read = await reader.ReadAsync(received.AsMemory(offset));
            Assert.True(read > 0);
            offset += read;
        }

        Assert.Equal(payload, received);
        Assert.Equal(4UL, reader.ReadNonceCounter);
        Assert.Equal(0, await reader.ReadAsync(received));
    }

    // ================================ first client packet ================================

    [Fact]
    public void AddressHeader_MatchesThePinnedBytes()
    {
        Span<byte> buffer = stackalloc byte[ProxyAddress.MaxLength + 2];

        int n = ShadowsocksClient.BuildAddressHeader(buffer, "example.com", 443);
        Assert.Equal(HeaderDomain443, Hex(buffer.Slice(0, n)));

        n = ShadowsocksClient.BuildAddressHeader(buffer, "1.2.3.4", 80);
        Assert.Equal(HeaderIpv4, Hex(buffer.Slice(0, n)));

        n = ShadowsocksClient.BuildAddressHeader(buffer, "2001:db8::1", 8080);
        Assert.Equal(HeaderIpv6, Hex(buffer.Slice(0, n)));

        n = ShadowsocksClient.BuildAddressHeader(buffer, "example.com", 80);
        Assert.Equal(HeaderDomain80, Hex(buffer.Slice(0, n)));
    }

    /// <summary>
    /// The complete first packet through the public path: <c>salt ‖ chunk(atyp ‖ addr ‖ port)</c>,
    /// with the vector salt injected through the internal hook. Nothing may be read.
    /// </summary>
    [Theory]
    [InlineData(Aes128, "example.com", 443, "domain")]
    [InlineData(Aes128, "1.2.3.4", 80, "ipv4")]
    [InlineData(Aes128, "2001:db8::1", 8080, "ipv6")]
    [InlineData(Aes192, "example.com", 443, "domain")]
    [InlineData(Aes192, "1.2.3.4", 80, "ipv4")]
    [InlineData(Aes192, "2001:db8::1", 8080, "ipv6")]
    [InlineData(Aes256, "example.com", 443, "domain")]
    [InlineData(Aes256, "1.2.3.4", 80, "ipv4")]
    [InlineData(Aes256, "2001:db8::1", 8080, "ipv6")]
    [ChaCha20InlineData(ChaCha, "example.com", 443, "domain")]
    [ChaCha20InlineData(ChaCha, "1.2.3.4", 80, "ipv4")]
    [ChaCha20InlineData(ChaCha, "2001:db8::1", 8080, "ipv6")]
    public async Task ConnectAsync_WritesThePinnedFirstPacket_AndReadsNothing(string name, string host, int port, string which)
    {
        Vector v = Vectors[name];
        string expected = which switch
        {
            "domain" => v.PacketDomain,
            "ipv4" => v.PacketIpv4,
            _ => v.PacketIpv6
        };

        var transport = new ScriptedDuplexStream();
        var client = new ShadowsocksClient(new ShadowsocksOptions
        {
            Method = name, Password = Password, Host = "proxy.example", Port = 8388
        })
        {
            SaltSource = salt => FixedSalt(salt.Length).CopyTo(salt)
        };

        await using Stream tunnel = await client.ConnectAsync(transport, host, port);

        Assert.Equal(expected, Hex(transport.Written));
        Assert.Equal(0, transport.ReadCount); // the server salt is read lazily, never at connect
        Assert.IsType<ShadowsocksStream>(tunnel);
    }

    /// <summary>
    /// The header and the first payload may share one chunk (shadowsocks-rust does this to hide
    /// the short address chunk). This client sends the header alone from ConnectAsync, so the
    /// coalesced vector is pinned at the stream level, where a single write is a single chunk.
    /// </summary>
    [Theory]
    [InlineData(Aes128)]
    [InlineData(Aes192)]
    [InlineData(Aes256)]
    [ChaCha20InlineData(ChaCha)]
    public async Task HeaderWithInitialPayloadInOneChunk_MatchesThePinnedPacket(string name)
    {
        Vector v = Vectors[name];
        var transport = new DuplexTestStream([]);
        var stream = Stream(v, transport);

        await stream.WriteAsync(Hex(HeaderDomain80 + InitialPayload));

        Assert.Equal(v.PacketDomainWithPayload, Hex(transport.Written));
        Assert.Equal("GET / HTTP/1.0\r\n\r\n", Encoding.ASCII.GetString(Hex(InitialPayload)));
    }

    // ================================ constants ================================

    [Fact]
    public void Constants_MatchTheSpec()
    {
        Assert.Equal(16, ShadowsocksStream.TagSize);
        Assert.Equal(2, ShadowsocksStream.LengthSize);
        Assert.Equal(18, ShadowsocksStream.LengthBlockSize);
        Assert.Equal(0x3FFF, ShadowsocksStream.MaxPayloadSize);
        Assert.Equal(16417, ShadowsocksStream.MaxWireChunkSize);
        Assert.Equal(12, ShadowsocksCipher.NonceSize);
        Assert.Equal(16, ShadowsocksCipher.KeySize(ShadowsocksMethod.Aes128Gcm));
        Assert.Equal(24, ShadowsocksCipher.KeySize(ShadowsocksMethod.Aes192Gcm));
        Assert.Equal(32, ShadowsocksCipher.KeySize(ShadowsocksMethod.Aes256Gcm));
        Assert.Equal(32, ShadowsocksCipher.KeySize(ShadowsocksMethod.ChaCha20Poly1305));
    }
}
