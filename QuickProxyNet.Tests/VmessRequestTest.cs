using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the VMessAEAD (alterId = 0) client request header:
/// <see cref="VmessCmdKey"/>, <see cref="VmessAuthId"/> and <see cref="VmessRequest"/>.
///
/// Every wire vector below is GROUND TRUTH produced by an independent Python
/// reimplementation (scratchpad/vmess_request_truth.py) written from
/// docs/vmess-aead-request.md alone — stdlib hashlib/zlib/struct, a hand-rolled
/// ipad/opad nested KDF and a hand-rolled FNV-1a-32, with AES-ECB/AES-GCM from
/// `cryptography`. That script first reproduces public known-answer vectors
/// (CRC32("123456789")=0xCBF43926, FNV-1a-32("")=0x811C9DC5, MD5("")) and the KDF
/// vectors already committed in VmessCryptoTest before any value here is trusted.
///
/// All inputs are synthetic: a made-up UUID, a fixed timestamp, counting byte
/// patterns, and RFC-documentation targets (mc.example.com, 192.0.2.10).
/// </summary>
public class VmessRequestTest
{
    // ---- synthetic scenario (must match scratchpad/vmess_request_truth.py) ----
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";
    private const long Timestamp = 1700000000L;

    private static readonly byte[] Random4 = Hex("aabbccdd");
    private static readonly byte[] ConnectionNonce = Hex("0102030405060708");
    private static readonly byte[] BodyIv = Hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    private static readonly byte[] BodyKey = Hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    private const byte RespV = 0x2A;
    private const byte Option = 0x1D; // S|M|P|A
    private const byte Security = VmessRequest.SecurityAes128Gcm; // 3
    private const byte Command = VmessRequest.CommandTcp;         // 1

    private static readonly byte[] Padding15 = Hex("e0e1e2e3e4e5e6e7e8e9eaebecedee");
    private static readonly byte[] Padding0 = [];

    private const string DomainHost = "mc.example.com";
    private const int DomainPort = 25565;
    private const string IPv4Host = "192.0.2.10";
    private const int IPv4Port = 443;

    // ---- pinned expectations ----
    private const string ExpectedCmdKey = "704509150f5149ab9e46f235943a0cf1";
    private const string ExpectedAuthIdKey = "d6ab098903a2d086db7b1473959b93ed";
    private const string ExpectedAuthIdPlaintext = "000000006553f100aabbccdd5bdd8f9d";
    private const string ExpectedAuthId = "b76d66e3b7e88c9e6bd82d8bd530a9a1";

    private const string ExpectedCommandDomainPad15 =
        "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf2a1df3" +
        "000163dd020e6d632e6578616d706c652e636f6de0e1e2e3e4e5e6e7e8e9eaebecedee" +
        "bfbe1759";

    private const string ExpectedCommandDomainPad0 =
        "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf2a1d03" +
        "000163dd020e6d632e6578616d706c652e636f6d2a3bdef2";

    private const string ExpectedCommandIPv4Pad15 =
        "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf2a1df3" +
        "000101bb01c000020ae0e1e2e3e4e5e6e7e8e9eaebecedeef9190117";

    private const string ExpectedCommandIPv4Pad0 =
        "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf2a1d03" +
        "000101bb01c000020acbfcda38";

    private const string ExpectedWireDomainPad15 =
        "b76d66e3b7e88c9e6bd82d8bd530a9a1e5e5800c8a518063849e15436598e33cf69f" +
        "0102030405060708" +
        "e10b9b9a4af9ddb12a73a436cd39304f38f3119cc7084e1e6a34eefc6b489e24447ad6" +
        "9d43deded7de3a56cb346402328dec2f57a4dedb18a9f9a125615740e0d537f9309af7" +
        "6b1b55d066fd66442fbfbff185570c89035db2005a";

    private const string ExpectedWireDomainPad0 =
        "b76d66e3b7e88c9e6bd82d8bd530a9a1e592f5c5f887a7fbc084eb3a16349b72f6b6" +
        "0102030405060708" +
        "e10b9b9a4af9ddb12a73a436cd39304f38f3119cc7084e1e6a34eefc6b489e24447ad6" +
        "6d43deded7de3a56cb346402328dec2f57a4dedb1863239d34366928564bcdd415f97f" +
        "3d9cbd0a44ac";

    private const string ExpectedWireIPv4Pad15 =
        "b76d66e3b7e88c9e6bd82d8bd530a9a1e5eeded78ce590ae08a9e8f2a2b4827d81ee" +
        "0102030405060708" +
        "e10b9b9a4af9ddb12a73a436cd39304f38f3119cc7084e1e6a34eefc6b489e24447ad6" +
        "9d43debcb1ddf43baa10e19bb10378a6d46d555d9fa2f4ae287caba7108b655708835" +
        "24cc3f633e83e436bf256";

    private const string ExpectedWireIPv4Pad0 =
        "b76d66e3b7e88c9e6bd82d8bd530a9a1e59f53e4457e72b26646dceb7de514b34d09" +
        "0102030405060708" +
        "e10b9b9a4af9ddb12a73a436cd39304f38f3119cc7084e1e6a34eefc6b489e24447ad6" +
        "6d43debcb1ddf43baa10ca8689d89aa806f52494b2073fd760ab873b3fcf";

    private static byte[] Hex(string h) => Convert.FromHexString(h);

    private static byte[] CmdKey()
    {
        var key = new byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, key);
        return key;
    }

    private static byte[] AuthId()
    {
        var authId = new byte[VmessAuthId.Size];
        VmessAuthId.Create(CmdKey(), Timestamp, Random4, authId);
        return authId;
    }

    // The material is a ref struct, so it is rebuilt per call from the array fields.
    private static VmessRequestMaterial Material(byte[] padding) => new()
    {
        AuthIdTimestamp = Timestamp,
        AuthIdRandom = Random4,
        ConnectionNonce = ConnectionNonce,
        BodyKey = BodyKey,
        BodyIv = BodyIv,
        ResponseVerifier = RespV,
        Padding = padding,
    };

    private static byte[] BuildCommandSection(byte[] padding, string host, int port)
    {
        var buffer = new byte[VmessRequest.MaxCommandSectionSize];
        int length = VmessRequest.WriteCommandSection(
            buffer, Material(padding), Option, Security, Command, host, port);
        return buffer[..length];
    }

    private static byte[] BuildWire(byte[] padding, string host, int port)
    {
        var buffer = new byte[VmessRequest.MaxRequestSize];
        int length = VmessRequest.Build(
            buffer, CmdKey(), Material(padding), Option, Security, Command, host, port);
        return buffer[..length];
    }

    // ========================= §1 cmdKey =========================

    [Fact]
    public void CmdKey_MatchesGroundTruth()
    {
        Assert.Equal(ExpectedCmdKey, Convert.ToHexStringLower(CmdKey()));
    }

    [Fact]
    public void CmdKey_IsMd5OfUuidPlusMagic_52ByteInput()
    {
        // Independent re-computation of §1 from the raw pieces, to prove the helper
        // hashes uuid16 ‖ magic (52 bytes) in that order and nothing else.
        byte[] input = new byte[52];
        Guid.Parse(Uuid).TryWriteBytes(input.AsSpan(0, 16), bigEndian: true, out _);
        "c48619fe-8f02-49e0-b9e9-edf763e17e21"u8.CopyTo(input.AsSpan(16));

        Assert.Equal(Convert.ToHexStringLower(MD5.HashData(input)), Convert.ToHexStringLower(CmdKey()));
    }

    [Fact]
    public void CmdKey_UsesBigEndianUuidBytes_NotGuidToByteArray()
    {
        // Guid.ToByteArray() is little-endian for the first three fields; using it would
        // silently produce a different (wrong) cmdKey.
        byte[] wrong = new byte[52];
        Guid.Parse(Uuid).ToByteArray().CopyTo(wrong, 0);
        "c48619fe-8f02-49e0-b9e9-edf763e17e21"u8.CopyTo(wrong.AsSpan(16));

        Assert.NotEqual(ExpectedCmdKey, Convert.ToHexStringLower(MD5.HashData(wrong)));
    }

    [Fact]
    public void CmdKey_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[15];
            VmessCmdKey.Derive(Uuid, small);
        });
    }

    [Fact]
    public void CmdKey_UnusableUuid_Throws()
    {
        // 31 characters: too long for Xray's derivation window (1..30), too short to be a
        // canonical UUID (32..36). Upstream errors here, so must we.
        Assert.Throws<FormatException>(() =>
        {
            Span<byte> dst = stackalloc byte[16];
            VmessCmdKey.Derive(new string('x', 31), dst);
        });

        Assert.Throws<FormatException>(() =>
        {
            Span<byte> dst = stackalloc byte[16];
            VmessCmdKey.Derive("", dst);
        });
    }

    [Fact]
    public void CmdKey_ShortNonUuidId_UsesDerivedUuid()
    {
        // A short non-UUID id is not an error: it is mapped to UUIDv5(nil, id), so the
        // cmdKey must equal the one derived from that UUID's canonical spelling.
        Span<byte> fromText = stackalloc byte[16];
        VmessCmdKey.Derive("not-a-uuid", fromText);

        Span<byte> fromDerivedUuid = stackalloc byte[16];
        VmessCmdKey.Derive("9b70e619-d7b3-55b1-b743-756ebd573b4e", fromDerivedUuid);

        Assert.Equal(fromDerivedUuid.ToArray(), fromText.ToArray());
    }

    // ========================= §3 AuthID =========================

    [Fact]
    public void AuthId_Plaintext_MatchesGroundTruth()
    {
        Span<byte> plaintext = stackalloc byte[16];
        VmessAuthId.WritePlaintext(Timestamp, Random4, plaintext);
        Assert.Equal(ExpectedAuthIdPlaintext, Convert.ToHexStringLower(plaintext));
    }

    [Fact]
    public void AuthId_Plaintext_LayoutIsTimestampRandomCrc()
    {
        Span<byte> plaintext = stackalloc byte[16];
        VmessAuthId.WritePlaintext(Timestamp, Random4, plaintext);

        // [0..8) int64 big-endian timestamp
        Assert.Equal(Timestamp, BinaryPrimitives.ReadInt64BigEndian(plaintext));
        // [8..12) the supplied random bytes
        Assert.Equal(Random4, plaintext.Slice(8, 4).ToArray());
        // [12..16) CRC-32/IEEE of the FIRST TWELVE bytes, big-endian
        uint crc = Crc32.Compute(plaintext[..12]);
        Assert.Equal(crc, BinaryPrimitives.ReadUInt32BigEndian(plaintext[12..]));
        Assert.Equal(0x5bdd8f9du, crc);
    }

    [Fact]
    public void AuthId_Plaintext_ZeroInputs_MatchesGroundTruth()
    {
        Span<byte> plaintext = stackalloc byte[16];
        VmessAuthId.WritePlaintext(0, new byte[4], plaintext);
        Assert.Equal("0000000000000000000000007bd5c66f", Convert.ToHexStringLower(plaintext));
    }

    [Fact]
    public void AuthId_EncryptionKey_MatchesGroundTruth()
    {
        Span<byte> key = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey(), "AES Auth ID Encryption"u8, key);
        Assert.Equal(ExpectedAuthIdKey, Convert.ToHexStringLower(key));
    }

    [Fact]
    public void AuthId_Encrypted_MatchesGroundTruth()
    {
        Assert.Equal(ExpectedAuthId, Convert.ToHexStringLower(AuthId()));
    }

    [Fact]
    public void AuthId_ZeroInputs_MatchesGroundTruth()
    {
        Span<byte> authId = stackalloc byte[16];
        VmessAuthId.Create(CmdKey(), 0, new byte[4], authId);
        Assert.Equal("fd5844d453230c0f57028e2d77bb6cf8", Convert.ToHexStringLower(authId));
    }

    [Fact]
    public void AuthId_IsSingleBlockEcb_NoPaddingNoIv()
    {
        // Decrypting the 16-byte AuthID with the derived key must return the plaintext
        // exactly — proving raw ECB of one block (an AEAD or CBC would not round-trip).
        byte[] key = new byte[16];
        VmessKdf.Kdf16(CmdKey(), "AES Auth ID Encryption"u8, key);

        using var aes = Aes.Create();
        aes.Key = key;
        byte[] decrypted = aes.DecryptEcb(AuthId(), PaddingMode.None);

        Assert.Equal(ExpectedAuthIdPlaintext, Convert.ToHexStringLower(decrypted));
    }

    [Fact]
    public void AuthId_ConvenienceOverload_UsesCurrentTimeAndFreshRandomness()
    {
        byte[] key = new byte[16];
        VmessKdf.Kdf16(CmdKey(), "AES Auth ID Encryption"u8, key);

        Span<byte> first = stackalloc byte[16];
        Span<byte> second = stackalloc byte[16];
        VmessAuthId.Create(CmdKey(), first);
        VmessAuthId.Create(CmdKey(), second);

        // Fresh randomness per call.
        Assert.NotEqual(first.ToArray(), second.ToArray());

        using var aes = Aes.Create();
        aes.Key = key;
        byte[] plaintext = aes.DecryptEcb(first, PaddingMode.None);

        long stamp = BinaryPrimitives.ReadInt64BigEndian(plaintext);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // VMessAEAD sends the exact current second (no ±30 s legacy jitter).
        Assert.InRange(stamp, now - 5, now + 5);
        Assert.Equal(Crc32.Compute(plaintext.AsSpan(0, 12)),
            BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan(12)));
    }

    [Fact]
    public void AuthId_RandomWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> dst = stackalloc byte[16];
            VmessAuthId.Create(CmdKey(), Timestamp, new byte[3], dst);
        });
    }

    [Fact]
    public void AuthId_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[15];
            VmessAuthId.Create(CmdKey(), Timestamp, Random4, small);
        });
    }

    [Fact]
    public void AuthId_CmdKeyWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> dst = stackalloc byte[16];
            VmessAuthId.Create(new byte[15], Timestamp, Random4, dst);
        });
    }

    [Fact]
    public void AuthId_PlaintextDestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[15];
            VmessAuthId.WritePlaintext(Timestamp, Random4, small);
        });
    }

    // ========================= §5 command section =========================

    [Fact]
    public void CommandSection_Domain_Padding15_MatchesGroundTruth()
    {
        byte[] data = BuildCommandSection(Padding15, DomainHost, DomainPort);
        Assert.Equal(75, data.Length);
        Assert.Equal(ExpectedCommandDomainPad15, Convert.ToHexStringLower(data));
    }

    [Fact]
    public void CommandSection_Domain_Padding0_MatchesGroundTruth()
    {
        byte[] data = BuildCommandSection(Padding0, DomainHost, DomainPort);
        Assert.Equal(60, data.Length);
        Assert.Equal(ExpectedCommandDomainPad0, Convert.ToHexStringLower(data));
    }

    [Fact]
    public void CommandSection_IPv4_Padding15_MatchesGroundTruth()
    {
        byte[] data = BuildCommandSection(Padding15, IPv4Host, IPv4Port);
        Assert.Equal(64, data.Length);
        Assert.Equal(ExpectedCommandIPv4Pad15, Convert.ToHexStringLower(data));
    }

    [Fact]
    public void CommandSection_IPv4_Padding0_MatchesGroundTruth()
    {
        byte[] data = BuildCommandSection(Padding0, IPv4Host, IPv4Port);
        Assert.Equal(49, data.Length);
        Assert.Equal(ExpectedCommandIPv4Pad0, Convert.ToHexStringLower(data));
    }

    [Fact]
    public void CommandSection_FieldLayout_IsVersionIvKeyRespOptionPadSec()
    {
        byte[] data = BuildCommandSection(Padding15, DomainHost, DomainPort);

        Assert.Equal(0x01, data[0]);                                  // version
        Assert.Equal(BodyIv, data[1..17]);                            // requestBodyIV
        Assert.Equal(BodyKey, data[17..33]);                          // requestBodyKey
        Assert.Equal(RespV, data[33]);                                // response verifier
        Assert.Equal(Option, data[34]);                               // option flags
        Assert.Equal(0xF3, data[35]);                                 // (15 << 4) | 3
        Assert.Equal(15, data[35] >> 4);                              // padding nibble
        Assert.Equal(Security, (byte)(data[35] & 0x0F));              // security nibble
        Assert.Equal(0x00, data[36]);                                 // reserved
        Assert.Equal(Command, data[37]);                              // command
    }

    [Fact]
    public void CommandSection_WritesPortBeforeAddress()
    {
        // VMess is PortThenAddress — the opposite of SOCKS5/Trojan.
        byte[] data = BuildCommandSection(Padding0, DomainHost, DomainPort);

        Assert.Equal(DomainPort, BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(38, 2)));
        Assert.Equal(0x63, data[38]);                                 // 25565 = 0x63DD
        Assert.Equal(0xDD, data[39]);
        Assert.Equal(0x02, data[40]);                                 // atyp = domain
        Assert.Equal(DomainHost.Length, data[41]);                    // 1-byte length prefix
        Assert.Equal(DomainHost, System.Text.Encoding.ASCII.GetString(data, 42, DomainHost.Length));
    }

    [Fact]
    public void CommandSection_IPv4_UsesAtyp01AndRawBytes()
    {
        byte[] data = BuildCommandSection(Padding0, IPv4Host, IPv4Port);

        Assert.Equal(IPv4Port, BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(38, 2)));
        Assert.Equal(0x01, data[40]);                                 // atyp = IPv4
        Assert.Equal(Hex("c000020a"), data[41..45]);                  // 192.0.2.10
    }

    [Fact]
    public void CommandSection_IPv6_UsesAtyp03And16RawBytes()
    {
        byte[] data = BuildCommandSection(Padding0, "2001:db8::1", 8080);

        Assert.Equal(8080, BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(38, 2)));
        Assert.Equal(0x03, data[40]);                                 // atyp = IPv6
        Assert.Equal(Hex("20010db8000000000000000000000001"), data[41..57]);
        Assert.Equal(40 + 1 + 16 + 4, data.Length);
    }

    [Fact]
    public void CommandSection_PaddingPrecedesChecksum_AndIsCovered()
    {
        byte[] data = BuildCommandSection(Padding15, DomainHost, DomainPort);

        // padding sits immediately before the 4-byte checksum
        Assert.Equal(Padding15, data[^19..^4]);

        // FNV-1a-32 big-endian over everything preceding it, padding included
        Assert.Equal(Fnv1a32.Compute(data.AsSpan(0, data.Length - 4)),
            BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(data.Length - 4)));
        Assert.Equal(0xbfbe1759u, Fnv1a32.Compute(data.AsSpan(0, data.Length - 4)));
    }

    [Fact]
    public void CommandSection_ChecksumChangesWithPadding()
    {
        byte[] withPadding = BuildCommandSection(Padding15, DomainHost, DomainPort);
        byte[] withoutPadding = BuildCommandSection(Padding0, DomainHost, DomainPort);

        Assert.NotEqual(withPadding[^4..], withoutPadding[^4..]);
        Assert.Equal(0x2a3bdef2u, Fnv1a32.Compute(withoutPadding.AsSpan(0, withoutPadding.Length - 4)));
    }

    [Fact]
    public void CommandSection_PaddingTooLong_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            var buffer = new byte[VmessRequest.MaxCommandSectionSize];
            VmessRequest.WriteCommandSection(
                buffer, Material(new byte[16]), Option, Security, Command, DomainHost, DomainPort);
        });
    }

    [Fact]
    public void CommandSection_BodyKeyWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            var buffer = new byte[VmessRequest.MaxCommandSectionSize];
            var material = new VmessRequestMaterial
            {
                AuthIdTimestamp = Timestamp,
                AuthIdRandom = Random4,
                ConnectionNonce = ConnectionNonce,
                BodyKey = new byte[15],
                BodyIv = BodyIv,
                ResponseVerifier = RespV,
                Padding = Padding0,
            };
            VmessRequest.WriteCommandSection(
                buffer, material, Option, Security, Command, DomainHost, DomainPort);
        });
    }

    [Fact]
    public void CommandSection_BodyIvWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            var buffer = new byte[VmessRequest.MaxCommandSectionSize];
            var material = new VmessRequestMaterial
            {
                AuthIdTimestamp = Timestamp,
                AuthIdRandom = Random4,
                ConnectionNonce = ConnectionNonce,
                BodyKey = BodyKey,
                BodyIv = new byte[17],
                ResponseVerifier = RespV,
                Padding = Padding0,
            };
            VmessRequest.WriteCommandSection(
                buffer, material, Option, Security, Command, DomainHost, DomainPort);
        });
    }

    [Fact]
    public void CommandSection_SecurityOutOfRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            var buffer = new byte[VmessRequest.MaxCommandSectionSize];
            VmessRequest.WriteCommandSection(
                buffer, Material(Padding0), Option, 0x10, Command, DomainHost, DomainPort);
        });
    }

    [Fact]
    public void CommandSection_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            var buffer = new byte[VmessRequest.MaxCommandSectionSize - 1];
            VmessRequest.WriteCommandSection(
                buffer, Material(Padding0), Option, Security, Command, DomainHost, DomainPort);
        });
    }

    // ========================= §4 sealed envelope =========================

    [Fact]
    public void Wire_Domain_Padding15_MatchesGroundTruth()
    {
        byte[] wire = BuildWire(Padding15, DomainHost, DomainPort);
        Assert.Equal(58 + 75, wire.Length);
        Assert.Equal(ExpectedWireDomainPad15, Convert.ToHexStringLower(wire));
    }

    [Fact]
    public void Wire_Domain_Padding0_MatchesGroundTruth()
    {
        byte[] wire = BuildWire(Padding0, DomainHost, DomainPort);
        Assert.Equal(58 + 60, wire.Length);
        Assert.Equal(ExpectedWireDomainPad0, Convert.ToHexStringLower(wire));
    }

    [Fact]
    public void Wire_IPv4_Padding15_MatchesGroundTruth()
    {
        byte[] wire = BuildWire(Padding15, IPv4Host, IPv4Port);
        Assert.Equal(58 + 64, wire.Length);
        Assert.Equal(ExpectedWireIPv4Pad15, Convert.ToHexStringLower(wire));
    }

    [Fact]
    public void Wire_IPv4_Padding0_MatchesGroundTruth()
    {
        byte[] wire = BuildWire(Padding0, IPv4Host, IPv4Port);
        Assert.Equal(58 + 49, wire.Length);
        Assert.Equal(ExpectedWireIPv4Pad0, Convert.ToHexStringLower(wire));
    }

    [Fact]
    public void Wire_FieldOrder_IsAuthIdLengthNoncePayload()
    {
        byte[] wire = BuildWire(Padding15, DomainHost, DomainPort);

        Assert.Equal(AuthId(), wire[..16]);                       // [0..16)  authid
        Assert.Equal(ConnectionNonce, wire[34..42]);              // [34..42) connection nonce
        Assert.Equal(58 + 75, wire.Length);                       // 16 + 18 + 8 + (L + 16)
    }

    [Fact]
    public void Wire_LengthAead_DecryptsToCommandSectionLength()
    {
        // Acts as the server: re-derive the length key/nonce and open [16..34) with the
        // AuthID as associated data.
        byte[] wire = BuildWire(Padding15, DomainHost, DomainPort);
        byte[] authId = wire[..16];

        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        VmessKdf.Kdf16(CmdKey(), "VMess Header AEAD Key_Length"u8, authId, ConnectionNonce, key);
        VmessKdf.Kdf12(CmdKey(), "VMess Header AEAD Nonce_Length"u8, authId, ConnectionNonce, nonce);

        byte[] plaintext = new byte[2];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, wire.AsSpan(16, 2), wire.AsSpan(18, 16), plaintext, authId);

        Assert.Equal(75, BinaryPrimitives.ReadUInt16BigEndian(plaintext));
    }

    [Fact]
    public void Wire_PayloadAead_DecryptsToCommandSection()
    {
        byte[] wire = BuildWire(Padding15, DomainHost, DomainPort);
        byte[] authId = wire[..16];

        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        VmessKdf.Kdf16(CmdKey(), "VMess Header AEAD Key"u8, authId, ConnectionNonce, key);
        VmessKdf.Kdf12(CmdKey(), "VMess Header AEAD Nonce"u8, authId, ConnectionNonce, nonce);

        int length = wire.Length - 58;
        byte[] plaintext = new byte[length];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, wire.AsSpan(42, length), wire.AsSpan(42 + length, 16), plaintext, authId);

        Assert.Equal(ExpectedCommandDomainPad15, Convert.ToHexStringLower(plaintext));
    }

    [Fact]
    public void Wire_AuthIdIsAssociatedData_TamperingIsDetected()
    {
        byte[] wire = BuildWire(Padding0, IPv4Host, IPv4Port);
        byte[] tamperedAuthId = wire[..16];
        tamperedAuthId[0] ^= 0xFF;

        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        VmessKdf.Kdf16(CmdKey(), "VMess Header AEAD Key"u8, wire.AsSpan(0, 16), ConnectionNonce, key);
        VmessKdf.Kdf12(CmdKey(), "VMess Header AEAD Nonce"u8, wire.AsSpan(0, 16), ConnectionNonce, nonce);

        int length = wire.Length - 58;
        byte[] plaintext = new byte[length];
        using var gcm = new AesGcm(key, 16);

        // Correct key/nonce but the wrong AAD must fail the tag check.
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            gcm.Decrypt(nonce, wire.AsSpan(42, length), wire.AsSpan(42 + length, 16), plaintext, tamperedAuthId));
    }

    [Fact]
    public void Seal_ComposesWithWriteCommandSection()
    {
        byte[] data = BuildCommandSection(Padding15, DomainHost, DomainPort);
        byte[] sealed_ = new byte[VmessRequest.MaxRequestSize];
        int length = VmessRequest.Seal(sealed_, CmdKey(), AuthId(), ConnectionNonce, data);

        Assert.Equal(58 + data.Length, length);
        Assert.Equal(ExpectedWireDomainPad15, Convert.ToHexStringLower(sealed_.AsSpan(0, length)));
    }

    [Fact]
    public void Seal_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            byte[] data = BuildCommandSection(Padding0, IPv4Host, IPv4Port);
            byte[] tooSmall = new byte[58 + data.Length - 1];
            VmessRequest.Seal(tooSmall, CmdKey(), AuthId(), ConnectionNonce, data);
        });
    }

    [Fact]
    public void Seal_CmdKeyWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            VmessRequest.Seal(new byte[VmessRequest.MaxRequestSize], new byte[15], AuthId(),
                ConnectionNonce, BuildCommandSection(Padding0, IPv4Host, IPv4Port)));
    }

    [Fact]
    public void Seal_AuthIdWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            VmessRequest.Seal(new byte[VmessRequest.MaxRequestSize], CmdKey(), new byte[15],
                ConnectionNonce, BuildCommandSection(Padding0, IPv4Host, IPv4Port)));
    }

    [Fact]
    public void Seal_ConnectionNonceWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            VmessRequest.Seal(new byte[VmessRequest.MaxRequestSize], CmdKey(), AuthId(),
                new byte[7], BuildCommandSection(Padding0, IPv4Host, IPv4Port)));
    }

    // ========================= sizes & production material =========================

    [Fact]
    public void Constants_MatchSpecSizes()
    {
        Assert.Equal(58, VmessRequest.SealOverhead);
        Assert.Equal(15, VmessRequest.MaxPaddingLength);
        Assert.Equal(60, VmessRequest.MaterialScratchSize);
        Assert.Equal(316, VmessRequest.MaxCommandSectionSize);
        Assert.Equal(374, VmessRequest.MaxRequestSize);
        Assert.Equal(0x1D, VmessRequest.DefaultOption);
    }

    [Fact]
    public void CreateMaterial_FillsEveryFieldWithTheRightSize()
    {
        Span<byte> scratch = stackalloc byte[VmessRequest.MaterialScratchSize];
        var material = VmessRequest.CreateMaterial(scratch);

        Assert.Equal(VmessAuthId.RandomSize, material.AuthIdRandom.Length);
        Assert.Equal(VmessRequest.ConnectionNonceSize, material.ConnectionNonce.Length);
        Assert.Equal(VmessRequest.BodyKeySize, material.BodyKey.Length);
        Assert.Equal(VmessRequest.BodyKeySize, material.BodyIv.Length);
        Assert.InRange(material.Padding.Length, 0, VmessRequest.MaxPaddingLength);
        Assert.InRange(material.AuthIdTimestamp,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 5,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5);

        // The body key and IV must be independent random values, not the same slice.
        Assert.NotEqual(material.BodyKey.ToArray(), material.BodyIv.ToArray());
    }

    [Fact]
    public void CreateMaterial_ProducesAValidHeaderOfTheExpectedLength()
    {
        Span<byte> scratch = stackalloc byte[VmessRequest.MaterialScratchSize];
        var material = VmessRequest.CreateMaterial(scratch);

        Span<byte> destination = stackalloc byte[VmessRequest.MaxRequestSize];
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, cmdKey);

        int length = VmessRequest.Build(destination, cmdKey, material, VmessRequest.DefaultOption,
            VmessRequest.SecurityAes128Gcm, VmessRequest.CommandTcp, DomainHost, DomainPort);

        // 58 + version(1)+iv(16)+key(16)+respV(1)+opt(1)+padSec(1)+rsv(1)+cmd(1)+port(2)
        //    + atyp(1)+len(1)+host(14) + padding + fnv(4)
        Assert.Equal(58 + 60 + material.Padding.Length, length);
        Assert.Equal(material.ConnectionNonce.ToArray(), destination.Slice(34, 8).ToArray());
    }

    [Fact]
    public void CreateMaterial_ScratchTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> scratch = stackalloc byte[VmessRequest.MaterialScratchSize - 1];
            VmessRequest.CreateMaterial(scratch);
        });
    }

    [Fact]
    public void Build_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            byte[] tooSmall = new byte[58 + 60 - 1];
            VmessRequest.Build(tooSmall, CmdKey(), Material(Padding0), Option, Security, Command,
                DomainHost, DomainPort);
        });
    }
}
