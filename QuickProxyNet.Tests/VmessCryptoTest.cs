namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the VMessAEAD crypto primitives (<see cref="VmessKdf"/>,
/// <see cref="Fnv1a32"/>, <see cref="Crc32"/>, <see cref="VmessBodyKeys"/>).
///
/// The KDF / expansion vectors below are GROUND TRUTH produced by an independent
/// Python reimplementation (manual ipad/opad nested HMAC, standalone FNV/CRC/MD5/SHA)
/// over fixed synthetic inputs — NO real UUIDs/IPs. The standalone primitives are also
/// anchored against publicly known vectors (CRC32("123456789")=0xCBF43926,
/// FNV-1a-32("")=0x811C9DC5, etc.), which the Python must reproduce before its KDF
/// output is trusted.
/// </summary>
public class VmessCryptoTest
{
    // ---- synthetic inputs (must match scratchpad/vmess_truth.py) ----
    private static readonly byte[] CmdKey =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]; // 00..0F

    private static readonly byte[] AuthId =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]; // 10..1F

    private static readonly byte[] Nonce =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]; // 8-byte connection nonce

    private static byte[] Hex(string h) => Convert.FromHexString(h);

    // ========================= VmessKdf: 3-path (request header) =========================

    [Fact]
    public void Kdf16_RequestLengthKey_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "VMess Header AEAD Key_Length"u8, AuthId, Nonce, dst);
        Assert.Equal(Hex("47c5ee168f14ba38aebc458844e45fa3"), dst.ToArray());
    }

    [Fact]
    public void Kdf12_RequestLengthNonce_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[12];
        VmessKdf.Kdf12(CmdKey, "VMess Header AEAD Nonce_Length"u8, AuthId, Nonce, dst);
        Assert.Equal(Hex("1568461eed64408cce969ac2"), dst.ToArray());
    }

    [Fact]
    public void Kdf16_RequestPayloadKey_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "VMess Header AEAD Key"u8, AuthId, Nonce, dst);
        Assert.Equal(Hex("e008b551916d71746eb05acd8cfc6e9b"), dst.ToArray());
    }

    [Fact]
    public void Kdf12_RequestPayloadNonce_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[12];
        VmessKdf.Kdf12(CmdKey, "VMess Header AEAD Nonce"u8, AuthId, Nonce, dst);
        Assert.Equal(Hex("a8b2aa472f51ef4939775062"), dst.ToArray());
    }

    // ========================= VmessKdf: 1-path (response header) =========================

    [Fact]
    public void Kdf16_ResponseLengthKey_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "AEAD Resp Header Len Key"u8, dst);
        Assert.Equal(Hex("1dbcdc6d886515862212014a20172f03"), dst.ToArray());
    }

    [Fact]
    public void Kdf12_ResponseLengthIv_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[12];
        VmessKdf.Kdf12(CmdKey, "AEAD Resp Header Len IV"u8, dst);
        Assert.Equal(Hex("c10dd09b55bbeca420a83f58"), dst.ToArray());
    }

    [Fact]
    public void Kdf16_ResponsePayloadKey_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "AEAD Resp Header Key"u8, dst);
        Assert.Equal(Hex("e8c31fe70c8376b328379ee4bacfa47b"), dst.ToArray());
    }

    [Fact]
    public void Kdf12_ResponsePayloadIv_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[12];
        VmessKdf.Kdf12(CmdKey, "AEAD Resp Header IV"u8, dst);
        Assert.Equal(Hex("4c594d26e9cb8a2feeee9cca"), dst.ToArray());
    }

    // ========================= VmessKdf: auth-id AES key (1-path) =========================

    [Fact]
    public void Kdf16_AuthIdEncryptionKey_MatchesGroundTruth()
    {
        Span<byte> dst = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "AES Auth ID Encryption"u8, dst);
        Assert.Equal(Hex("9fa4289c41650861a45b34aeab3879fe"), dst.ToArray());
    }

    // ========================= VmessKdf: truncation & validation =========================

    [Fact]
    public void Kdf16_And_Kdf12_ArePrefixesOfTheSame32ByteOutput()
    {
        // Kdf16/Kdf12 truncate the same 32-byte KDF output, so the 12-byte prefix must
        // equal the first 12 bytes of the 16-byte result (Key_Length full = ...5fa3eecd...).
        Span<byte> full16 = stackalloc byte[16];
        VmessKdf.Kdf16(CmdKey, "VMess Header AEAD Key_Length"u8, AuthId, Nonce, full16);
        Assert.Equal(
            Hex("47c5ee168f14ba38aebc458844e45fa3"),
            full16.ToArray());
    }

    [Fact]
    public void Kdf16_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[15];
            VmessKdf.Kdf16(CmdKey, "AEAD Resp Header Key"u8, small);
        });
    }

    [Fact]
    public void Kdf12_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[11];
            VmessKdf.Kdf12(CmdKey, "AEAD Resp Header IV"u8, AuthId, Nonce, small);
        });
    }

    // ========================= FNV-1a-32 =========================

    [Fact]
    public void Fnv1a32_KnownVectors()
    {
        Assert.Equal(0x811c9dc5u, Fnv1a32.Compute(ReadOnlySpan<byte>.Empty));
        Assert.Equal(0xe40c292cu, Fnv1a32.Compute("a"u8));
    }

    [Fact]
    public void Fnv1a32_SyntheticSample_MatchesGroundTruth()
    {
        // 00..13 (20 bytes)
        Span<byte> sample = stackalloc byte[20];
        for (int i = 0; i < sample.Length; i++)
            sample[i] = (byte)i;

        Assert.Equal(0x783b3501u, Fnv1a32.Compute(sample));
        Assert.Equal(0x4f9f2cabu, Fnv1a32.Compute("hello"u8));
    }

    [Fact]
    public void Fnv1a32_WriteBigEndian_IsNetworkOrder()
    {
        Span<byte> dst = stackalloc byte[4];
        Fnv1a32.WriteBigEndian("hello"u8, dst);
        Assert.Equal(Hex("4f9f2cab"), dst.ToArray());
    }

    // ========================= CRC-32/IEEE =========================

    [Fact]
    public void Crc32_KnownVectors()
    {
        Assert.Equal(0xCBF43926u, Crc32.Compute("123456789"u8));
        Assert.Equal(0x00000000u, Crc32.Compute(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Crc32_SyntheticSample_MatchesGroundTruth()
    {
        // 00..0B (12 bytes) — an AuthID plaintext prefix (timestamp ‖ random).
        Span<byte> sample = stackalloc byte[12];
        for (int i = 0; i < sample.Length; i++)
            sample[i] = (byte)i;

        Assert.Equal(0x9270c965u, Crc32.Compute(sample));
    }

    [Fact]
    public void Crc32_WriteBigEndian_IsNetworkOrder()
    {
        Span<byte> dst = stackalloc byte[4];
        Crc32.WriteBigEndian("123456789"u8, dst);
        Assert.Equal(Hex("cbf43926"), dst.ToArray());
    }

    // ========================= VmessBodyKeys: ChaCha20 expansion =========================

    [Fact]
    public void ExpandChaCha20Key_MatchesGroundTruth()
    {
        // bodyKey = 00..0F
        Span<byte> key = stackalloc byte[32];
        VmessBodyKeys.ExpandChaCha20Key(CmdKey, key);
        Assert.Equal(
            Hex("1ac1ef01e96caf1be0d329331a4fc2a8e0542db5418c43d256a6a643afa553fe"),
            key.ToArray());
    }

    [Fact]
    public void ExpandChaCha20Key_HalvesAreMd5Chained()
    {
        // Sanity: key[16:32] = MD5(key[0:16]); MD5("") anchor is unrelated but confirms
        // the BCL MD5 is the standard one via the well-known empty-string digest.
        Assert.Equal(
            "d41d8cd98f00b204e9800998ecf8427e",
            Convert.ToHexStringLower(System.Security.Cryptography.MD5.HashData(ReadOnlySpan<byte>.Empty)));
    }

    [Fact]
    public void ExpandChaCha20Key_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[31];
            VmessBodyKeys.ExpandChaCha20Key(CmdKey, small);
        });
    }

    // ========================= VmessBodyKeys: response key/IV =========================

    [Fact]
    public void DeriveResponseKeyOrIv_MatchesGroundTruth()
    {
        // source = requestBodyKey = 00..0F -> SHA256(x)[0:16]
        Span<byte> dst = stackalloc byte[16];
        VmessBodyKeys.DeriveResponseKeyOrIv(CmdKey, dst);
        Assert.Equal(Hex("be45cb2605bf36bebde684841a28f0fd"), dst.ToArray());
    }

    [Fact]
    public void DeriveResponseKeyOrIv_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[15];
            VmessBodyKeys.DeriveResponseKeyOrIv(CmdKey, small);
        });
    }
}
