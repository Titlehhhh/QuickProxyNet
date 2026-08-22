using System.Text;

namespace QuickProxyNet.Tests;

public class Sha224Test
{
    /// <summary>
    /// Asserts the vector against BOTH code paths: the public dispatching entry (which
    /// takes the Vector128 schedule path on accelerated hardware) and the forced scalar
    /// fallback. On a machine without Vector128 acceleration both calls run scalar.
    /// </summary>
    private static void AssertDigest(ReadOnlySpan<byte> data, string expectedHex)
    {
        byte[] expected = Convert.FromHexString(expectedHex);

        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(data, digest);
        Assert.Equal(expected, digest.ToArray());

        digest.Clear();
        Sha224.ComputeHashScalar(data, digest);
        Assert.Equal(expected, digest.ToArray());
    }

    // === FIPS 180-4 / NIST CAVP vectors ===

    [Fact]
    public void ComputeHash_EmptyInput_MatchesNistVector()
        => AssertDigest(
            ReadOnlySpan<byte>.Empty,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    [Fact]
    public void ComputeHash_Abc_MatchesNistVector()
        => AssertDigest(
            "abc"u8,
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");

    [Fact]
    public void ComputeHash_56ByteInput_PaddingSpillsIntoSecondBlock()
        // 56 bytes: tail + 0x80 + 8-byte length does not fit in one 64-byte block,
        // so the padding must roll over into a second block.
        => AssertDigest(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8,
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

    [Fact]
    public void ComputeHash_112ByteInput_MultiBlock_MatchesNistVector()
        // Official NIST two-block message sample (112 bytes > 64 exercises the
        // full-block loop before padding).
        => AssertDigest(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"u8 +
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"u8,
            "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");

    // === Independent oracle (OpenSSL) for block-boundary and long inputs ===

    [Fact]
    public void ComputeHash_63Bytes_LastSingleBlockBoundary()
    {
        Span<byte> data = stackalloc byte[63];
        data.Fill((byte)'x');
        AssertDigest(data, "57176f335e39202a5454db924c660af77ec98a91f35706d9f57d7398");
    }

    [Fact]
    public void ComputeHash_64Bytes_ExactBlockThenPaddingOnlyBlock()
    {
        Span<byte> data = stackalloc byte[64];
        data.Fill((byte)'x');
        AssertDigest(data, "08c3050e95fe11eacb9dc7824bf6a92bcf2d59c21701321fba0e62c5");
    }

    [Fact]
    public void ComputeHash_200Bytes_MultiBlock()
    {
        Span<byte> data = stackalloc byte[200];
        data.Fill((byte)'a');
        AssertDigest(data, "2559984fd15e055f0d84c346483508242f02653ab7956401e551511c");
    }

    // === Scalar vs vectorized schedule: exhaustive length sweep 0..192 ===

    [Fact]
    public void ComputeHash_VectorAndScalarPathsAgree_AllLengthsToThreeBlocks()
    {
        // On accelerated hardware this cross-checks the Vector128 schedule against the
        // scalar one for every input length up to three blocks; without acceleration it
        // degenerates to scalar == scalar and stays green.
        Span<byte> data = stackalloc byte[192];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i * 31 + 7);

        Span<byte> viaDispatch = stackalloc byte[Sha224.HashSize];
        Span<byte> viaScalar = stackalloc byte[Sha224.HashSize];
        for (int len = 0; len <= data.Length; len++)
        {
            Sha224.ComputeHash(data.Slice(0, len), viaDispatch);
            Sha224.ComputeHashScalar(data.Slice(0, len), viaScalar);
            Assert.Equal(viaScalar.ToArray(), viaDispatch.ToArray());
        }
    }

    // === WriteHexLower ===

    [Fact]
    public void WriteHexLower_Abc_Produces56LowercaseHexBytes()
    {
        Span<byte> hex = stackalloc byte[Sha224.HexSize];
        Sha224.WriteHexLower("abc"u8, hex);
        Assert.Equal(
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            Encoding.ASCII.GetString(hex));
    }

    [Fact]
    public void WriteHexLower_Empty_Produces56LowercaseHexBytes()
    {
        Span<byte> hex = stackalloc byte[Sha224.HexSize];
        Sha224.WriteHexLower(ReadOnlySpan<byte>.Empty, hex);
        Assert.Equal(
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            Encoding.ASCII.GetString(hex));
    }

    // === Destination validation ===

    [Fact]
    public void ComputeHash_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[Sha224.HashSize - 1];
            Sha224.ComputeHash("abc"u8, small);
        });
    }

    [Fact]
    public void WriteHexLower_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[Sha224.HexSize - 1];
            Sha224.WriteHexLower("abc"u8, small);
        });
    }
}
