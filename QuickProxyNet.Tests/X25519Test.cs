using System.Security.Cryptography;
using QuickProxyNet.Reality;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the managed X25519 used by the REALITY key exchange.
/// </summary>
/// <remarks>
/// The RFC 7748 vectors prove the arithmetic against the specification. The Xray keypair proves
/// it against the implementation we actually have to interoperate with — a self-consistent
/// curve implementation that disagrees with Go would pass every vector we invented ourselves.
/// </remarks>
public class X25519Test
{
    private static byte[] Hex(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);

        return bytes;
    }

    /// <summary>Decodes the base64url form share links and Xray's own tooling use for keys.</summary>
    private static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }

    // RFC 7748 §5.2.
    [Theory]
    [InlineData(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [InlineData(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public void Rfc7748_ScalarMultiplication(string scalar, string u, string expected)
    {
        byte[] result = new byte[32];
        X25519.Agree(result, Hex(scalar), Hex(u));

        Assert.Equal(expected, Convert.ToHexString(result).ToLowerInvariant());
    }

    // RFC 7748 §6.1.
    [Fact]
    public void Rfc7748_DiffieHellman()
    {
        byte[] alicePrivate = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPrivate = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        byte[] alicePublic = new byte[32];
        byte[] bobPublic = new byte[32];
        X25519.GetPublicKey(alicePublic, alicePrivate);
        X25519.GetPublicKey(bobPublic, bobPrivate);

        Assert.Equal(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            Convert.ToHexString(alicePublic).ToLowerInvariant());
        Assert.Equal(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            Convert.ToHexString(bobPublic).ToLowerInvariant());

        byte[] fromAlice = new byte[32];
        byte[] fromBob = new byte[32];
        X25519.Agree(fromAlice, alicePrivate, bobPublic);
        X25519.Agree(fromBob, bobPrivate, alicePublic);

        Assert.Equal(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            Convert.ToHexString(fromAlice).ToLowerInvariant());
        Assert.Equal(fromAlice, fromBob);
    }

    /// <summary>
    /// The keypair below came out of <c>xray x25519</c>. Deriving the same public key from the
    /// same private key is a direct cross-check against Go's curve25519.
    /// </summary>
    [Fact]
    public void XrayGeneratedKeypair_DerivesTheSamePublicKey()
    {
        byte[] privateKey = Base64Url(Integration.LocalRealityServer.PrivateKey);
        byte[] expected = Base64Url(Integration.LocalRealityServer.PublicKey);

        byte[] actual = new byte[32];
        X25519.GetPublicKey(actual, privateKey);

        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(actual));
    }

    [Fact]
    public void GeneratedKeyPairs_Agree()
    {
        byte[] privateA = new byte[32], publicA = new byte[32];
        byte[] privateB = new byte[32], publicB = new byte[32];
        X25519.GenerateKeyPair(privateA, publicA);
        X25519.GenerateKeyPair(privateB, publicB);

        byte[] sharedA = new byte[32], sharedB = new byte[32];
        X25519.Agree(sharedA, privateA, publicB);
        X25519.Agree(sharedB, privateB, publicA);

        Assert.Equal(sharedA, sharedB);
    }

    /// <summary>
    /// RFC 7748 §6.1 requires rejecting an all-zero result: it means the peer sent a low-order
    /// point, and the "shared" secret would be one the attacker chose.
    /// </summary>
    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    public void LowOrderPoint_IsRejected(string peerPublicKey)
    {
        byte[] privateKey = new byte[32];
        byte[] publicKey = new byte[32];
        X25519.GenerateKeyPair(privateKey, publicKey);

        byte[] shared = new byte[32];
        Assert.Throws<CryptographicException>(() => X25519.Agree(shared, privateKey, Hex(peerPublicKey)));
    }

    /// <summary>2^255 - 19, the field the limbs represent residues in.</summary>
    private static readonly System.Numerics.BigInteger Prime =
        (System.Numerics.BigInteger.One << 255) - 19;

    private static System.Numerics.BigInteger ToInteger(ReadOnlySpan<ulong> limbs)
    {
        System.Numerics.BigInteger value = 0;
        for (int i = limbs.Length - 1; i >= 0; i--)
            value = (value << 51) + limbs[i];

        return value % Prime;
    }

    /// <summary>
    /// Field multiplication against arbitrary-precision arithmetic, on limb patterns chosen to
    /// stress the carry chain.
    /// </summary>
    /// <remarks>
    /// The scalar-multiplication vectors above exercise the field ops only through whatever limb
    /// values the ladder happens to produce. A dropped carry mask is wrong by exactly one limb
    /// weight and fires for a vanishing fraction of inputs, so it can hide behind every RFC
    /// vector and every random handshake while still breaking one connection in a billion. These
    /// compare the arithmetic directly, with the maximum limb values deliberately included.
    /// </remarks>
    /// <summary>
    /// Limb patterns that sit on the carry boundaries, plus a fixed pseudo-random spread.
    /// </summary>
    /// <remarks>
    /// The upper bound is 2^52, not 2^51: the ladder adds field elements without carrying, so the
    /// field operations really are handed limbs above the mask, and an implementation that only
    /// survives canonical inputs would pass a narrower set of cases and still fail in the ladder.
    /// </remarks>
    private static List<ulong[]> CarryStressCases()
    {
        const ulong mask51 = (1UL << 51) - 1;

        ulong[][] adversarial =
        [
            [mask51, mask51, mask51, mask51, mask51],
            [mask51, 0, 0, 0, 0],
            [0, 0, 0, 0, mask51],
            [1, 0, 0, 0, 0],
            [(1UL << 52) - 1, (1UL << 52) - 1, (1UL << 52) - 1, (1UL << 52) - 1, (1UL << 52) - 1],
            [mask51 - 1, 1, mask51, 2, mask51]
        ];

        var random = new Random(20260820);
        var cases = new List<ulong[]>(adversarial);
        for (int i = 0; i < 200; i++)
        {
            cases.Add(
            [
                (ulong)random.NextInt64(0, 1L << 52),
                (ulong)random.NextInt64(0, 1L << 52),
                (ulong)random.NextInt64(0, 1L << 52),
                (ulong)random.NextInt64(0, 1L << 52),
                (ulong)random.NextInt64(0, 1L << 52)
            ]);
        }

        return cases;
    }

    [Fact]
    public void Multiply_MatchesArbitraryPrecision()
    {
        List<ulong[]> cases = CarryStressCases();
        ulong[] result = new ulong[5];

        foreach (ulong[] left in cases)
        {
            foreach (ulong[] right in cases)
            {
                X25519.MultiplyForTests(result, left, right);

                Assert.Equal(
                    ToInteger(left) * ToInteger(right) % Prime,
                    ToInteger(result));
            }

            // 121665 is the only scalar the ladder ever passes to MulSmall.
            X25519.MulSmall(result, left, 121665);

            Assert.Equal(
                ToInteger(left) * 121665 % Prime,
                ToInteger(result));
        }
    }

    /// <summary>
    /// Squaring against both arbitrary-precision arithmetic and the general multiply.
    /// </summary>
    /// <remarks>
    /// <c>Sqr</c> exists only as a faster <c>Mul(r, v, v)</c>: it folds the pairs of equal cross
    /// products into single doubled ones, which is where a squaring routine goes wrong — a
    /// doubling missed on one term is a result that is wrong by a limb and right everywhere the
    /// term happens to be zero. Checking it against both references pins the shortcut to the
    /// thing it is a shortcut for.
    /// </remarks>
    [Fact]
    public void Square_MatchesMultiplyAndArbitraryPrecision()
    {
        List<ulong[]> cases = CarryStressCases();
        ulong[] squared = new ulong[5];
        ulong[] multiplied = new ulong[5];

        foreach (ulong[] value in cases)
        {
            X25519.Sqr(squared, value);
            X25519.MultiplyForTests(multiplied, value, value);

            Assert.Equal(ToInteger(value) * ToInteger(value) % Prime, ToInteger(squared));
            Assert.Equal(ToInteger(multiplied), ToInteger(squared));
        }
    }

    [Fact]
    public void Clamp_MatchesRfc7748()
    {
        byte[] scalar = new byte[32];
        Array.Fill(scalar, (byte)0xFF);
        X25519.Clamp(scalar);

        Assert.Equal(0xF8, scalar[0]);
        Assert.Equal(0x7F, scalar[31]);
    }
}
