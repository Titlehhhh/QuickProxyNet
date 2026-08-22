using System.Security.Cryptography;

namespace QuickProxyNet.Tests;

/// <summary>
/// Covers the SHA-2/32 core shared by <see cref="Sha224"/> and <see cref="Sha256"/>, including
/// the midstate resume surface that <c>MidstateVmessKdf</c> in the benchmark project builds on.
/// </summary>
/// <remarks>
/// The BCL is the independent oracle here: <see cref="SHA256"/> and <see cref="HMACSHA256"/>
/// come from the OS crypto stack, so agreeing with them across a full length sweep pins both
/// the shared compression function and the resume logic. FIPS 180-4 vectors are asserted
/// separately so a hypothetical BCL change cannot make a wrong implementation look right.
/// </remarks>
public class Sha256CoreTest
{
    private static byte[] Pattern(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)(i * 37 + 11);
        return data;
    }

    // === SHA-256: FIPS 180-4 vectors ===

    [Theory]
    [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
    public void ComputeHash_MatchesNistVector(string input, string expectedHex)
    {
        byte[] data = System.Text.Encoding.ASCII.GetBytes(input);
        byte[] expected = Convert.FromHexString(expectedHex);

        Span<byte> digest = stackalloc byte[Sha256.HashSize];
        Sha256.ComputeHash(data, digest);
        Assert.Equal(expected, digest.ToArray());

        digest.Clear();
        Sha256.ComputeHashScalar(data, digest);
        Assert.Equal(expected, digest.ToArray());
    }

    // === SHA-256: length sweep against the BCL, both code paths ===

    [Fact]
    public void ComputeHash_AgreesWithBcl_AllLengthsToThreeBlocks()
    {
        Span<byte> viaDispatch = stackalloc byte[Sha256.HashSize];
        Span<byte> viaScalar = stackalloc byte[Sha256.HashSize];

        for (int length = 0; length <= 192; length++)
        {
            byte[] data = Pattern(length);
            byte[] expected = SHA256.HashData(data);

            Sha256.ComputeHash(data, viaDispatch);
            Sha256.ComputeHashScalar(data, viaScalar);

            Assert.Equal(expected, viaDispatch.ToArray());
            Assert.Equal(expected, viaScalar.ToArray());
        }
    }

    [Fact]
    public void ComputeHash_AgreesWithBcl_LargeInput()
    {
        byte[] data = Pattern(9_001);
        Span<byte> digest = stackalloc byte[Sha256.HashSize];
        Sha256.ComputeHash(data, digest);
        Assert.Equal(SHA256.HashData(data), digest.ToArray());
    }

    [Fact]
    public void ComputeHash_DestinationTooSmall_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> small = stackalloc byte[Sha256.HashSize - 1];
            Sha256.ComputeHash("abc"u8, small);
        });
    }

    // === Midstate resume: absorbing blocks then finishing must equal a one-shot hash ===

    [Fact]
    public void AbsorbThenFinish_EqualsOneShot_ForEveryBlockSplit()
    {
        // The whole point of exposing the state is that a caller may compress some leading
        // blocks, keep the eight-word midstate, and resume later. Every split must reproduce
        // the one-shot digest, including the total-length bookkeeping in the padding.
        byte[] data = Pattern(300);
        byte[] expected = SHA256.HashData(data);

        Span<uint> state = stackalloc uint[Sha256Core.StateWords];
        Span<uint> schedule = stackalloc uint[Sha256Core.ScheduleWords];
        Span<byte> digest = stackalloc byte[Sha256Core.DigestSize];

        for (int prefixBlocks = 0; prefixBlocks * 64 <= data.Length; prefixBlocks++)
        {
            int prefix = prefixBlocks * 64;

            Sha256Core.Sha256Iv.CopyTo(state);
            Sha256Core.Absorb(state, data.AsSpan(0, prefix), schedule, vectorize: true);
            Sha256Core.Finish(state, data.AsSpan(prefix), (ulong)data.Length, schedule, vectorize: true);
            Sha256Core.WriteDigest(state, digest, Sha256Core.DigestSize);

            Assert.Equal(expected, digest.ToArray());
        }
    }

    // === Midstate-resumed HMAC ===

    private static byte[] BclSeedHmac(byte[] message)
        => HMACSHA256.HashData("VMess AEAD KDF"u8.ToArray(), message);

    /// <summary>
    /// Builds HMAC(seed, prefix ‖ tail) the way a midstate consumer would: compress the pad
    /// block once, keep the state, resume over the prefix, then finish over the tail.
    /// </summary>
    private static byte[] ResumedSeedHmac(byte[] prefix, byte[] tail)
    {
        const int blockSize = Sha256Core.BlockSize;

        Span<uint> schedule = stackalloc uint[Sha256Core.ScheduleWords];
        Span<uint> state = stackalloc uint[Sha256Core.StateWords];
        Span<byte> pad = stackalloc byte[blockSize];
        Span<byte> innerDigest = stackalloc byte[Sha256Core.DigestSize];
        byte[] result = new byte[Sha256Core.DigestSize];

        // Inner pass: (seed ⊕ ipad) as a reusable midstate, then prefix, then tail.
        pad.Clear();
        "VMess AEAD KDF"u8.CopyTo(pad);
        for (int i = 0; i < blockSize; i++)
            pad[i] ^= 0x36;

        Sha256Core.Sha256Iv.CopyTo(state);
        Sha256Core.Absorb(state, pad, schedule, vectorize: true);
        Sha256Core.Absorb(state, prefix, schedule, vectorize: true);
        Sha256Core.Finish(
            state, tail, (ulong)(blockSize + prefix.Length + tail.Length), schedule, vectorize: true);
        Sha256Core.WriteDigest(state, innerDigest, Sha256Core.DigestSize);

        // Outer pass: (seed ⊕ opad) then the 32-byte inner digest.
        pad.Clear();
        "VMess AEAD KDF"u8.CopyTo(pad);
        for (int i = 0; i < blockSize; i++)
            pad[i] ^= 0x5C;

        Sha256Core.Sha256Iv.CopyTo(state);
        Sha256Core.Absorb(state, pad, schedule, vectorize: true);
        Sha256Core.Finish(
            state, innerDigest, (ulong)(blockSize + Sha256Core.DigestSize), schedule, vectorize: true);
        Sha256Core.WriteDigest(state, result, Sha256Core.DigestSize);

        return result;
    }

    [Fact]
    public void ResumedHmac_AgreesWithBclHmac_AllMessageLengthsToThreeBlocks()
    {
        // If the resumed state or the total-length bookkeeping were wrong by a single bit,
        // every one of these would fail.
        for (int length = 0; length <= 200; length++)
        {
            byte[] message = Pattern(length);
            Assert.Equal(BclSeedHmac(message), ResumedSeedHmac([], message));
        }
    }

    [Fact]
    public void ResumedHmac_ConstantPrefixSplit_EqualsHashOfConcatenation()
    {
        // Folding constant leading blocks into the midstate and resuming must equal hashing
        // prefix ‖ tail in one go, for every split.
        foreach (int prefixBlocks in new[] { 0, 1, 2, 3 })
        {
            byte[] prefix = Pattern(prefixBlocks * Sha256Core.BlockSize);

            for (int tailLength = 0; tailLength <= 140; tailLength += 7)
            {
                byte[] tail = Pattern(tailLength);
                byte[] concatenated = [.. prefix, .. tail];
                Assert.Equal(BclSeedHmac(concatenated), ResumedSeedHmac(prefix, tail));
            }
        }
    }

    // === The KDF built on top must still be the textbook nested construction ===

    [Fact]
    public void Kdf16_SinglePathElement_MatchesHandRolledNestedHmac()
    {
        // Reference: KDF(key, label) = HMAC_label(HMAC_seed)(key), expanded by hand with the
        // BCL as the only hash primitive. Independent of every midstate in the library.
        byte[] key = Pattern(16);
        byte[] label = "VMess Header AEAD Key_Length"u8.ToArray();

        byte[] expected = NestedHmac(label, key);

        Span<byte> actual = stackalloc byte[16];
        VmessKdf.Kdf16(key, label, actual);
        Assert.Equal(expected.AsSpan(0, 16).ToArray(), actual.ToArray());
    }

    private static byte[] NestedHmac(byte[] pathElement, byte[] message)
    {
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            byte k = i < pathElement.Length ? pathElement[i] : (byte)0;
            ipad[i] = (byte)(k ^ 0x36);
            opad[i] = (byte)(k ^ 0x5C);
        }

        byte[] inner = BclSeedHmac([.. ipad, .. message]);
        return BclSeedHmac([.. opad, .. inner]);
    }
}
