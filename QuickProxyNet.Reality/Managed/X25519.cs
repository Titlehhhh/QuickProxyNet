using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet.Reality.Managed;

/// <summary>
/// X25519 scalar multiplication (RFC 7748), for the key exchange REALITY hides inside the TLS
/// <c>key_share</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists at all.</b> .NET 11 added <c>X25519DiffieHellman</c>; .NET 8, 9 and 10 have
/// no X25519 anywhere in the BCL. The library targets all four, and REALITY without X25519 is not
/// REALITY, so the older targets need an implementation. Correctness is checkable against the RFC
/// 7748 vectors and against a real Xray server, which is what the tests do.
/// </para>
/// <para>
/// <b>Representation.</b> Field elements are five 51-bit limbs in a <c>Span&lt;ulong&gt;</c>, the
/// standard radix-2^51 layout: products fit in <see cref="UInt128"/> without overflow, and the
/// reduction of 2^255 - 19 becomes a multiply by 19 on the wrapped limb.
/// </para>
/// <para>
/// <b>What this is not.</b> The Montgomery ladder below is written to run the same sequence of
/// operations regardless of the scalar — the conditional swap is arithmetic, not a branch — but
/// this is managed code on a JIT, and it makes no claim of being constant-time against a local
/// attacker measuring cache or timing. For REALITY's use, the secret is a per-connection
/// ephemeral key and the adversary is on the network, so that is the right trade. It would not be
/// for a long-lived signing key.
/// </para>
/// </remarks>
internal static class X25519
{
    /// <summary>Length in bytes of a scalar, a public key and a shared secret.</summary>
    public const int KeySize = 32;

    private const int Limbs = 5;
    private const ulong Mask51 = (1UL << 51) - 1;

    /// <summary>The canonical base point, u = 9.</summary>
    private static ReadOnlySpan<byte> BasePoint =>
    [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    /// <summary>Generates an ephemeral key pair.</summary>
    /// <param name="privateKey">Receives the clamped private scalar; 32 bytes.</param>
    /// <param name="publicKey">Receives the corresponding u-coordinate; 32 bytes.</param>
    public static void GenerateKeyPair(Span<byte> privateKey, Span<byte> publicKey)
    {
        if (privateKey.Length != KeySize || publicKey.Length != KeySize)
            throw new ArgumentException($"X25519 keys are {KeySize} bytes.");

        RandomNumberGenerator.Fill(privateKey);
        Clamp(privateKey);
        ScalarMultiply(publicKey, privateKey, BasePoint);
    }

    /// <summary>Computes the public key for an existing private scalar.</summary>
    /// <param name="publicKey">Receives the u-coordinate; 32 bytes.</param>
    /// <param name="privateKey">The private scalar; 32 bytes.</param>
    public static void GetPublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey) =>
        ScalarMultiply(publicKey, privateKey, BasePoint);

    /// <summary>
    /// Computes the shared secret for <paramref name="privateKey"/> and <paramref name="peerPublicKey"/>.
    /// </summary>
    /// <param name="sharedSecret">Receives the shared secret; 32 bytes.</param>
    /// <param name="privateKey">Our private scalar; 32 bytes.</param>
    /// <param name="peerPublicKey">The peer's u-coordinate; 32 bytes.</param>
    /// <exception cref="CryptographicException">
    /// The result is all zeroes, which means the peer supplied a low-order point. RFC 7748 §6.1
    /// requires rejecting it: continuing would derive a key an attacker already knows.
    /// </exception>
    public static void Agree(Span<byte> sharedSecret, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
    {
        ScalarMultiply(sharedSecret, privateKey, peerPublicKey);

        byte accumulated = 0;
        for (int i = 0; i < KeySize; i++)
            accumulated |= sharedSecret[i];

        if (accumulated == 0)
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw new CryptographicException(
                "X25519 produced an all-zero shared secret, which means the peer's public key was a " +
                "low-order point. RFC 7748 requires rejecting it.");
        }
    }

    /// <summary>Applies the RFC 7748 clamping to a private scalar, in place.</summary>
    public static void Clamp(Span<byte> scalar)
    {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    /// <summary>The Montgomery ladder: <paramref name="result"/> = scalar · u.</summary>
    private static void ScalarMultiply(Span<byte> result, ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u)
    {
        if (result.Length != KeySize || scalar.Length != KeySize || u.Length != KeySize)
            throw new ArgumentException($"X25519 operands are {KeySize} bytes.");

        Span<byte> clamped = stackalloc byte[KeySize];
        scalar.CopyTo(clamped);
        Clamp(clamped);

        Span<ulong> x1 = stackalloc ulong[Limbs];
        Span<ulong> x2 = stackalloc ulong[Limbs];
        Span<ulong> z2 = stackalloc ulong[Limbs];
        Span<ulong> x3 = stackalloc ulong[Limbs];
        Span<ulong> z3 = stackalloc ulong[Limbs];
        Span<ulong> a = stackalloc ulong[Limbs];
        Span<ulong> b = stackalloc ulong[Limbs];
        Span<ulong> c = stackalloc ulong[Limbs];
        Span<ulong> d = stackalloc ulong[Limbs];
        Span<ulong> e = stackalloc ulong[Limbs];

        Decode(x1, u);

        Zero(x2);
        x2[0] = 1;      // x2 = 1
        Zero(z2);       // z2 = 0
        x1.CopyTo(x3);  // x3 = u
        Zero(z3);
        z3[0] = 1;      // z3 = 1

        ulong swap = 0;

        for (int position = 254; position >= 0; position--)
        {
            ulong bit = (ulong)((clamped[position >> 3] >> (position & 7)) & 1);
            swap ^= bit;
            ConditionalSwap(x2, x3, swap);
            ConditionalSwap(z2, z3, swap);
            swap = bit;

            // The RFC 7748 §5 ladder step, verbatim.
            Sub(a, x2, z2);      // a  = x2 - z2
            Add(b, x2, z2);      // b  = x2 + z2
            Sub(c, x3, z3);      // c  = x3 - z3
            Add(d, x3, z3);      // d  = x3 + z3
            Mul(c, c, b);        // c  = (x3 - z3)(x2 + z2)
            Mul(d, d, a);        // d  = (x3 + z3)(x2 - z2)
            Add(e, c, d);
            Sub(c, c, d);
            Mul(x3, e, e);       // x3 = (c + d)^2
            Mul(z3, c, c);       // z3 = (c - d)^2
            Mul(z3, z3, x1);     // z3 *= u
            Mul(e, a, a);        // e  = BB = (x2 - z2)^2
            Mul(c, b, b);        // c  = AA = (x2 + z2)^2
            Mul(x2, e, c);       // x2 = AA·BB
            Sub(b, c, e);        // b  = E = AA - BB   (A is no longer needed)
            MulSmall(d, b, 121665);
            Add(d, d, c);        // d  = AA + a24·E  — AA, not BB: a24 = (486662 - 2)/4 only
                                 //      balances the doubling formula against AA.
            Mul(z2, b, d);       // z2 = E·(AA + a24·E)
        }

        ConditionalSwap(x2, x3, swap);
        ConditionalSwap(z2, z3, swap);

        Invert(z2, z2);
        Mul(x2, x2, z2);
        Encode(result, x2);

        CryptographicOperations.ZeroMemory(clamped);
    }

    private static void Zero(Span<ulong> fe)
    {
        for (int i = 0; i < Limbs; i++)
            fe[i] = 0;
    }

    /// <summary>Loads 32 little-endian bytes into five 51-bit limbs, masking bit 255.</summary>
    private static void Decode(Span<ulong> fe, ReadOnlySpan<byte> bytes)
    {
        ulong low = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        ulong second = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
        ulong third = BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]);
        ulong high = BinaryPrimitives.ReadUInt64LittleEndian(bytes[24..]);

        fe[0] = low & Mask51;
        fe[1] = ((low >> 51) | (second << 13)) & Mask51;
        fe[2] = ((second >> 38) | (third << 26)) & Mask51;
        fe[3] = ((third >> 25) | (high << 39)) & Mask51;
        // RFC 7748 §5: the most significant bit of the u-coordinate is ignored on decode.
        fe[4] = (high >> 12) & Mask51;
    }

    /// <summary>Fully reduces and stores a field element as 32 little-endian bytes.</summary>
    private static void Encode(Span<byte> bytes, Span<ulong> fe)
    {
        Carry(fe);
        Carry(fe);
        Carry(fe);

        // Conditionally subtract p = 2^255 - 19 so the output is the canonical representative.
        ulong q = (fe[0] + 19) >> 51;
        q = (fe[1] + q) >> 51;
        q = (fe[2] + q) >> 51;
        q = (fe[3] + q) >> 51;
        q = (fe[4] + q) >> 51;

        fe[0] += 19 * q;

        fe[1] += fe[0] >> 51; fe[0] &= Mask51;
        fe[2] += fe[1] >> 51; fe[1] &= Mask51;
        fe[3] += fe[2] >> 51; fe[2] &= Mask51;
        fe[4] += fe[3] >> 51; fe[3] &= Mask51;
        fe[4] &= Mask51;

        ulong low = fe[0] | (fe[1] << 51);
        ulong second = (fe[1] >> 13) | (fe[2] << 38);
        ulong third = (fe[2] >> 26) | (fe[3] << 25);
        ulong high = (fe[3] >> 39) | (fe[4] << 12);

        BinaryPrimitives.WriteUInt64LittleEndian(bytes, low);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], second);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[16..], third);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[24..], high);
    }

    private static void Add(Span<ulong> result, Span<ulong> left, Span<ulong> right)
    {
        for (int i = 0; i < Limbs; i++)
            result[i] = left[i] + right[i];
    }

    /// <summary>
    /// Subtraction with a 2p bias, so every limb stays non-negative without a borrow chain.
    /// </summary>
    private static void Sub(Span<ulong> result, Span<ulong> left, Span<ulong> right)
    {
        // 2p in limb form: 2*(2^51 - 19) for limb 0 and 2*(2^51 - 1) elsewhere. Adding it before
        // subtracting keeps the value congruent mod p and the limbs unsigned.
        result[0] = left[0] + 0xFFFFFFFFFFFDAUL - right[0];
        result[1] = left[1] + 0xFFFFFFFFFFFFEUL - right[1];
        result[2] = left[2] + 0xFFFFFFFFFFFFEUL - right[2];
        result[3] = left[3] + 0xFFFFFFFFFFFFEUL - right[3];
        result[4] = left[4] + 0xFFFFFFFFFFFFEUL - right[4];
        Carry(result);
    }

    private static void Mul(Span<ulong> result, Span<ulong> left, Span<ulong> right)
    {
        ulong f0 = left[0], f1 = left[1], f2 = left[2], f3 = left[3], f4 = left[4];
        ulong g0 = right[0], g1 = right[1], g2 = right[2], g3 = right[3], g4 = right[4];

        // Limbs above 4 wrap by 2^255 ≡ 19, so their contributions fold back multiplied by 19.
        ulong g1_19 = 19 * g1;
        ulong g2_19 = 19 * g2;
        ulong g3_19 = 19 * g3;
        ulong g4_19 = 19 * g4;

        UInt128 h0 = (UInt128)f0 * g0 + (UInt128)f1 * g4_19 + (UInt128)f2 * g3_19 + (UInt128)f3 * g2_19 + (UInt128)f4 * g1_19;
        UInt128 h1 = (UInt128)f0 * g1 + (UInt128)f1 * g0 + (UInt128)f2 * g4_19 + (UInt128)f3 * g3_19 + (UInt128)f4 * g2_19;
        UInt128 h2 = (UInt128)f0 * g2 + (UInt128)f1 * g1 + (UInt128)f2 * g0 + (UInt128)f3 * g4_19 + (UInt128)f4 * g3_19;
        UInt128 h3 = (UInt128)f0 * g3 + (UInt128)f1 * g2 + (UInt128)f2 * g1 + (UInt128)f3 * g0 + (UInt128)f4 * g4_19;
        UInt128 h4 = (UInt128)f0 * g4 + (UInt128)f1 * g3 + (UInt128)f2 * g2 + (UInt128)f3 * g1 + (UInt128)f4 * g0;

        ulong carry = (ulong)(h0 >> 51); ulong r0 = (ulong)h0 & Mask51;
        h1 += carry; carry = (ulong)(h1 >> 51); ulong r1 = (ulong)h1 & Mask51;
        h2 += carry; carry = (ulong)(h2 >> 51); ulong r2 = (ulong)h2 & Mask51;
        h3 += carry; carry = (ulong)(h3 >> 51); ulong r3 = (ulong)h3 & Mask51;
        h4 += carry; carry = (ulong)(h4 >> 51); ulong r4 = (ulong)h4 & Mask51;

        r0 += 19 * carry;
        r1 += r0 >> 51; r0 &= Mask51;
        r2 += r1 >> 51; r1 &= Mask51;

        result[0] = r0;
        result[1] = r1;
        result[2] = r2;
        result[3] = r3;
        result[4] = r4;
    }

    private static void MulSmall(Span<ulong> result, Span<ulong> value, ulong scalar)
    {
        UInt128 h0 = (UInt128)value[0] * scalar;
        UInt128 h1 = (UInt128)value[1] * scalar;
        UInt128 h2 = (UInt128)value[2] * scalar;
        UInt128 h3 = (UInt128)value[3] * scalar;
        UInt128 h4 = (UInt128)value[4] * scalar;

        ulong carry = (ulong)(h0 >> 51); ulong r0 = (ulong)h0 & Mask51;
        h1 += carry; carry = (ulong)(h1 >> 51); ulong r1 = (ulong)h1 & Mask51;
        h2 += carry; carry = (ulong)(h2 >> 51); ulong r2 = (ulong)h2 & Mask51;
        h3 += carry; carry = (ulong)(h3 >> 51); ulong r3 = (ulong)h3 & Mask51;
        h4 += carry; carry = (ulong)(h4 >> 51); ulong r4 = (ulong)h4 & Mask51;

        r0 += 19 * carry;
        r1 += r0 >> 51; r0 &= Mask51;

        result[0] = r0;
        result[1] = r1;
        result[2] = r2;
        result[3] = r3;
        result[4] = r4;
    }

    private static void Carry(Span<ulong> fe)
    {
        ulong carry = fe[0] >> 51; fe[0] &= Mask51;
        fe[1] += carry; carry = fe[1] >> 51; fe[1] &= Mask51;
        fe[2] += carry; carry = fe[2] >> 51; fe[2] &= Mask51;
        fe[3] += carry; carry = fe[3] >> 51; fe[3] &= Mask51;
        fe[4] += carry; carry = fe[4] >> 51; fe[4] &= Mask51;
        fe[0] += 19 * carry;
    }

    /// <summary>
    /// Swaps two field elements when <paramref name="swap"/> is 1, arithmetically.
    /// </summary>
    /// <remarks>
    /// A branch here would leak the scalar's bits through timing, which is the classic way a
    /// textbook ladder becomes a key-recovery oracle. The mask makes both cases do identical work.
    /// </remarks>
    private static void ConditionalSwap(Span<ulong> left, Span<ulong> right, ulong swap)
    {
        ulong mask = 0UL - swap;
        for (int i = 0; i < Limbs; i++)
        {
            ulong difference = mask & (left[i] ^ right[i]);
            left[i] ^= difference;
            right[i] ^= difference;
        }
    }

    /// <summary>Computes the multiplicative inverse via z^(p-2), the standard addition chain.</summary>
    private static void Invert(Span<ulong> result, Span<ulong> z)
    {
        Span<ulong> z2 = stackalloc ulong[Limbs];
        Span<ulong> z9 = stackalloc ulong[Limbs];
        Span<ulong> z11 = stackalloc ulong[Limbs];
        Span<ulong> z2_5_0 = stackalloc ulong[Limbs];
        Span<ulong> z2_10_0 = stackalloc ulong[Limbs];
        Span<ulong> z2_20_0 = stackalloc ulong[Limbs];
        Span<ulong> z2_50_0 = stackalloc ulong[Limbs];
        Span<ulong> z2_100_0 = stackalloc ulong[Limbs];
        Span<ulong> t = stackalloc ulong[Limbs];

        Mul(z2, z, z);                                  // 2
        Mul(t, z2, z2);                                 // 4
        Mul(t, t, t);                                   // 8
        Mul(z9, t, z);                                  // 9
        Mul(z11, z9, z2);                               // 11
        Mul(t, z11, z11);                               // 22
        Mul(z2_5_0, t, z9);                             // 2^5 - 2^0

        Square(t, z2_5_0, 5);
        Mul(z2_10_0, t, z2_5_0);

        Square(t, z2_10_0, 10);
        Mul(z2_20_0, t, z2_10_0);

        Square(t, z2_20_0, 20);
        Mul(t, t, z2_20_0);

        Square(t, t, 10);
        Mul(z2_50_0, t, z2_10_0);

        Square(t, z2_50_0, 50);
        Mul(z2_100_0, t, z2_50_0);

        Square(t, z2_100_0, 100);
        Mul(t, t, z2_100_0);

        Square(t, t, 50);
        Mul(t, t, z2_50_0);

        Square(t, t, 5);
        Mul(result, t, z11);
    }

    private static void Square(Span<ulong> result, Span<ulong> value, int times)
    {
        Mul(result, value, value);
        for (int i = 1; i < times; i++)
            Mul(result, result, result);
    }
}
