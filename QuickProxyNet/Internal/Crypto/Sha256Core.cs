using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace QuickProxyNet;

/// <summary>
/// The shared FIPS 180-4 SHA-2/32 engine behind <see cref="Sha224"/> and <see cref="Sha256"/>.
/// SHA-224 and SHA-256 differ only in their initial hash values and in how much of the final
/// state is emitted, so the block compression, the message schedule and the padding rules live
/// here exactly once.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the BCL hash types this exposes the <em>state</em>: a caller can absorb some blocks,
/// keep the eight-word midstate, and later resume from a copy of it, which no platform hash
/// API allows. Nothing in the library needs that today — the one candidate, a VMessAEAD KDF
/// built on precomputed HMAC ipad/opad midstates, was measured and lost to the platform HMAC
/// (see the remarks on <c>VmessKdf</c>). The surface is kept, and tested against the BCL,
/// because it is what lets <c>MidstateVmessKdf</c> in the benchmark project reproduce that
/// comparison on other hardware.
/// </para>
/// <para>
/// .NET exposes no x86 SHA-NI intrinsics (dotnet/runtime#256 is unimplemented), and the
/// dedicated ARM64 <c>Sha256</c> intrinsics cannot be exercised on x64 CI. When
/// <see cref="Vector128"/> is hardware accelerated (SSE2 / AdvSimd) the message schedule is
/// expanded four words at a time; the compression rounds are inherently serial and stay
/// scalar, but they are unrolled eight at a time so the eight-way state rotation is
/// expressed by renaming registers instead of by moving them. A pure scalar path always
/// exists and is used on any CPU without acceleration.
/// </para>
/// </remarks>
internal static class Sha256Core
{
    /// <summary>Compression block size in bytes.</summary>
    internal const int BlockSize = 64;

    /// <summary>Number of 32-bit words in the chaining state.</summary>
    internal const int StateWords = 8;

    /// <summary>Full (untruncated) digest size in bytes.</summary>
    internal const int DigestSize = 32;

    /// <summary>Number of 32-bit words in one expanded message schedule.</summary>
    internal const int ScheduleWords = 64;

    /// <summary>SHA-256 initial hash values (fractional parts of the square roots of the first eight primes).</summary>
    internal static ReadOnlySpan<uint> Sha256Iv =>
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    /// <summary>SHA-224 initial hash values (second 32 bits of the square roots of the 9th..16th primes).</summary>
    internal static ReadOnlySpan<uint> Sha224Iv =>
    [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];

    // SHA-256 round constants (fractional parts of cube roots of the first 64 primes).
    private static ReadOnlySpan<uint> K =>
    [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    /// <summary>
    /// One-shot hash over a single contiguous input.
    /// </summary>
    /// <param name="iv">Initial hash values: <see cref="Sha256Iv"/> or <see cref="Sha224Iv"/>.</param>
    /// <param name="data">The complete message.</param>
    /// <param name="destination">Receives <paramref name="outputBytes"/> bytes of digest.</param>
    /// <param name="outputBytes">Digest bytes to emit; must be a multiple of four and at most 32.</param>
    /// <param name="vectorize">Whether the <see cref="Vector128"/> schedule path may be used.</param>
    internal static void ComputeHash(
        ReadOnlySpan<uint> iv, ReadOnlySpan<byte> data, Span<byte> destination, int outputBytes, bool vectorize)
    {
        Span<uint> state = stackalloc uint[StateWords];
        iv.CopyTo(state);

        Span<uint> schedule = stackalloc uint[ScheduleWords];
        Finish(state, data, (ulong)data.Length, schedule, vectorize);
        WriteDigest(state, destination, outputBytes);
    }

    /// <summary>
    /// Absorbs <paramref name="blocks"/> into <paramref name="state"/>. The length must be a
    /// whole multiple of <see cref="BlockSize"/>; any remainder is silently ignored, so this
    /// is only for the "complete blocks" part of a message.
    /// </summary>
    internal static void Absorb(Span<uint> state, ReadOnlySpan<byte> blocks, Span<uint> schedule, bool vectorize)
    {
        while (blocks.Length >= BlockSize)
        {
            ProcessBlock(blocks, state, schedule, vectorize);
            blocks = blocks.Slice(BlockSize);
        }
    }

    /// <summary>
    /// Absorbs <paramref name="tail"/> (any length) and then the FIPS 180-4 padding for a
    /// message of <paramref name="totalBytes"/> bytes in total — which includes everything
    /// already folded into <paramref name="state"/> before this call. After this the state
    /// holds the final chaining value.
    /// </summary>
    internal static void Finish(
        Span<uint> state, ReadOnlySpan<byte> tail, ulong totalBytes, Span<uint> schedule, bool vectorize)
    {
        while (tail.Length >= BlockSize)
        {
            ProcessBlock(tail, state, schedule, vectorize);
            tail = tail.Slice(BlockSize);
        }

        // Final block(s): tail + 0x80 + zero pad + 64-bit big-endian bit length. Fits in one
        // block when the tail is <= 55 bytes, otherwise spills into a second block. Only the
        // bytes after the tail are cleared — clearing all 128 doubled the memset on the KDF's
        // hottest call shape, where the tail is a 32-byte digest.
        int padded = tail.Length + 1 + 8 <= BlockSize ? BlockSize : 2 * BlockSize;

        Span<byte> pad = stackalloc byte[2 * BlockSize];
        tail.CopyTo(pad);
        pad.Slice(tail.Length, padded - tail.Length).Clear();
        pad[tail.Length] = 0x80;

        BinaryPrimitives.WriteUInt64BigEndian(pad.Slice(padded - 8), totalBytes * 8);

        ProcessBlock(pad, state, schedule, vectorize);
        if (padded == 2 * BlockSize)
            ProcessBlock(pad.Slice(BlockSize), state, schedule, vectorize);
    }

    /// <summary>
    /// Serializes the first <paramref name="outputBytes"/> bytes of the state big-endian.
    /// SHA-224 keeps seven words, SHA-256 all eight.
    /// </summary>
    internal static void WriteDigest(ReadOnlySpan<uint> state, Span<byte> destination, int outputBytes)
    {
        for (int i = 0; i < outputBytes / 4; i++)
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(i * 4), state[i]);
    }

    private static void ProcessBlock(ReadOnlySpan<byte> block, Span<uint> state, Span<uint> w, bool vectorize)
    {
        for (int i = 0; i < 16; i++)
            w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4));

        if (vectorize && Vector128.IsHardwareAccelerated)
            ExpandScheduleVector128(w);
        else
            ExpandScheduleScalar(w);

        uint a = state[0], b = state[1], c = state[2], d = state[3];
        uint e = state[4], f = state[5], g = state[6], h = state[7];

        // Folding K[i] into w[i] in a separate pass before the rounds was tried and did not
        // pay: it left the vectorized path unchanged and made the scalar path measurably
        // worse, so the constant load stays inside the round.
        ReadOnlySpan<uint> constants = K;
        ref uint kp = ref MemoryMarshal.GetReference(constants);
        ref uint wp = ref MemoryMarshal.GetReference(w);

        // Eight rounds per iteration. A SHA-256 round shifts the whole state by one slot;
        // doing eight at a time lets the shift be expressed by which variable each round
        // reads, so none of the 8 x 64 register moves of the naive loop are emitted. After
        // the eighth round the names line up with the state again.
        for (int i = 0; i < 64; i += 8)
        {
            uint t1, t2;

            t1 = h + Sum1(e) + Ch(e, f, g) + Unsafe.Add(ref kp, i) + Unsafe.Add(ref wp, i);
            t2 = Sum0(a) + Maj(a, b, c);
            d += t1;
            h = t1 + t2;

            t1 = g + Sum1(d) + Ch(d, e, f) + Unsafe.Add(ref kp, i + 1) + Unsafe.Add(ref wp, i + 1);
            t2 = Sum0(h) + Maj(h, a, b);
            c += t1;
            g = t1 + t2;

            t1 = f + Sum1(c) + Ch(c, d, e) + Unsafe.Add(ref kp, i + 2) + Unsafe.Add(ref wp, i + 2);
            t2 = Sum0(g) + Maj(g, h, a);
            b += t1;
            f = t1 + t2;

            t1 = e + Sum1(b) + Ch(b, c, d) + Unsafe.Add(ref kp, i + 3) + Unsafe.Add(ref wp, i + 3);
            t2 = Sum0(f) + Maj(f, g, h);
            a += t1;
            e = t1 + t2;

            t1 = d + Sum1(a) + Ch(a, b, c) + Unsafe.Add(ref kp, i + 4) + Unsafe.Add(ref wp, i + 4);
            t2 = Sum0(e) + Maj(e, f, g);
            h += t1;
            d = t1 + t2;

            t1 = c + Sum1(h) + Ch(h, a, b) + Unsafe.Add(ref kp, i + 5) + Unsafe.Add(ref wp, i + 5);
            t2 = Sum0(d) + Maj(d, e, f);
            g += t1;
            c = t1 + t2;

            t1 = b + Sum1(g) + Ch(g, h, a) + Unsafe.Add(ref kp, i + 6) + Unsafe.Add(ref wp, i + 6);
            t2 = Sum0(c) + Maj(c, d, e);
            f += t1;
            b = t1 + t2;

            t1 = a + Sum1(f) + Ch(f, g, h) + Unsafe.Add(ref kp, i + 7) + Unsafe.Add(ref wp, i + 7);
            t2 = Sum0(b) + Maj(b, c, d);
            e += t1;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    private static void ExpandScheduleScalar(Span<uint> w)
    {
        ref uint p = ref MemoryMarshal.GetReference(w);
        for (int i = 16; i < 64; i++)
        {
            Unsafe.Add(ref p, i) =
                Unsafe.Add(ref p, i - 16)
                + Sigma0(Unsafe.Add(ref p, i - 15))
                + Unsafe.Add(ref p, i - 7)
                + Sigma1(Unsafe.Add(ref p, i - 2));
        }
    }

    /// <summary>
    /// Expands w[16..63] four words per iteration using portable <see cref="Vector128"/>
    /// operations (SSE2 on x64, AdvSimd on arm64). The sigma-0 term and the three-way add are
    /// vectorized; sigma-1 stays scalar because w[i+2] and w[i+3] depend on the just-computed
    /// w[i] and w[i+1].
    /// </summary>
    private static void ExpandScheduleVector128(Span<uint> w)
    {
        ref uint p = ref MemoryMarshal.GetReference(w);
        for (int i = 16; i < 64; i += 4)
        {
            var wm15 = Vector128.LoadUnsafe(ref p, (nuint)(i - 15));
            var s0 = RotateRight(wm15, 7) ^ RotateRight(wm15, 18) ^ (wm15 >>> 3);
            var partial = Vector128.LoadUnsafe(ref p, (nuint)(i - 16)) + s0
                          + Vector128.LoadUnsafe(ref p, (nuint)(i - 7));

            uint w0 = partial.GetElement(0) + Sigma1(Unsafe.Add(ref p, i - 2));
            uint w1 = partial.GetElement(1) + Sigma1(Unsafe.Add(ref p, i - 1));
            Unsafe.Add(ref p, i) = w0;
            Unsafe.Add(ref p, i + 1) = w1;
            Unsafe.Add(ref p, i + 2) = partial.GetElement(2) + Sigma1(w0);
            Unsafe.Add(ref p, i + 3) = partial.GetElement(3) + Sigma1(w1);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> RotateRight(Vector128<uint> v, int n)
        => (v >>> n) | (v << (32 - n));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sum0(uint x)
        => uint.RotateRight(x, 2) ^ uint.RotateRight(x, 13) ^ uint.RotateRight(x, 22);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sum1(uint x)
        => uint.RotateRight(x, 6) ^ uint.RotateRight(x, 11) ^ uint.RotateRight(x, 25);

    // Ch(x,y,z) = (x & y) ^ (~x & z), rewritten to three operations.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Ch(uint x, uint y, uint z) => z ^ (x & (y ^ z));

    // Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z), rewritten to four operations.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Maj(uint x, uint y, uint z) => (x & y) | (z & (x ^ y));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sigma0(uint x)
        => uint.RotateRight(x, 7) ^ uint.RotateRight(x, 18) ^ (x >> 3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Sigma1(uint x)
        => uint.RotateRight(x, 17) ^ uint.RotateRight(x, 19) ^ (x >> 10);
}
