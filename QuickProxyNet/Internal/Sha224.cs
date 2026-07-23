using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace QuickProxyNet;

/// <summary>
/// Self-contained SHA-224 (FIPS 180-4) over a single contiguous input. The BCL has no
/// SHA-224, but the Trojan protocol authenticates with <c>hex(SHA224(password))</c>.
/// SHA-224 is SHA-256 with different initial hash values and the digest truncated to
/// the first 28 bytes. Allocation-free: state, schedule and padding are stack-allocated.
/// </summary>
/// <remarks>
/// .NET exposes no x86 SHA-NI intrinsics (dotnet/runtime#256 is unimplemented), and the
/// dedicated ARM64 <c>Sha256</c> intrinsics cannot be exercised on x64 CI. When
/// <see cref="Vector128"/> is hardware accelerated (SSE2 / AdvSimd), the message
/// schedule is expanded four words at a time; the compression rounds are inherently
/// serial and stay scalar. A pure scalar path always exists and is used on any CPU
/// without acceleration.
/// </remarks>
internal static class Sha224
{
    /// <summary>Digest size in bytes (224 bits).</summary>
    public const int HashSize = 28;

    /// <summary>Digest size in lowercase-hex ASCII bytes.</summary>
    public const int HexSize = HashSize * 2;

    private const int BlockSize = 64;

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
    /// Computes SHA224(<paramref name="data"/>) and writes the 28-byte digest into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is shorter than 28 bytes.
    /// </exception>
    public static void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, Vector128.IsHardwareAccelerated);

    /// <summary>
    /// Scalar-only variant of <see cref="ComputeHash"/>. Exists so tests can verify the
    /// fallback path on hardware where the vector path would normally be selected, and
    /// so benchmarks can compare the two.
    /// </summary>
    internal static void ComputeHashScalar(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, vectorize: false);

    /// <summary>
    /// Computes SHA224(<paramref name="data"/>) and writes the digest as exactly 56
    /// lowercase-hex ASCII bytes into <paramref name="destinationAscii"/>. Used by the
    /// Trojan request builder to emit the auth prefix directly into a wire buffer.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="destinationAscii"/> is shorter than 56 bytes.
    /// </exception>
    public static void WriteHexLower(ReadOnlySpan<byte> data, Span<byte> destinationAscii)
    {
        if (destinationAscii.Length < HexSize)
            throw new ArgumentException(
                $"Destination must be at least {HexSize} bytes.", nameof(destinationAscii));

        Span<byte> digest = stackalloc byte[HashSize];
        ComputeHash(data, digest);

        for (int i = 0; i < HashSize; i++)
        {
            destinationAscii[2 * i] = HexDigit(digest[i] >> 4);
            destinationAscii[2 * i + 1] = HexDigit(digest[i] & 0xF);
        }
    }

    private static byte HexDigit(int nibble)
        => (byte)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));

    private static void ComputeHashCore(ReadOnlySpan<byte> data, Span<byte> destination, bool vectorize)
    {
        if (destination.Length < HashSize)
            throw new ArgumentException(
                $"Destination must be at least {HashSize} bytes.", nameof(destination));

        // SHA-224 initial hash values (second 32 bits of the fractional parts of the
        // square roots of the 9th..16th primes).
        Span<uint> h =
        [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];

        Span<uint> w = stackalloc uint[64];

        // Full 64-byte blocks straight from the input.
        ReadOnlySpan<byte> remaining = data;
        while (remaining.Length >= BlockSize)
        {
            ProcessBlock(remaining, h, w, vectorize);
            remaining = remaining.Slice(BlockSize);
        }

        // Final block(s): tail + 0x80 + zero pad + 64-bit big-endian bit length. Fits in
        // one block when tail <= 55 bytes, otherwise spills into a second block.
        Span<byte> pad = stackalloc byte[2 * BlockSize];
        pad.Clear();
        remaining.CopyTo(pad);
        pad[remaining.Length] = 0x80;

        int padded = remaining.Length + 1 + 8 <= BlockSize ? BlockSize : 2 * BlockSize;
        BinaryPrimitives.WriteUInt64BigEndian(pad.Slice(padded - 8), (ulong)data.Length * 8);

        ProcessBlock(pad, h, w, vectorize);
        if (padded == 2 * BlockSize)
            ProcessBlock(pad.Slice(BlockSize), h, w, vectorize);

        // SHA-224 keeps only the first seven state words.
        for (int i = 0; i < HashSize / 4; i++)
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(i * 4), h[i]);
    }

    private static void ProcessBlock(ReadOnlySpan<byte> block, Span<uint> h, Span<uint> w, bool vectorize)
    {
        for (int i = 0; i < 16; i++)
            w[i] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i * 4));

        if (vectorize && Vector128.IsHardwareAccelerated)
            ExpandScheduleVector128(w);
        else
            ExpandScheduleScalar(w);

        uint a = h[0], b = h[1], c = h[2], d = h[3];
        uint e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++)
        {
            uint s1 = uint.RotateRight(e, 6) ^ uint.RotateRight(e, 11) ^ uint.RotateRight(e, 25);
            uint ch = (e & f) ^ (~e & g);
            uint t1 = hh + s1 + ch + K[i] + w[i];
            uint s0 = uint.RotateRight(a, 2) ^ uint.RotateRight(a, 13) ^ uint.RotateRight(a, 22);
            uint maj = (a & b) ^ (a & c) ^ (b & c);
            uint t2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    private static void ExpandScheduleScalar(Span<uint> w)
    {
        for (int i = 16; i < 64; i++)
        {
            uint s0 = uint.RotateRight(w[i - 15], 7) ^ uint.RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
            w[i] = w[i - 16] + s0 + w[i - 7] + Sigma1(w[i - 2]);
        }
    }

    /// <summary>
    /// Expands w[16..63] four words per iteration using portable <see cref="Vector128"/>
    /// operations (SSE2 on x64, AdvSimd on arm64). The sigma-0 term and the three-way
    /// add are vectorized; sigma-1 stays scalar because w[i+2] and w[i+3] depend on the
    /// just-computed w[i] and w[i+1].
    /// </summary>
    private static void ExpandScheduleVector128(Span<uint> w)
    {
        for (int i = 16; i < 64; i += 4)
        {
            var wm15 = Vector128.Create(w.Slice(i - 15, 4));
            var s0 = RotateRight(wm15, 7) ^ RotateRight(wm15, 18) ^ (wm15 >>> 3);
            var partial = Vector128.Create(w.Slice(i - 16, 4)) + s0
                          + Vector128.Create(w.Slice(i - 7, 4));

            uint w0 = partial.GetElement(0) + Sigma1(w[i - 2]);
            uint w1 = partial.GetElement(1) + Sigma1(w[i - 1]);
            w[i] = w0;
            w[i + 1] = w1;
            w[i + 2] = partial.GetElement(2) + Sigma1(w0);
            w[i + 3] = partial.GetElement(3) + Sigma1(w1);
        }
    }

    private static Vector128<uint> RotateRight(Vector128<uint> v, int n)
        => (v >>> n) | (v << (32 - n));

    private static uint Sigma1(uint x)
        => uint.RotateRight(x, 17) ^ uint.RotateRight(x, 19) ^ (x >> 10);
}
