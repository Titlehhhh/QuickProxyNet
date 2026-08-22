using System;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// A/B for the SHA-2/32 compression function: the previous implementation, whose round loop
/// shifted the eight state words with explicit assignments and indexed the schedule and the
/// round constants through bounds-checked spans, against the current
/// <see cref="Sha256Core"/>, which unrolls eight rounds so the shift becomes a renaming and
/// reaches both arrays through <c>Unsafe.Add</c>.
/// </summary>
/// <remarks>
/// Interleaved in one process, for the same reason as <see cref="VmessKdfBenchmark"/>: run to
/// run, this machine moves untouched benchmarks by ~10%, so cross-run deltas of this size
/// cannot be read. The BCL is included only as a reference point for how far a managed
/// implementation is from OS crypto — it is not a baseline anything is expected to beat.
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class Sha256CompressionBenchmark
{
    private class Config : ManualConfig
    {
        public Config()
        {
            Job job = Environment.GetEnvironmentVariable("QPN_BENCH_LONG") == "1"
                ? Job.Default.WithLaunchCount(3).WithWarmupCount(5).WithIterationCount(20)
                : Job.ShortRun;

            AddJob(job.WithToolchain(InProcessNoEmitToolchain.Instance));
        }
    }

    private readonly byte[] _password = "correct-horse-battery-staple"u8.ToArray(); // 28 bytes, 1 block
    private readonly byte[] _large = new byte[64 * 1024];                            // 1024 blocks

    public Sha256CompressionBenchmark() => new Random(42).NextBytes(_large);

    [GlobalSetup]
    public void Setup()
    {
        Span<byte> mine = stackalloc byte[Sha224.HashSize];
        Span<byte> legacy = stackalloc byte[Sha224.HashSize];

        foreach (byte[] input in new[] { _password, _large })
        {
            Sha224.ComputeHash(input, mine);
            LegacySha224.ComputeHash(input, legacy);
            if (!mine.SequenceEqual(legacy))
                throw new InvalidOperationException("SHA-224 implementations disagree.");
        }
    }

    // === One block: the real Trojan call shape, where fixed overhead shows up ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("OneBlock")]
    public byte OneBlock_LegacyRoundLoop()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        LegacySha224.ComputeHash(_password, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("OneBlock")]
    public byte OneBlock_UnrolledRounds()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(_password, digest);
        return digest[0];
    }

    // === 1024 blocks: isolates the per-block compression cost from fixed overhead ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_LegacyRoundLoop()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        LegacySha224.ComputeHash(_large, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_UnrolledRounds()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(_large, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_BclSha256_Reference()
    {
        Span<byte> digest = stackalloc byte[32];
        System.Security.Cryptography.SHA256.HashData(_large, digest);
        return digest[0];
    }
}

/// <summary>
/// The superseded SHA-224, verbatim. Benchmark-only reference implementation.
/// </summary>
internal static class LegacySha224
{
    private const int HashSize = 28;
    private const int BlockSize = 64;

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

    public static void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
        => ComputeHashCore(data, destination, Vector128.IsHardwareAccelerated);

    private static void ComputeHashCore(ReadOnlySpan<byte> data, Span<byte> destination, bool vectorize)
    {
        Span<uint> h =
        [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];

        Span<uint> w = stackalloc uint[64];

        ReadOnlySpan<byte> remaining = data;
        while (remaining.Length >= BlockSize)
        {
            ProcessBlock(remaining, h, w, vectorize);
            remaining = remaining.Slice(BlockSize);
        }

        Span<byte> pad = stackalloc byte[2 * BlockSize];
        pad.Clear();
        remaining.CopyTo(pad);
        pad[remaining.Length] = 0x80;

        int padded = remaining.Length + 1 + 8 <= BlockSize ? BlockSize : 2 * BlockSize;
        BinaryPrimitives.WriteUInt64BigEndian(pad.Slice(padded - 8), (ulong)data.Length * 8);

        ProcessBlock(pad, h, w, vectorize);
        if (padded == 2 * BlockSize)
            ProcessBlock(pad.Slice(BlockSize), h, w, vectorize);

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
