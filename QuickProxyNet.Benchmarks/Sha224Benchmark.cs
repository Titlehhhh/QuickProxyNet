using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Scalar vs Vector128-schedule SHA-224 on the two shapes that matter: a password-sized
/// input (the actual Trojan use case — hashed once per connection) and a 64 KB bulk
/// input where per-block wins would compound. BCL SHA-256 (OS crypto, SHA-NI capable)
/// is included as a hardware-acceleration reference point.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class Sha224Benchmark
{
    private class Config : ManualConfig
    {
        public Config() => AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private readonly byte[] _password = "correct-horse-battery-staple"u8.ToArray(); // 28 bytes
    private readonly byte[] _large = new byte[64 * 1024];
    private readonly byte[] _digest = new byte[32];

    public Sha224Benchmark() => new Random(42).NextBytes(_large);

    // === Password-sized input (~28 bytes) — the real Trojan call shape ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Password")]
    public byte Password_Scalar()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHashScalar(_password, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Password")]
    public byte Password_Vector128Schedule()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(_password, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Password")]
    public byte Password_BclSha256_Reference()
    {
        SHA256.HashData(_password, _digest);
        return _digest[0];
    }

    // === 64 KB bulk input — where SIMD/hardware SHA is supposed to pay off ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_Scalar()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHashScalar(_large, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_Vector128Schedule()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(_large, digest);
        return digest[0];
    }

    [Benchmark]
    [BenchmarkCategory("Bulk64K")]
    public byte Bulk_BclSha256_Reference()
    {
        SHA256.HashData(_large, _digest);
        return _digest[0];
    }
}
