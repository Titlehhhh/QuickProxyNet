using System;
using System.IO;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// The VMess steady-state hot path: sealing and opening body chunks with
/// <see cref="VmessStream"/>. The header runs once per connection; this path runs for
/// every data chunk for the life of the connection, so it is the number that matters
/// for throughput.
/// </summary>
/// <remarks>
/// <c>Seal_*</c> writes to <see cref="Stream.Null"/> and isolates the encrypt + frame
/// cost. <c>RoundTrip_*</c> seals into a recycled <see cref="MemoryStream"/> and opens
/// the chunk back out, so (RoundTrip − Seal) approximates the open cost. Payloads are
/// 64 B (small interactive write) and 8174 B (the largest single-chunk plaintext this
/// implementation emits, i.e. one full 8 KB send buffer).
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class VmessStreamBenchmark
{
    private class Config : ManualConfig
    {
        public Config() => AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const int SmallSize = 64;
    private const int LargeSize = VmessStream.MaxSendPlaintextSize; // 8174

    private static readonly byte[] ClientKey = MakePattern(0xC1, 16);
    private static readonly byte[] ClientIv = MakePattern(0xC2, 16);
    private static readonly byte[] ServerKey = MakePattern(0x51, 16);
    private static readonly byte[] ServerIv = MakePattern(0x52, 16);

    private VmessStream _sealer = null!;
    private VmessStream _loopWriter = null!;
    private VmessStream _loopReader = null!;
    private MemoryStream _wire = null!;

    private readonly byte[] _small = MakePattern(0xAB, SmallSize);
    private readonly byte[] _large = MakePattern(0xCD, LargeSize);
    private readonly byte[] _readBuffer = new byte[VmessStream.SendBufferSize];

    private static byte[] MakePattern(byte seed, int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)(seed + i * 31);
        return data;
    }

    [GlobalSetup]
    public void Setup()
    {
        _sealer = new VmessStream(
            Stream.Null, ClientKey, ClientIv, ServerKey, ServerIv,
            VmessSecurity.Aes128Gcm, leaveInnerOpen: true);

        _wire = new MemoryStream(64 * 1024);
        _loopWriter = new VmessStream(
            _wire, ClientKey, ClientIv, ServerKey, ServerIv,
            VmessSecurity.Aes128Gcm, leaveInnerOpen: true);
        // The reader's read direction mirrors the writer's write direction.
        _loopReader = new VmessStream(
            _wire, ServerKey, ServerIv, ClientKey, ClientIv,
            VmessSecurity.Aes128Gcm, leaveInnerOpen: true);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sealer.Dispose();
        _loopWriter.Dispose();
        _loopReader.Dispose();
        _wire.Dispose();
    }

    // ============================ seal only ============================

    [Benchmark]
    [BenchmarkCategory("Seal")]
    public ValueTask Seal_64B() => _sealer.WriteAsync(_small.AsMemory());

    [Benchmark]
    [BenchmarkCategory("Seal")]
    public ValueTask Seal_8K() => _sealer.WriteAsync(_large.AsMemory());

    // ======================== seal + open loopback ========================

    [Benchmark]
    [BenchmarkCategory("RoundTrip")]
    public Task<int> RoundTrip_64B() => RoundTrip(_small);

    [Benchmark]
    [BenchmarkCategory("RoundTrip")]
    public Task<int> RoundTrip_8K() => RoundTrip(_large);

    private async Task<int> RoundTrip(byte[] payload)
    {
        _wire.Position = 0;
        _wire.SetLength(0);
        await _loopWriter.WriteAsync(payload.AsMemory());

        _wire.Position = 0;
        int total = 0;
        while (total < payload.Length)
        {
            int read = await _loopReader.ReadAsync(_readBuffer.AsMemory());
            if (read == 0)
                throw new InvalidOperationException("Unexpected end of stream.");
            total += read;
        }

        return total;
    }
}
