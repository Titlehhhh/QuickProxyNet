using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// End-to-end steady-state throughput of <see cref="RealityTlsStream"/> over an in-memory
/// transport, so what is measured is our framing and our allocations — no socket, no kernel, no
/// second process.
/// </summary>
/// <remarks>
/// <para>
/// Every operation moves exactly 1 MiB, which makes the <c>Allocated</c> column read directly as
/// <b>bytes allocated per MiB transferred</b>. That is the point of this benchmark:
/// <c>TlsRecordStream.WriteAsync</c> allocates a fresh record buffer <em>and</em> a fresh scratch
/// buffer for every record, and <c>RealityTlsStream.FillAsync</c> copies every inbound record out
/// of the record layer's buffer with <c>ToArray</c>. At 16 KiB per record that is three
/// per-record heap allocations that a pooled implementation would not make, and this is the number
/// that says whether removing them is worth the change.
/// </para>
/// <para>
/// <c>Write_1MiB</c> writes into <see cref="Stream.Null"/> and isolates the seal-and-frame cost.
/// <c>RoundTrip_1MiB</c> writes into a recycled <see cref="MemoryStream"/> and reads the same
/// megabyte back out, so (RoundTrip − Write) approximates the read path. The writer and reader
/// hold a matched pair of record protections and are never rebuilt, so their record sequence
/// numbers stay in lockstep across the whole run — which is what makes a persistent, allocation-
/// free harness possible at all.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class RealityTlsStreamBenchmark
{
    private class Config : ManualConfig
    {
        public Config() =>
            AddJob(Job.ShortRun.WithIterationCount(5).WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const int Payload = 1024 * 1024;
    private const ushort Aes128Gcm = 0x1301;

    private byte[] _data = null!;
    private byte[] _readBuffer = null!;

    private MemoryStream _wire = null!;
    private RealityTlsStream _sink = null!;
    private RealityTlsStream _writer = null!;
    private RealityTlsStream _reader = null!;

    [GlobalSetup]
    public void Setup()
    {
        TlsCipherSuite suite = TlsCipherSuite.FromId(Aes128Gcm)!;

        Span<byte> sinkSecret = stackalloc byte[suite.HashLength];
        Span<byte> pairSecret = stackalloc byte[suite.HashLength];
        RandomNumberGenerator.Fill(sinkSecret);
        RandomNumberGenerator.Fill(pairSecret);

        _data = new byte[Payload];
        RandomNumberGenerator.Fill(_data);
        _readBuffer = new byte[TlsRecordStream.MaxPlaintext];

        var sinkRecords = new TlsRecordStream(Stream.Null)
        {
            Write = new TlsRecordProtection(suite, sinkSecret)
        };
        _sink = new RealityTlsStream(Stream.Null, sinkRecords, []);

        // Room for 1 MiB of plaintext plus per-record headers and tags, so the stream never grows
        // during a measured operation.
        _wire = new MemoryStream(Payload + (128 * 1024));

        var writerRecords = new TlsRecordStream(_wire)
        {
            Write = new TlsRecordProtection(suite, pairSecret)
        };
        var readerRecords = new TlsRecordStream(_wire)
        {
            Read = new TlsRecordProtection(suite, pairSecret)
        };

        _writer = new RealityTlsStream(_wire, writerRecords, []);
        _reader = new RealityTlsStream(_wire, readerRecords, []);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sink.Dispose();
        _writer.Dispose();
        _reader.Dispose();
        _wire.Dispose();
    }

    /// <summary>Seal and frame 1 MiB — 64 full-size records — into a discarding transport.</summary>
    [Benchmark]
    [BenchmarkCategory("Write")]
    public ValueTask Write_1MiB() => _sink.WriteAsync(_data.AsMemory(), CancellationToken.None);

    /// <summary>Seal 1 MiB into memory and read the same megabyte back out.</summary>
    [Benchmark]
    [BenchmarkCategory("RoundTrip")]
    public async Task<int> RoundTrip_1MiB()
    {
        _wire.Position = 0;
        _wire.SetLength(0);

        await _writer.WriteAsync(_data.AsMemory(), CancellationToken.None);

        _wire.Position = 0;
        int total = 0;
        while (total < Payload)
        {
            int read = await _reader.ReadAsync(_readBuffer.AsMemory(), CancellationToken.None);
            if (read == 0)
                throw new InvalidOperationException("The in-memory transport ended early.");

            total += read;
        }

        return total;
    }
}
