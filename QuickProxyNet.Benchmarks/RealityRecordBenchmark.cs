using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// The managed REALITY hot path: <see cref="TlsRecordProtection"/> sealing and opening one TLS 1.3
/// record. Everything else in the client runs once per connection; this runs for every record for
/// the life of the tunnel, so it is the number that sets the ceiling on throughput.
/// </summary>
/// <remarks>
/// <para>
/// Sizes are 64 B (an interactive write), 1 KiB, 8 KiB and 16 384 B — the last being
/// <see cref="TlsRecordStream.MaxPlaintext"/>, the size every bulk transfer actually uses.
/// </para>
/// <para>
/// <b>Why <c>Unprotect</c> is measured by subtraction.</b> A TLS record's nonce is the static IV
/// xored with a sequence number that advances on every call and cannot be rewound, so a
/// pre-computed ciphertext decrypts exactly once — there is no way to call <c>Unprotect</c> in a
/// loop against a fixed input without the tag check failing. <c>RoundTrip</c> therefore drives a
/// matched writer/reader pair that stay in lockstep for the whole run, and the open cost is
/// (RoundTrip − Protect). This is the same construction <see cref="VmessStreamBenchmark"/> uses,
/// for the same reason.
/// </para>
/// <para>
/// The <c>MB/s</c> column is plaintext bytes per second; for <c>RoundTrip</c> the payload is
/// processed twice, so that column understates the AEAD's raw rate by design — it is the rate the
/// tunnel sustains, which is what a caller cares about.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class RealityRecordBenchmark
{
    private class Config : ManualConfig
    {
        public Config()
        {
            AddJob(Job.ShortRun.WithIterationCount(5).WithToolchain(InProcessNoEmitToolchain.Instance));
            AddColumn(new ThroughputColumn());
        }
    }

    /// <summary>Plaintext bytes per second, derived from the <c>Size</c> parameter and the mean.</summary>
    private sealed class ThroughputColumn : IColumn
    {
        public string Id => nameof(ThroughputColumn);
        public string ColumnName => "MB/s";
        public bool AlwaysShow => true;
        public ColumnCategory Category => ColumnCategory.Custom;
        public int PriorityInCategory => 0;
        public bool IsNumeric => true;
        public UnitType UnitType => UnitType.Dimensionless;

        public string Legend =>
            "Plaintext megabytes (10^6 B) per second: Size / Mean. RoundTrip moves the payload twice.";

        public bool IsAvailable(Summary summary) => true;

        public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;

        public string GetValue(Summary summary, BenchmarkCase benchmarkCase)
        {
            double? mean = summary[benchmarkCase]?.ResultStatistics?.Mean;
            object size = benchmarkCase.Parameters[nameof(Size)];

            if (mean is not > 0 || size is not int bytes)
                return "?";

            // Mean is nanoseconds, so bytes / (mean * 1e-9) / 1e6 == bytes * 1000 / mean.
            return (bytes * 1000.0 / mean.Value).ToString("N1", CultureInfo.InvariantCulture);
        }

        public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style) =>
            GetValue(summary, benchmarkCase);
    }

    private const ushort Aes128Gcm = 0x1301;
    private const ushort ChaCha20Poly1305Suite = 0x1303;

    /// <summary>
    /// The suites to measure. ChaCha20-Poly1305 is only offered where the platform has it — on a
    /// machine without it, <see cref="TlsCipherSuite.FromId"/> returns null and the client never
    /// negotiates it, so benchmarking it would measure nothing the client can reach.
    /// </summary>
    public static IEnumerable<string> Suites()
    {
        yield return "AES-128-GCM";

        if (ChaCha20Poly1305.IsSupported)
            yield return "ChaCha20-Poly1305";
    }

    [ParamsSource(nameof(Suites))]
    public string Suite { get; set; } = "AES-128-GCM";

    [Params(64, 1024, 8192, TlsRecordStream.MaxPlaintext)]
    public int Size { get; set; }

    private TlsRecordProtection _protect = null!;
    private TlsRecordProtection _pairWrite = null!;
    private TlsRecordProtection _pairRead = null!;

    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _opened = null!;
    private readonly byte[] _tag = new byte[TlsCipherSuite.TagLength];
    private readonly byte[] _header = new byte[5];

    [GlobalSetup]
    public void Setup()
    {
        ushort id = Suite == "ChaCha20-Poly1305" ? ChaCha20Poly1305Suite : Aes128Gcm;
        TlsCipherSuite suite = TlsCipherSuite.FromId(id)
                               ?? throw new NotSupportedException($"{Suite} is not available on this platform.");

        Span<byte> trafficSecret = stackalloc byte[suite.HashLength];
        RandomNumberGenerator.Fill(trafficSecret);

        _protect = new TlsRecordProtection(suite, trafficSecret);
        _pairWrite = new TlsRecordProtection(suite, trafficSecret);
        _pairRead = new TlsRecordProtection(suite, trafficSecret);

        _plaintext = new byte[Size];
        _ciphertext = new byte[Size];
        _opened = new byte[Size];
        RandomNumberGenerator.Fill(_plaintext);

        // A real outer record header: application_data, TLS 1.2 legacy version, ciphertext length.
        int recordLength = Size + TlsCipherSuite.TagLength;
        _header[0] = (byte)TlsContentType.ApplicationData;
        _header[1] = 3;
        _header[2] = 3;
        _header[3] = (byte)(recordLength >> 8);
        _header[4] = (byte)recordLength;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _protect.Dispose();
        _pairWrite.Dispose();
        _pairRead.Dispose();
    }

    /// <summary>Seal one record. No allocation: every buffer is preallocated.</summary>
    [Benchmark]
    [BenchmarkCategory("Protect")]
    public void Protect() => _protect.Protect(_plaintext, _ciphertext, _tag, _header);

    /// <summary>Seal and open one record with a matched pair, so the sequence numbers stay aligned.</summary>
    [Benchmark]
    [BenchmarkCategory("RoundTrip")]
    public void RoundTrip()
    {
        _pairWrite.Protect(_plaintext, _ciphertext, _tag, _header);
        _pairRead.Unprotect(_ciphertext, _tag, _opened, _header);
    }
}
