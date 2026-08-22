using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Perf comparisons for the VLESS hot paths: UUID big-endian encoding, request-header
/// build, and share-link parsing. Each category compares a naive baseline against the
/// implementation used by the library.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class VlessBenchmark
{
    private class Config : ManualConfig
    {
        public Config() => AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";
    private const string ShareLink =
        "vless://11223344-5566-7788-99aa-bbccddeeff00@cdn.example.com:8443?type=tcp&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome#my-node";

    private readonly byte[] _buffer = new byte[512];

    // === UUID: canonical string -> 16 big-endian bytes ===

    // Baseline: the common WRONG approach — ToByteArray() is mixed-endian AND allocates.
    // Included to show both the correctness trap and the allocation cost.
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Uuid")]
    public byte Uuid_GuidToByteArray_Buggy()
    {
        byte[] bytes = Guid.Parse(Uuid).ToByteArray();
        return bytes[0];
    }

    // Library approach: Guid.TryParse + TryWriteBytes(bigEndian) — correct, zero-alloc.
    [Benchmark]
    [BenchmarkCategory("Uuid")]
    public byte Uuid_TryWriteBigEndian()
    {
        Span<byte> dest = stackalloc byte[16];
        UuidCodec.WriteBigEndian(Uuid, dest);
        return dest[0];
    }

    // Hand-rolled hex parse — no Guid machinery at all.
    [Benchmark]
    [BenchmarkCategory("Uuid")]
    public byte Uuid_ManualHex()
    {
        Span<byte> dest = stackalloc byte[16];
        ParseUuidHex(Uuid, dest);
        return dest[0];
    }

    private static void ParseUuidHex(ReadOnlySpan<char> id, Span<byte> dest)
    {
        int di = 0;
        for (int i = 0; i < id.Length && di < 16; i++)
        {
            if (id[i] == '-') continue;
            int hi = FromHex(id[i]);
            int lo = FromHex(id[++i]);
            dest[di++] = (byte)((hi << 4) | lo);
        }
    }

    private static int FromHex(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => 0
    };

    // === Request header build ===

    // Baseline: MemoryStream-based build, allocates the stream + ToArray().
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Header")]
    public int Header_MemoryStream()
    {
        using var ms = new MemoryStream(64);
        ms.WriteByte(0x00);
        ms.Write(Guid.Parse(Uuid).ToByteArray()); // (also the buggy order, but this is the naive baseline)
        ms.WriteByte(0x00);
        ms.WriteByte(0x01);
        Span<byte> port = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(port, 25565);
        ms.Write(port);
        ms.WriteByte(0x02);
        byte[] host = Encoding.UTF8.GetBytes("mc.example.com");
        ms.WriteByte((byte)host.Length);
        ms.Write(host);
        return ms.ToArray().Length;
    }

    // Library approach: single span write, zero allocation.
    [Benchmark]
    [BenchmarkCategory("Header")]
    public int Header_SpanBuild() => VlessHelper.BuildRequest(_buffer, Uuid, "mc.example.com", 25565);

    // === Share-link parse ===

    // Baseline: Uri + Dictionary from a naive Split of the query.
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Parse")]
    public int Parse_UriPlusDictionary()
    {
        var uri = new Uri(ShareLink);
        var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq > 0)
                q[pair[..eq]] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return q.Count + uri.Host.Length;
    }

    // Library approach: single-pass span query scan.
    [Benchmark]
    [BenchmarkCategory("Parse")]
    public int Parse_ShareLink()
    {
        var o = VlessShareLink.Parse(ShareLink);
        return o.Host.Length + (o.Alpn?.Count ?? 0);
    }
}
