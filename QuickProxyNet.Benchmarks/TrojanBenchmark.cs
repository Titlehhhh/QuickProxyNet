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
/// Perf comparisons for the Trojan hot paths: request-header build (including the
/// mandatory SHA-224 password hash) and share-link parsing. Each category compares a
/// naive baseline against the implementation used by the library.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class TrojanBenchmark
{
    private class Config : ManualConfig
    {
        public Config() => AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const string Password = "mysecretpassword";
    private const string ShareLink =
        "trojan://mysecretpassword@cdn.example.com:8443?type=tcp&sni=real.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1#my-node";

    private readonly byte[] _buffer = new byte[512];

    // === Request header build (SHA-224 hash + request layout) ===

    // Baseline: hash to a byte[], format a hex string, assemble in a MemoryStream.
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Build")]
    public int Build_MemoryStream()
    {
        Span<byte> digest = stackalloc byte[Sha224.HashSize];
        Sha224.ComputeHash(Encoding.UTF8.GetBytes(Password), digest);
        string hex = Convert.ToHexStringLower(digest);

        using var ms = new MemoryStream(96);
        ms.Write(Encoding.ASCII.GetBytes(hex));
        ms.WriteByte(0x0D);
        ms.WriteByte(0x0A);
        ms.WriteByte(0x01);                        // CMD
        ms.WriteByte(0x03);                        // ATYP domain
        byte[] host = Encoding.UTF8.GetBytes("mc.example.com");
        ms.WriteByte((byte)host.Length);
        ms.Write(host);
        Span<byte> port = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(port, 25565);
        ms.Write(port);
        ms.WriteByte(0x0D);
        ms.WriteByte(0x0A);
        return ms.ToArray().Length;
    }

    // Library approach: single span write, SHA-224 straight into the buffer, zero allocation.
    [Benchmark]
    [BenchmarkCategory("Build")]
    public int Build_SpanBuild() => TrojanHelper.BuildRequest(_buffer, Password, "mc.example.com", 25565);

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
        var o = TrojanShareLink.Parse(ShareLink);
        return o.Host.Length + (o.Alpn?.Count ?? 0);
    }
}
