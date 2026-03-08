using System;
using System.Buffers;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Compares approaches for finding "\r\n\r\n" in HTTP response buffers.
/// Tests whether SearchValues&lt;byte&gt; provides benefit over plain IndexOf.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class FindEndOfHeadersBenchmark
{
    private class Config : ManualConfig
    {
        public Config()
        {
            AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
        }
    }
    // Typical HTTP CONNECT response: ~80 bytes headers, \r\n\r\n at the end
    private byte[] _shortResponse = null!;

    // Large response with many headers: ~600 bytes, \r\n\r\n near the end
    private byte[] _longResponse = null!;

    // Worst case: \r\n\r\n at the very end of a 4 KB buffer
    private byte[] _worstCase = null!;

    private static readonly byte[] s_endOfHeaders = "\r\n\r\n"u8.ToArray();

    private static readonly SearchValues<byte> s_crSearch = SearchValues.Create("\r"u8);

    [GlobalSetup]
    public void Setup()
    {
        _shortResponse = Encoding.UTF8.GetBytes(
            "HTTP/1.1 200 Connection established\r\n" +
            "Proxy-Agent: nginx\r\n" +
            "\r\n");

        _longResponse = Encoding.UTF8.GetBytes(
            "HTTP/1.1 200 Connection established\r\n" +
            "Proxy-Agent: squid/4.15\r\n" +
            "X-Cache: MISS from proxy.example.com\r\n" +
            "X-Cache-Lookup: NONE from proxy.example.com:3128\r\n" +
            "Via: 1.1 proxy.example.com (squid/4.15)\r\n" +
            "Connection: keep-alive\r\n" +
            "Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n" +
            "X-Forwarded-For: 192.168.1.100\r\n" +
            "X-Request-Id: abcdef01-2345-6789-abcd-ef0123456789\r\n" +
            "Content-Length: 0\r\n" +
            "\r\n");

        // 4 KB buffer with \r\n\r\n at the very end
        _worstCase = new byte[4096];
        // Fill with plausible header-like content (no premature \r\n\r\n)
        var padding = Encoding.UTF8.GetBytes("X-Header: value\r\n");
        int pos = 0;
        while (pos + padding.Length + 4 <= _worstCase.Length)
        {
            padding.CopyTo(_worstCase, pos);
            pos += padding.Length;
        }
        // Fill remaining with spaces, then put \r\n\r\n at the end
        while (pos < _worstCase.Length - 4) _worstCase[pos++] = (byte)' ';
        "\r\n\r\n"u8.CopyTo(_worstCase.AsSpan(pos));
    }

    // === Approach 1: Current — IndexOf with static byte[] ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Short")]
    public int IndexOf_StaticArray_Short() => _shortResponse.AsSpan().IndexOf(s_endOfHeaders);

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Long")]
    public int IndexOf_StaticArray_Long() => _longResponse.AsSpan().IndexOf(s_endOfHeaders);

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Worst")]
    public int IndexOf_StaticArray_Worst() => _worstCase.AsSpan().IndexOf(s_endOfHeaders);

    // === Approach 2: IndexOf with u8 literal directly ===

    [Benchmark]
    [BenchmarkCategory("Short")]
    public int IndexOf_Utf8Literal_Short() => _shortResponse.AsSpan().IndexOf("\r\n\r\n"u8);

    [Benchmark]
    [BenchmarkCategory("Long")]
    public int IndexOf_Utf8Literal_Long() => _longResponse.AsSpan().IndexOf("\r\n\r\n"u8);

    [Benchmark]
    [BenchmarkCategory("Worst")]
    public int IndexOf_Utf8Literal_Worst() => _worstCase.AsSpan().IndexOf("\r\n\r\n"u8);

    // === Approach 3: SearchValues-assisted (find \r, then validate sequence) ===

    [Benchmark]
    [BenchmarkCategory("Short")]
    public int SearchValues_Short() => FindWithSearchValues(_shortResponse);

    [Benchmark]
    [BenchmarkCategory("Long")]
    public int SearchValues_Long() => FindWithSearchValues(_longResponse);

    [Benchmark]
    [BenchmarkCategory("Worst")]
    public int SearchValues_Worst() => FindWithSearchValues(_worstCase);

    private static int FindWithSearchValues(ReadOnlySpan<byte> span)
    {
        int offset = 0;
        while (offset <= span.Length - 4)
        {
            int idx = span[offset..].IndexOfAny(s_crSearch);
            if (idx < 0) return -1;

            int abs = offset + idx;
            if (abs + 3 < span.Length &&
                span[abs + 1] == (byte)'\n' &&
                span[abs + 2] == (byte)'\r' &&
                span[abs + 3] == (byte)'\n')
            {
                return abs;
            }

            offset = abs + 1;
        }

        return -1;
    }
}
