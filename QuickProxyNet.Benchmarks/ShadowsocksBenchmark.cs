using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// The Shadowsocks steady-state hot path — sealing and opening AEAD chunks with
/// <see cref="ShadowsocksStream"/> — measured next to <see cref="VmessStream"/>, the in-house
/// reference for AEAD chunk streaming, at the same payload sizes; plus <c>ss://</c> share-link
/// parsing next to <c>trojan://</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>Seal</c> writes to <see cref="Stream.Null"/> and isolates the seal + frame cost.
/// <c>RoundTrip</c> seals into a recycled <see cref="MemoryStream"/> and opens the chunks back
/// out, so (RoundTrip − Seal) approximates the open cost. <c>SealYield</c> writes to a sink whose
/// <c>WriteAsync</c> always completes asynchronously: that is the shape of a real socket, and the
/// only shape in which an <c>async</c> method's state machine is boxed — so its allocated bytes
/// are the ones a live connection actually pays per write.
/// </para>
/// <para>
/// Payloads: 1 KiB (a small interactive write), 16 383 B (<see cref="ShadowsocksStream.MaxPayloadSize"/>,
/// exactly one full Shadowsocks chunk; VMess cuts it into three) and 1 MiB (65 Shadowsocks
/// chunks, 129 VMess chunks). Shadowsocks pays two AEAD operations per chunk by protocol — the
/// length is sealed on its own — where VMess pays one. AES-128-GCM VMess is the baseline in every
/// category because that is the cipher VMess speaks; the Shadowsocks <c>aes-128-gcm</c> rows
/// separate framing cost from cipher cost, since <c>aes-256-gcm</c> runs 14 AES rounds to 10.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class ShadowsocksBenchmark
{
    private class Config : ManualConfig
    {
        public Config() => AddJob(Job.ShortRun.WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const int SmallSize = 1024;
    private const int ChunkSize = ShadowsocksStream.MaxPayloadSize; // 16383
    private const int LargeSize = 1024 * 1024;

    private const string Password = "quickproxynet-benchmark-password";

    // ---- share links: same host, password and remark for every scheme ----

    private const string TrojanLink =
        "trojan://mysecretpassword@cdn.example.com:8443?type=tcp&sni=real.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1#my-node";

    // SIP002, base64 userinfo (standard alphabet, padded — what v2rayN emits).
    private static readonly string SsSip002Base64Link =
        "ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:mysecretpassword")) +
        "@cdn.example.com:8443#my-node";

    // SIP002, plain percent-encoded userinfo (shadowsocks-rust's preferred output).
    private const string SsSip002PlainLink =
        "ss://aes-256-gcm:mysecretpassword@cdn.example.com:8443#my-node";

    // Legacy: the whole authority is one base64 blob.
    private static readonly string SsLegacyLink =
        "ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-256-gcm:mysecretpassword@cdn.example.com:8443")) +
        "#my-node";

    // ---- VMess keys (body keys are 16 bytes regardless of cipher) ----

    private static readonly byte[] VmessClientKey = MakePattern(0xC1, 16);
    private static readonly byte[] VmessClientIv = MakePattern(0xC2, 16);
    private static readonly byte[] VmessServerKey = MakePattern(0x51, 16);
    private static readonly byte[] VmessServerIv = MakePattern(0x52, 16);

    private readonly byte[] _small = MakePattern(0xAB, SmallSize);
    private readonly byte[] _chunk = MakePattern(0xCD, ChunkSize);
    private readonly byte[] _large = MakePattern(0xEF, LargeSize);
    private readonly byte[] _readBuffer = new byte[64 * 1024];

    // Seal-only streams (sink: Stream.Null).
    private ShadowsocksStream _ssAes128Sealer = null!;
    private ShadowsocksStream _ssAes256Sealer = null!;
    private ShadowsocksStream _ssChaChaSealer = null!;
    private VmessStream _vmAes128Sealer = null!;
    private VmessStream _vmChaChaSealer = null!;

    // Seal-only streams whose sink always completes asynchronously.
    private ShadowsocksStream _ssAes128YieldSealer = null!;
    private VmessStream _vmAes128YieldSealer = null!;

    // Loopback pairs (writer + reader over one recycled MemoryStream each).
    private Loop<ShadowsocksStream> _ssAes128Loop;
    private Loop<ShadowsocksStream> _ssAes256Loop;
    private Loop<ShadowsocksStream> _ssChaChaLoop;
    private Loop<VmessStream> _vmAes128Loop;
    private Loop<VmessStream> _vmChaChaLoop;

    private struct Loop<T> where T : Stream
    {
        public MemoryStream Wire;
        public T Writer;
        public T Reader;

        public void Dispose()
        {
            Writer.Dispose();
            Reader.Dispose();
            Wire.Dispose();
        }
    }

    private static byte[] MakePattern(byte seed, int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)(seed + i * 31);
        return data;
    }

    private static byte[] MasterKey(ShadowsocksMethod method)
    {
        byte[] key = new byte[ShadowsocksCipher.KeySize(method)];
        ShadowsocksCipher.DeriveMasterKey(Password, key);
        return key;
    }

    private static byte[] Salt(ShadowsocksMethod method, byte seed) =>
        MakePattern(seed, ShadowsocksCipher.SaltSize(method));

    private static ShadowsocksStream Ss(Stream inner, ShadowsocksMethod method, byte saltSeed) =>
        new(inner, method, MasterKey(method), Salt(method, saltSeed), leaveInnerOpen: true);

    private static VmessStream VmWriter(Stream inner, VmessSecurity security) =>
        new(inner, VmessClientKey, VmessClientIv, VmessServerKey, VmessServerIv, security, leaveInnerOpen: true);

    // The reader's read direction mirrors the writer's write direction.
    private static VmessStream VmReader(Stream inner, VmessSecurity security) =>
        new(inner, VmessServerKey, VmessServerIv, VmessClientKey, VmessClientIv, security, leaveInnerOpen: true);

    private static Loop<ShadowsocksStream> SsLoop(ShadowsocksMethod method)
    {
        // The reader keys its read direction from whatever salt arrives, exactly like a server;
        // its own write direction (and salt) is never used.
        var wire = new MemoryStream(LargeSize + 64 * 1024);
        return new Loop<ShadowsocksStream>
        {
            Wire = wire,
            Writer = Ss(wire, method, 0x11),
            Reader = Ss(wire, method, 0x22),
        };
    }

    private static Loop<VmessStream> VmLoop(VmessSecurity security)
    {
        var wire = new MemoryStream(LargeSize + 64 * 1024);
        return new Loop<VmessStream>
        {
            Wire = wire,
            Writer = VmWriter(wire, security),
            Reader = VmReader(wire, security),
        };
    }

    [GlobalSetup]
    public void Setup()
    {
        _ssAes128Sealer = Ss(Stream.Null, ShadowsocksMethod.Aes128Gcm, 0x31);
        _ssAes256Sealer = Ss(Stream.Null, ShadowsocksMethod.Aes256Gcm, 0x32);
        _ssChaChaSealer = Ss(Stream.Null, ShadowsocksMethod.ChaCha20Poly1305, 0x33);
        _vmAes128Sealer = VmWriter(Stream.Null, VmessSecurity.Aes128Gcm);
        _vmChaChaSealer = VmWriter(Stream.Null, VmessSecurity.ChaCha20Poly1305);

        _ssAes128YieldSealer = Ss(new YieldingSink(), ShadowsocksMethod.Aes128Gcm, 0x41);
        _vmAes128YieldSealer = VmWriter(new YieldingSink(), VmessSecurity.Aes128Gcm);

        _ssAes128Loop = SsLoop(ShadowsocksMethod.Aes128Gcm);
        _ssAes256Loop = SsLoop(ShadowsocksMethod.Aes256Gcm);
        _ssChaChaLoop = SsLoop(ShadowsocksMethod.ChaCha20Poly1305);
        _vmAes128Loop = VmLoop(VmessSecurity.Aes128Gcm);
        _vmChaChaLoop = VmLoop(VmessSecurity.ChaCha20Poly1305);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _ssAes128Sealer.Dispose();
        _ssAes256Sealer.Dispose();
        _ssChaChaSealer.Dispose();
        _vmAes128Sealer.Dispose();
        _vmChaChaSealer.Dispose();
        _ssAes128YieldSealer.Dispose();
        _vmAes128YieldSealer.Dispose();
        _ssAes128Loop.Dispose();
        _ssAes256Loop.Dispose();
        _ssChaChaLoop.Dispose();
        _vmAes128Loop.Dispose();
        _vmChaChaLoop.Dispose();
    }

    // ============================ seal only → Stream.Null ============================

    [Benchmark(Baseline = true), BenchmarkCategory("Seal 1K")]
    public ValueTask Seal_1K_Vmess_Aes128() => _vmAes128Sealer.WriteAsync(_small.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1K")]
    public ValueTask Seal_1K_Ss_Aes128() => _ssAes128Sealer.WriteAsync(_small.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1K")]
    public ValueTask Seal_1K_Ss_Aes256() => _ssAes256Sealer.WriteAsync(_small.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1K")]
    public ValueTask Seal_1K_Vmess_ChaCha() => _vmChaChaSealer.WriteAsync(_small.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1K")]
    public ValueTask Seal_1K_Ss_ChaCha() => _ssChaChaSealer.WriteAsync(_small.AsMemory());

    [Benchmark(Baseline = true), BenchmarkCategory("Seal 16K")]
    public ValueTask Seal_16K_Vmess_Aes128() => _vmAes128Sealer.WriteAsync(_chunk.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 16K")]
    public ValueTask Seal_16K_Ss_Aes128() => _ssAes128Sealer.WriteAsync(_chunk.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 16K")]
    public ValueTask Seal_16K_Ss_Aes256() => _ssAes256Sealer.WriteAsync(_chunk.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 16K")]
    public ValueTask Seal_16K_Vmess_ChaCha() => _vmChaChaSealer.WriteAsync(_chunk.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 16K")]
    public ValueTask Seal_16K_Ss_ChaCha() => _ssChaChaSealer.WriteAsync(_chunk.AsMemory());

    [Benchmark(Baseline = true), BenchmarkCategory("Seal 1M")]
    public ValueTask Seal_1M_Vmess_Aes128() => _vmAes128Sealer.WriteAsync(_large.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1M")]
    public ValueTask Seal_1M_Ss_Aes128() => _ssAes128Sealer.WriteAsync(_large.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1M")]
    public ValueTask Seal_1M_Ss_Aes256() => _ssAes256Sealer.WriteAsync(_large.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1M")]
    public ValueTask Seal_1M_Vmess_ChaCha() => _vmChaChaSealer.WriteAsync(_large.AsMemory());

    [Benchmark, BenchmarkCategory("Seal 1M")]
    public ValueTask Seal_1M_Ss_ChaCha() => _ssChaChaSealer.WriteAsync(_large.AsMemory());

    // ======================== seal + open, MemoryStream loopback ========================

    [Benchmark(Baseline = true), BenchmarkCategory("RoundTrip 1K")]
    public Task<int> RoundTrip_1K_Vmess_Aes128() => RoundTrip(_vmAes128Loop, _small);

    [Benchmark, BenchmarkCategory("RoundTrip 1K")]
    public Task<int> RoundTrip_1K_Ss_Aes128() => RoundTrip(_ssAes128Loop, _small);

    [Benchmark, BenchmarkCategory("RoundTrip 1K")]
    public Task<int> RoundTrip_1K_Ss_Aes256() => RoundTrip(_ssAes256Loop, _small);

    [Benchmark, BenchmarkCategory("RoundTrip 1K")]
    public Task<int> RoundTrip_1K_Vmess_ChaCha() => RoundTrip(_vmChaChaLoop, _small);

    [Benchmark, BenchmarkCategory("RoundTrip 1K")]
    public Task<int> RoundTrip_1K_Ss_ChaCha() => RoundTrip(_ssChaChaLoop, _small);

    [Benchmark(Baseline = true), BenchmarkCategory("RoundTrip 16K")]
    public Task<int> RoundTrip_16K_Vmess_Aes128() => RoundTrip(_vmAes128Loop, _chunk);

    [Benchmark, BenchmarkCategory("RoundTrip 16K")]
    public Task<int> RoundTrip_16K_Ss_Aes128() => RoundTrip(_ssAes128Loop, _chunk);

    [Benchmark, BenchmarkCategory("RoundTrip 16K")]
    public Task<int> RoundTrip_16K_Ss_Aes256() => RoundTrip(_ssAes256Loop, _chunk);

    [Benchmark, BenchmarkCategory("RoundTrip 16K")]
    public Task<int> RoundTrip_16K_Vmess_ChaCha() => RoundTrip(_vmChaChaLoop, _chunk);

    [Benchmark, BenchmarkCategory("RoundTrip 16K")]
    public Task<int> RoundTrip_16K_Ss_ChaCha() => RoundTrip(_ssChaChaLoop, _chunk);

    [Benchmark(Baseline = true), BenchmarkCategory("RoundTrip 1M")]
    public Task<int> RoundTrip_1M_Vmess_Aes128() => RoundTrip(_vmAes128Loop, _large);

    [Benchmark, BenchmarkCategory("RoundTrip 1M")]
    public Task<int> RoundTrip_1M_Ss_Aes128() => RoundTrip(_ssAes128Loop, _large);

    [Benchmark, BenchmarkCategory("RoundTrip 1M")]
    public Task<int> RoundTrip_1M_Ss_Aes256() => RoundTrip(_ssAes256Loop, _large);

    [Benchmark, BenchmarkCategory("RoundTrip 1M")]
    public Task<int> RoundTrip_1M_Vmess_ChaCha() => RoundTrip(_vmChaChaLoop, _large);

    [Benchmark, BenchmarkCategory("RoundTrip 1M")]
    public Task<int> RoundTrip_1M_Ss_ChaCha() => RoundTrip(_ssChaChaLoop, _large);

    private async Task<int> RoundTrip<T>(Loop<T> loop, byte[] payload) where T : Stream
    {
        MemoryStream wire = loop.Wire;
        wire.Position = 0;
        wire.SetLength(0);
        await loop.Writer.WriteAsync(payload.AsMemory());

        wire.Position = 0;
        int total = 0;
        while (total < payload.Length)
        {
            int read = await loop.Reader.ReadAsync(_readBuffer.AsMemory());
            if (read == 0)
                throw new InvalidOperationException("Unexpected end of stream.");
            total += read;
        }

        return total;
    }

    // ================== seal → a sink that always completes asynchronously ==================

    [Benchmark(Baseline = true), BenchmarkCategory("SealYield 1K")]
    public Task SealYield_1K_Vmess_Aes128() => _vmAes128YieldSealer.WriteAsync(_small.AsMemory()).AsTask();

    [Benchmark, BenchmarkCategory("SealYield 1K")]
    public Task SealYield_1K_Ss_Aes128() => _ssAes128YieldSealer.WriteAsync(_small.AsMemory()).AsTask();

    [Benchmark(Baseline = true), BenchmarkCategory("SealYield 16K")]
    public Task SealYield_16K_Vmess_Aes128() => _vmAes128YieldSealer.WriteAsync(_chunk.AsMemory()).AsTask();

    [Benchmark, BenchmarkCategory("SealYield 16K")]
    public Task SealYield_16K_Ss_Aes128() => _ssAes128YieldSealer.WriteAsync(_chunk.AsMemory()).AsTask();

    [Benchmark(Baseline = true), BenchmarkCategory("SealYield 1M")]
    public Task SealYield_1M_Vmess_Aes128() => _vmAes128YieldSealer.WriteAsync(_large.AsMemory()).AsTask();

    [Benchmark, BenchmarkCategory("SealYield 1M")]
    public Task SealYield_1M_Ss_Aes128() => _ssAes128YieldSealer.WriteAsync(_large.AsMemory()).AsTask();

    /// <summary>
    /// A write sink whose <c>WriteAsync</c> never completes synchronously, so every awaiting
    /// <c>async</c> frame above it has to box its state machine — the way a real socket makes
    /// it. The yield itself costs both protocols the same.
    /// </summary>
    private sealed class YieldingSink : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) { }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => await Task.Yield();
    }

    // ================================ share-link parse ================================

    [Benchmark(Baseline = true), BenchmarkCategory("Parse")]
    public int Parse_Trojan()
    {
        TrojanShareLink.TryParse(TrojanLink, out TrojanOptions o);
        return o.Host.Length + o.Port;
    }

    [Benchmark, BenchmarkCategory("Parse")]
    public int Parse_Ss_Sip002_Base64()
    {
        ShadowsocksShareLink.TryParse(SsSip002Base64Link, out ShadowsocksOptions o);
        return o.Host.Length + o.Port;
    }

    [Benchmark, BenchmarkCategory("Parse")]
    public int Parse_Ss_Sip002_Plain()
    {
        ShadowsocksShareLink.TryParse(SsSip002PlainLink, out ShadowsocksOptions o);
        return o.Host.Length + o.Port;
    }

    [Benchmark, BenchmarkCategory("Parse")]
    public int Parse_Ss_Legacy()
    {
        ShadowsocksShareLink.TryParse(SsLegacyLink, out ShadowsocksOptions o);
        return o.Host.Length + o.Port;
    }
}
