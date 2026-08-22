using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Perf comparisons for the VMess hot paths: share-link parsing and the full VMessAEAD
/// request-header build (cmdKey derivation, AuthID, command section and both AEAD seals).
/// Each category compares a naive baseline against the implementation used by the library.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class VmessBenchmark
{
    /// <summary>
    /// <see cref="Job.ShortRun"/> by default (fast, but too noisy to defend a small delta).
    /// Set <c>QPN_BENCH_LONG=1</c> to switch to a multi-launch job with enough iterations
    /// that the reported error/StdDev is meaningful — use that when a timing change has to
    /// be claimed, not just observed.
    /// </summary>
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

    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";
    private const string TargetHost = "mc.example.com";
    private const int TargetPort = 25565;

    private const string Json =
        """
        {"v":"2","ps":"my node","add":"cdn.example.com","port":"8443",
         "id":"11223344-5566-7788-99aa-bbccddeeff00","aid":"0","scy":"aes-128-gcm",
         "net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"real.example.com"}
        """;

    private static readonly string ShareLink =
        "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(Json));

    private readonly byte[] _buffer = new byte[VmessRequest.MaxRequestSize];

    // ============================ share-link parse ============================

    // Baseline: decode to a string, hand the JSON to JsonDocument, then copy every
    // property into a Dictionary before reading the handful of fields that matter.
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Parse")]
    public int Parse_JsonDocumentPlusDictionary()
    {
        string payload = ShareLink["vmess://".Length..];
        byte[] json = Convert.FromBase64String(payload);

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var document = JsonDocument.Parse(json))
        {
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
                map[property.Name] = property.Value.ToString();
        }

        string host = map["add"];
        int port = int.Parse(map["port"]);
        string id = map["id"];
        int alterId = int.Parse(map["aid"]);

        return host.Length + port + id.Length + alterId;
    }

    // Library approach: pooled base64 decode, a single EnumerateObject pass, and no
    // intermediate dictionary.
    [Benchmark]
    [BenchmarkCategory("Parse")]
    public int Parse_ShareLink()
    {
        VmessOptions options = VmessShareLink.Parse(ShareLink);
        return options.Host.Length + options.Port + options.Id.Length + options.AlterId;
    }

    // ---- cost attribution for the parse path ----

    // Base64 decode alone, into a pooled buffer.
    [Benchmark]
    [BenchmarkCategory("Parse")]
    public int Parse_Base64Only()
    {
        ReadOnlySpan<char> payload = ShareLink.AsSpan()["vmess://".Length..];
        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent((payload.Length + 3) / 4 * 3);
        try
        {
            Convert.TryFromBase64Chars(payload, buffer, out int written);
            return written;
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    // Decode plus JsonDocument construction, with no field access at all: the floor both
    // the baseline and the library implementation are built on.
    [Benchmark]
    [BenchmarkCategory("Parse")]
    public int Parse_JsonDocumentOnly()
    {
        ReadOnlySpan<char> payload = ShareLink.AsSpan()["vmess://".Length..];
        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent((payload.Length + 3) / 4 * 3);
        try
        {
            Convert.TryFromBase64Chars(payload, buffer, out int written);
            using var document = JsonDocument.Parse(buffer.AsMemory(0, written));
            return document.RootElement.GetPropertyCount();
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    // ============================ request header build ============================

    // Baseline: the same protocol steps written the obvious allocating way — a byte[] per
    // intermediate value and a MemoryStream to assemble the envelope.
    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Header")]
    public int Header_NaiveAllocating()
    {
        byte[] cmdKey = new byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, cmdKey);

        byte[] bodyKey = RandomNumberGenerator.GetBytes(16);
        byte[] bodyIv = RandomNumberGenerator.GetBytes(16);
        byte[] connectionNonce = RandomNumberGenerator.GetBytes(8);
        byte[] random4 = RandomNumberGenerator.GetBytes(4);
        byte[] padding = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(0, 16));

        byte[] authId = new byte[VmessAuthId.Size];
        VmessAuthId.Create(cmdKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), random4, authId);

        // --- command section ---
        using var command = new MemoryStream(96);
        command.WriteByte(VmessRequest.Version);
        command.Write(bodyIv);
        command.Write(bodyKey);
        command.WriteByte(0x2A);
        command.WriteByte(VmessRequest.OptionChunkStream);
        command.WriteByte((byte)((padding.Length << 4) | VmessRequest.SecurityAes128Gcm));
        command.WriteByte(0x00);
        command.WriteByte(VmessRequest.CommandTcp);

        byte[] port = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(port, TargetPort);
        command.Write(port);

        byte[] host = Encoding.UTF8.GetBytes(TargetHost);
        command.WriteByte(0x02);
        command.WriteByte((byte)host.Length);
        command.Write(host);
        command.Write(padding);

        byte[] data = command.ToArray();
        byte[] checksum = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(checksum, Fnv1a32.Compute(data));

        byte[] plaintext = new byte[data.Length + 4];
        data.CopyTo(plaintext, 0);
        checksum.CopyTo(plaintext, data.Length);

        // --- AEAD envelope ---
        byte[] lengthKey = new byte[16];
        byte[] lengthNonce = new byte[12];
        byte[] payloadKey = new byte[16];
        byte[] payloadNonce = new byte[12];
        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key_Length"u8, authId, connectionNonce, lengthKey);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce_Length"u8, authId, connectionNonce, lengthNonce);
        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key"u8, authId, connectionNonce, payloadKey);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce"u8, authId, connectionNonce, payloadNonce);

        byte[] lengthPlaintext = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)plaintext.Length);

        byte[] encryptedLength = new byte[2];
        byte[] lengthTag = new byte[16];
        using (var gcm = new AesGcm(lengthKey, 16))
            gcm.Encrypt(lengthNonce, lengthPlaintext, encryptedLength, lengthTag, authId);

        byte[] encryptedHeader = new byte[plaintext.Length];
        byte[] headerTag = new byte[16];
        using (var gcm = new AesGcm(payloadKey, 16))
            gcm.Encrypt(payloadNonce, plaintext, encryptedHeader, headerTag, authId);

        using var wire = new MemoryStream(VmessRequest.MaxRequestSize);
        wire.Write(authId);
        wire.Write(encryptedLength);
        wire.Write(lengthTag);
        wire.Write(connectionNonce);
        wire.Write(encryptedHeader);
        wire.Write(headerTag);

        return wire.ToArray().Length;
    }

    // Library approach: stackalloc'd cmdKey and material, one pooled scratch buffer inside
    // Build, and the sealed header written straight into the caller's span.
    [Benchmark]
    [BenchmarkCategory("Header")]
    public int Header_Build()
    {
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        Span<byte> scratch = stackalloc byte[VmessRequest.MaterialScratchSize];
        try
        {
            VmessCmdKey.Derive(Uuid, cmdKey);
            VmessRequestMaterial material = VmessRequest.CreateMaterial(scratch);

            return VmessRequest.Build(
                _buffer,
                cmdKey,
                material,
                VmessRequest.OptionChunkStream,
                VmessRequest.SecurityAes128Gcm,
                VmessRequest.CommandTcp,
                TargetHost,
                TargetPort);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cmdKey);
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    // ---- cost attribution for the header build ----
    // Header_Build is dominated by two pieces neither implementation can avoid; these
    // isolate them so the ~1 µs of actual framing is not mistaken for the bottleneck.

    // One MD5 over 52 stack bytes.
    [Benchmark]
    [BenchmarkCategory("Header")]
    public byte Header_CmdKeyOnly()
    {
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, cmdKey);
        return cmdKey[0];
    }

    // AuthID: one KDF16 plus a single-block AES-ECB through Aes.Create().
    [Benchmark]
    [BenchmarkCategory("Header")]
    public byte Header_AuthIdOnly()
    {
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, cmdKey);

        Span<byte> authId = stackalloc byte[VmessAuthId.Size];
        VmessAuthId.Create(cmdKey, authId);
        return authId[0];
    }

    // The AES-128-ECB single-block encrypt inside the AuthID: Aes.Create(), key set,
    // one block — isolates what a cached/reused Aes instance could save.
    [Benchmark]
    [BenchmarkCategory("Header")]
    public byte Header_AesEcbOnly()
    {
        Span<byte> block = stackalloc byte[16];
        byte[] key = new byte[16];
        try
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = key;
            aes.EncryptEcb(block, block, PaddingMode.None);
            return block[0];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // The four request-header KDF derivations: each is a 4-deep nested HMAC-SHA256.
    [Benchmark]
    [BenchmarkCategory("Header")]
    public byte Header_KdfOnly()
    {
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        VmessCmdKey.Derive(Uuid, cmdKey);

        Span<byte> authId = stackalloc byte[16];
        Span<byte> nonce = stackalloc byte[8];
        Span<byte> key = stackalloc byte[16];
        Span<byte> iv = stackalloc byte[12];

        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key_Length"u8, authId, nonce, key);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce_Length"u8, authId, nonce, iv);
        VmessKdf.Kdf16(cmdKey, "VMess Header AEAD Key"u8, authId, nonce, key);
        VmessKdf.Kdf12(cmdKey, "VMess Header AEAD Nonce"u8, authId, nonce, iv);

        return (byte)(key[0] ^ iv[0]);
    }
}
