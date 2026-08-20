using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Everything the managed REALITY client does <b>once per connection</b>: the X25519 key
/// exchange, the REALITY auth-key derivation and session-id seal, the TLS 1.3 key schedule, and
/// building the ClientHello.
/// </summary>
/// <remarks>
/// <para>
/// None of this is a throughput number and it must not be read as one. A connection runs each of
/// these a handful of times and then never again, so the unit that matters is <em>latency added
/// to a single connect</em>. Sum the means, do not divide bytes by them.
/// </para>
/// <para>
/// The <c>X25519</c> category exists to answer one question: on <c>net11.0</c> the BCL finally
/// ships <see cref="System.Security.Cryptography.X25519DiffieHellman"/>, so is the hand-written
/// curve in <see cref="X25519"/> still worth carrying there? The managed one has to stay for
/// <c>net8.0</c>–<c>net10.0</c> regardless — the BCL has no X25519 at all on those — so this only
/// decides whether <c>net11.0</c> should branch to the platform implementation.
/// </para>
/// <para>
/// <c>Managed_Agree</c> and <c>Platform_Agree</c> are the like-for-like pair: both are one
/// variable-base scalar multiplication over an already-prepared key. <c>Platform_GetPublicKey</c>
/// additionally pays an <c>ImportPrivateKey</c>, because that is the only way the platform API
/// lets a caller move from a private scalar to its public half; that overhead is real for any
/// caller that keeps its own key bytes, which this client does.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class RealityHandshakeBenchmark
{
    private class Config : ManualConfig
    {
        public Config() =>
            AddJob(Job.ShortRun.WithIterationCount(5).WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const string ServerName = "www.microsoft.com";

    private readonly byte[] _clientPrivate = new byte[X25519.KeySize];
    private readonly byte[] _clientPublic = new byte[X25519.KeySize];
    private readonly byte[] _serverPrivate = new byte[X25519.KeySize];
    private readonly byte[] _serverPublic = new byte[X25519.KeySize];
    private readonly byte[] _shared = new byte[X25519.KeySize];

    private readonly byte[] _clientRandom = new byte[32];
    private readonly byte[] _authKey = new byte[RealityAuth.AuthKeySize];
    private readonly byte[] _shortId = new byte[RealityAuth.ShortIdSize];
    private readonly byte[] _clientVersion = [1, 8, 4];

    /// <summary>A real ClientHello, rebuilt from a template every iteration so the seal is in place.</summary>
    private byte[] _helloTemplate = null!;
    private byte[] _hello = null!;

    private readonly byte[] _trafficSecret = new byte[32];
    private readonly byte[] _key = new byte[16];
    private readonly byte[] _iv = new byte[12];
    private readonly byte[] _expanded = new byte[32];

    private static readonly string[] Alpn = ["h2", "http/1.1"];

#if NET11_0_OR_GREATER
    private X25519DiffieHellman _platformClient = null!;
    private X25519DiffieHellman _platformServer = null!;
    private readonly byte[] _platformShared = new byte[32];
    private readonly byte[] _platformPublic = new byte[32];
#endif

    [GlobalSetup]
    public void Setup()
    {
        X25519.GenerateKeyPair(_clientPrivate, _clientPublic);
        X25519.GenerateKeyPair(_serverPrivate, _serverPublic);

        RandomNumberGenerator.Fill(_clientRandom);
        RandomNumberGenerator.Fill(_shortId);
        RandomNumberGenerator.Fill(_trafficSecret);

        RealityAuth.DeriveAuthKey(_authKey, _clientPrivate, _serverPublic, _clientRandom);

        _helloTemplate = TlsClientHello.Build(ServerName, Alpn).Handshake;
        _hello = new byte[_helloTemplate.Length];

#if NET11_0_OR_GREATER
        _platformClient = X25519DiffieHellman.ImportPrivateKey(_clientPrivate);
        _platformServer = X25519DiffieHellman.ImportPrivateKey(_serverPrivate);
#endif
    }

    [GlobalCleanup]
    public void Cleanup()
    {
#if NET11_0_OR_GREATER
        _platformClient.Dispose();
        _platformServer.Dispose();
#endif
    }

    // ============================== X25519 ==============================

    /// <summary>One variable-base scalar multiplication: the REALITY shared secret.</summary>
    [Benchmark]
    [BenchmarkCategory("X25519")]
    public void Managed_Agree() => X25519.Agree(_shared, _clientPrivate, _serverPublic);

    /// <summary>One fixed-base (u = 9) scalar multiplication: private scalar to public key.</summary>
    [Benchmark]
    [BenchmarkCategory("X25519")]
    public void Managed_GetPublicKey() => X25519.GetPublicKey(_clientPublic, _clientPrivate);

#if NET11_0_OR_GREATER
    /// <summary>The .NET 11 platform equivalent of <see cref="Managed_Agree"/>.</summary>
    [Benchmark]
    [BenchmarkCategory("X25519")]
    public void Platform_Agree() => _platformClient.DeriveRawSecretAgreement(_serverPublic, _platformShared);

    /// <summary>
    /// The .NET 11 equivalent of <see cref="Managed_GetPublicKey"/>, including the
    /// <c>ImportPrivateKey</c> a caller holding raw key bytes cannot avoid.
    /// </summary>
    [Benchmark]
    [BenchmarkCategory("X25519")]
    public void Platform_GetPublicKey()
    {
        using var key = X25519DiffieHellman.ImportPrivateKey(_clientPrivate);
        key.ExportPublicKey(_platformPublic);
    }
#endif

    // ============================= REALITY =============================

    /// <summary>X25519 agreement plus HKDF-SHA256 — the REALITY auth key.</summary>
    [Benchmark]
    [BenchmarkCategory("Reality")]
    public void DeriveAuthKey() =>
        RealityAuth.DeriveAuthKey(_authKey, _clientPrivate, _serverPublic, _clientRandom);

    /// <summary>
    /// AES-256-GCM over the whole ClientHello as additional data, output into <c>session_id</c>.
    /// </summary>
    /// <remarks>
    /// The hello is copied from a template first because the seal is in-place and destroys its own
    /// additional data. That copy is a few hundred bytes and is part of what the caller pays
    /// anyway, since the hello is rebuilt per connection.
    /// </remarks>
    [Benchmark]
    [BenchmarkCategory("Reality")]
    public void SealSessionId()
    {
        _helloTemplate.AsSpan().CopyTo(_hello);
        RealityAuth.SealSessionId(_hello, _authKey, _shortId, 1_800_000_000u, _clientVersion);
    }

    // =========================== key schedule ===========================

    /// <summary>One HKDF-Expand-Label producing 32 bytes.</summary>
    [Benchmark]
    [BenchmarkCategory("KeySchedule")]
    public void ExpandLabel() =>
        TlsKeySchedule.ExpandLabel(HashAlgorithmName.SHA256, _trafficSecret, "derived"u8, default, _expanded);

    /// <summary>The two expands that turn a traffic secret into an AEAD key and static IV.</summary>
    [Benchmark]
    [BenchmarkCategory("KeySchedule")]
    public void TrafficKeys() =>
        TlsKeySchedule.TrafficKeys(HashAlgorithmName.SHA256, _trafficSecret, _key, _iv);

    // ============================ ClientHello ============================

    /// <summary>
    /// The whole ClientHello: a fresh key pair (one fixed-base scalar multiplication), the random,
    /// and every extension serialised.
    /// </summary>
    [Benchmark]
    [BenchmarkCategory("ClientHello")]
    public byte[] BuildClientHello() => TlsClientHello.Build(ServerName, Alpn).Handshake;
}
