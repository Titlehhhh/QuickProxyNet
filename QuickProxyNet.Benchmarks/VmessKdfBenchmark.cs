using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// A/B for the VMessAEAD KDF: the shipping <see cref="VmessKdf"/>, which delegates the
/// innermost (seed-keyed) HMAC to the platform's <see cref="IncrementalHash"/>, against
/// <see cref="MidstateVmessKdf"/>, which runs the managed <see cref="Sha256Core"/> and resumes
/// from precomputed ipad/opad midstates.
/// </summary>
/// <remarks>
/// <para>
/// The midstate variant is <b>not</b> in the library: it was implemented, measured, and lost.
/// It lives here so the comparison can be re-run — in particular on a CPU with SHA-NI, where
/// the platform side gets faster still and the gap should widen. See the remarks on
/// <see cref="VmessKdf"/> for the full finding.
/// </para>
/// <para>
/// Both variants run in the same process and the same BenchmarkDotNet run, alternating. That
/// matters more than usual here: measured across <em>separate</em> runs this machine moves
/// untouched benchmarks by ~10%, which is larger than the effect being measured. A ratio from
/// one interleaved run is not exposed to that drift.
/// </para>
/// <para>
/// The two categories are weighted differently by real traffic. One VMess connection performs
/// five one-element derivations (one in <c>VmessAuthId</c>, four in <c>VmessResponse</c>) and
/// four three-element ones, so <c>SingleElementKdf</c> must be multiplied by five and
/// <c>RequestHeaderKdf</c> counted once when adding them up.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class VmessKdfBenchmark
{
    /// <summary>
    /// <see cref="Job.ShortRun"/> by default; set <c>QPN_BENCH_LONG=1</c> for a multi-launch
    /// job whose reported error is small enough to defend the ratio.
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

    private readonly byte[] _cmdKey = new byte[16];
    private readonly byte[] _authId = new byte[16];
    private readonly byte[] _nonce = new byte[8];
    private readonly byte[] _key = new byte[16];
    private readonly byte[] _iv = new byte[12];

    private static ReadOnlySpan<byte> KeyLengthLabel => "VMess Header AEAD Key_Length"u8;
    private static ReadOnlySpan<byte> NonceLengthLabel => "VMess Header AEAD Nonce_Length"u8;
    private static ReadOnlySpan<byte> KeyLabel => "VMess Header AEAD Key"u8;
    private static ReadOnlySpan<byte> NonceLabel => "VMess Header AEAD Nonce"u8;
    private static ReadOnlySpan<byte> AuthIdLabel => "AES Auth ID Encryption"u8;

    [GlobalSetup]
    public void Setup()
    {
        new Random(1234).NextBytes(_cmdKey);
        new Random(5678).NextBytes(_authId);
        new Random(9012).NextBytes(_nonce);

        // A benchmark that measures two implementations of different functions is worthless.
        Span<byte> shipping = stackalloc byte[16];
        Span<byte> midstate = stackalloc byte[16];

        VmessKdf.Kdf16(_cmdKey, KeyLabel, _authId, _nonce, shipping);
        MidstateVmessKdf.Kdf16(_cmdKey, KeyLabel, _authId, _nonce, midstate);
        if (!shipping.SequenceEqual(midstate))
            throw new InvalidOperationException("KDF variants disagree on the 3-element path.");

        VmessKdf.Kdf16(_cmdKey, AuthIdLabel, shipping);
        MidstateVmessKdf.Kdf16(_cmdKey, AuthIdLabel, midstate);
        if (!shipping.SequenceEqual(midstate))
            throw new InvalidOperationException("KDF variants disagree on the 1-element path.");
    }

    // === The four request-header derivations: once per connection ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("RequestHeaderKdf")]
    public byte RequestHeader_PlatformIncrementalHash()
    {
        VmessKdf.Kdf16(_cmdKey, KeyLengthLabel, _authId, _nonce, _key);
        VmessKdf.Kdf12(_cmdKey, NonceLengthLabel, _authId, _nonce, _iv);
        VmessKdf.Kdf16(_cmdKey, KeyLabel, _authId, _nonce, _key);
        VmessKdf.Kdf12(_cmdKey, NonceLabel, _authId, _nonce, _iv);
        return (byte)(_key[0] ^ _iv[0]);
    }

    [Benchmark]
    [BenchmarkCategory("RequestHeaderKdf")]
    public byte RequestHeader_MidstateSeedHmac()
    {
        MidstateVmessKdf.Kdf16(_cmdKey, KeyLengthLabel, _authId, _nonce, _key);
        MidstateVmessKdf.Kdf12(_cmdKey, NonceLengthLabel, _authId, _nonce, _iv);
        MidstateVmessKdf.Kdf16(_cmdKey, KeyLabel, _authId, _nonce, _key);
        MidstateVmessKdf.Kdf12(_cmdKey, NonceLabel, _authId, _nonce, _iv);
        return (byte)(_key[0] ^ _iv[0]);
    }

    // === A single one-element derivation: five per connection ===

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("SingleElementKdf")]
    public byte Single_PlatformIncrementalHash()
    {
        VmessKdf.Kdf16(_cmdKey, AuthIdLabel, _key);
        return _key[0];
    }

    [Benchmark]
    [BenchmarkCategory("SingleElementKdf")]
    public byte Single_MidstateSeedHmac()
    {
        MidstateVmessKdf.Kdf16(_cmdKey, AuthIdLabel, _key);
        return _key[0];
    }
}

/// <summary>
/// HMAC-SHA256 keyed by the constant VMessAEAD KDF seed, with the ipad and opad blocks folded
/// into precomputed SHA-256 midstates. Benchmark-only: see <see cref="VmessKdfBenchmark"/>.
/// </summary>
internal static class MidstateSeedHmac
{
    internal const int DigestSize = Sha256Core.DigestSize;
    internal const int BlockSize = Sha256Core.BlockSize;

    private static ReadOnlySpan<byte> Seed => "VMess AEAD KDF"u8;

    // SHA-256 state after compressing (seed ‖ zeros) ⊕ ipad and ⊕ opad respectively. Derived
    // from the seed rather than pasted in as literals, so a typo cannot change the protocol.
    private static readonly uint[] InnerMidstate = PadMidstate(0x36);
    private static readonly uint[] OuterMidstate = PadMidstate(0x5C);

    private static uint[] PadMidstate(byte pad)
    {
        Span<byte> block = stackalloc byte[BlockSize];
        block.Clear();
        Seed.CopyTo(block);
        for (int i = 0; i < BlockSize; i++)
            block[i] ^= pad;

        uint[] state = new uint[Sha256Core.StateWords];
        Sha256Core.Sha256Iv.CopyTo(state);

        Span<uint> schedule = stackalloc uint[Sha256Core.ScheduleWords];
        Sha256Core.Absorb(state, block, schedule, Vector128.IsHardwareAccelerated);
        return state;
    }

    /// <summary>
    /// Loads the inner (ipad) midstate and absorbs <paramref name="prefixBlocks"/> — whole
    /// 64-byte blocks the caller knows will lead every message it is about to hash.
    /// </summary>
    internal static void BeginInner(Span<uint> state, ReadOnlySpan<byte> prefixBlocks, Span<uint> schedule)
    {
        InnerMidstate.CopyTo(state);
        Sha256Core.Absorb(state, prefixBlocks, schedule, Vector128.IsHardwareAccelerated);
    }

    /// <summary>
    /// Completes <c>HMAC(seed, prefix ‖ tail)</c> from a state produced by
    /// <see cref="BeginInner"/> that has already absorbed <paramref name="absorbedBytes"/>.
    /// </summary>
    internal static void FinishFromPrefix(
        ReadOnlySpan<uint> innerState, ulong absorbedBytes, ReadOnlySpan<byte> tail,
        Span<byte> destination, Span<uint> schedule)
    {
        bool vectorize = Vector128.IsHardwareAccelerated;

        Span<uint> state = stackalloc uint[Sha256Core.StateWords];
        innerState.CopyTo(state);
        Sha256Core.Finish(state, tail, absorbedBytes + (ulong)tail.Length, schedule, vectorize);

        Span<byte> innerDigest = stackalloc byte[DigestSize];
        Sha256Core.WriteDigest(state, innerDigest, DigestSize);

        // Outer pass: resume from the opad midstate and absorb only the 32-byte inner digest,
        // which pads into a single block.
        OuterMidstate.CopyTo(state);
        Sha256Core.Finish(state, innerDigest, BlockSize + (ulong)DigestSize, schedule, vectorize);
        Sha256Core.WriteDigest(state, destination, DigestSize);
    }

    internal static void ComputeHash(ReadOnlySpan<byte> message, Span<byte> destination)
    {
        Span<uint> schedule = stackalloc uint[Sha256Core.ScheduleWords];
        Span<uint> state = stackalloc uint[Sha256Core.StateWords];
        InnerMidstate.CopyTo(state);
        FinishFromPrefix(state, BlockSize, message, destination, schedule);
    }
}

/// <summary>
/// The VMessAEAD KDF with every constant prefix folded into a resumable SHA-256 midstate:
/// the seed's ipad/opad blocks (static) and the innermost path element's ipad/opad blocks
/// (constant for one derivation). Cuts a four-element derivation from 46 block compressions
/// to 24. Benchmark-only reference implementation — see <see cref="VmessKdfBenchmark"/> for
/// why it is not the shipping one.
/// </summary>
internal static class MidstateVmessKdf
{
    private const int BlockSize = Sha256Core.BlockSize;
    private const int DigestSize = Sha256Core.DigestSize;
    private const int StateWords = Sha256Core.StateWords;
    private const int PadPairSize = 2 * BlockSize;
    private const int MaxLevels = 3;
    private const int MaxStackInput = 256;

    public static void Kdf16(ReadOnlySpan<byte> key, ReadOnlySpan<byte> label, Span<byte> destination)
        => Derive(key, label, default, default, levels: 1, destination, 16);

    public static void Kdf16(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2, Span<byte> destination)
        => Derive(key, label, arg1, arg2, levels: 3, destination, 16);

    public static void Kdf12(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2, Span<byte> destination)
        => Derive(key, label, arg1, arg2, levels: 3, destination, 12);

    private static void Derive(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> label, ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2,
        int levels, Span<byte> destination, int length)
    {
        // One message-schedule scratch buffer for the whole derivation: a derivation drives
        // ~20 block-compression entry points, and a stackalloc each would pay 256 bytes of
        // implicit zeroing every time.
        Span<uint> schedule = stackalloc uint[Sha256Core.ScheduleWords];

        Span<byte> pads = stackalloc byte[MaxLevels * PadPairSize];
        InitLevel(pads, default, 0, label, schedule);

        // The innermost level folded into two resumable seed-HMAC midstates: one that has
        // absorbed ipadSeed ‖ labelIpad, one that has absorbed ipadSeed ‖ labelOpad.
        Span<uint> labelStates = stackalloc uint[2 * StateWords];
        MidstateSeedHmac.BeginInner(labelStates[..StateWords], pads[..BlockSize], schedule);
        MidstateSeedHmac.BeginInner(labelStates[StateWords..], pads.Slice(BlockSize, BlockSize), schedule);

        if (levels == 3)
        {
            InitLevel(pads, labelStates, 1, arg1, schedule);
            InitLevel(pads, labelStates, 2, arg2, schedule);
        }

        Span<byte> full = stackalloc byte[DigestSize];
        Compute(pads, labelStates, levels, key, full, schedule);
        full[..length].CopyTo(destination[..length]);

        CryptographicOperations.ZeroMemory(full);
        CryptographicOperations.ZeroMemory(pads);
        labelStates.Clear();
    }

    private static void InitLevel(
        Span<byte> pads, ReadOnlySpan<uint> labelStates, int level, ReadOnlySpan<byte> key,
        Span<uint> schedule)
    {
        Span<byte> normalizedKey = stackalloc byte[BlockSize];
        normalizedKey.Clear();

        if (key.Length > BlockSize)
            Compute(pads, labelStates, level, key, normalizedKey[..DigestSize], schedule);
        else
            key.CopyTo(normalizedKey);

        Xor(normalizedKey, 0x36, pads.Slice(level * PadPairSize, BlockSize));
        Xor(normalizedKey, 0x5C, pads.Slice(level * PadPairSize + BlockSize, BlockSize));

        CryptographicOperations.ZeroMemory(normalizedKey);
    }

    // XORs a whole 64-byte HMAC pad in eight 64-bit chunks instead of byte by byte.
    private static void Xor(ReadOnlySpan<byte> source, byte pad, Span<byte> destination)
    {
        ulong mask = pad * 0x0101010101010101UL;
        for (int i = 0; i < BlockSize; i += 8)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                destination.Slice(i, 8),
                BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(i, 8)) ^ mask);
        }
    }

    private static void Compute(
        ReadOnlySpan<byte> pads, ReadOnlySpan<uint> labelStates, int levels,
        ReadOnlySpan<byte> message, Span<byte> destination, Span<uint> schedule)
    {
        if (levels <= 1)
        {
            if (levels == 0)
            {
                // Bare seed HMAC: only reached from InitLevel's oversized-key fallback for
                // level 0, i.e. before the label midstates exist.
                MidstateSeedHmac.ComputeHash(message, destination);
                return;
            }

            // Level 0's pads are already folded into labelStates, so both passes resume from
            // a midstate that has absorbed 2 blocks and need no concatenation buffer at all.
            Span<byte> level0Digest = stackalloc byte[DigestSize];
            MidstateSeedHmac.FinishFromPrefix(
                labelStates[..StateWords], 2 * BlockSize, message, level0Digest, schedule);
            MidstateSeedHmac.FinishFromPrefix(
                labelStates[StateWords..], 2 * BlockSize, level0Digest, destination, schedule);

            CryptographicOperations.ZeroMemory(level0Digest);
            return;
        }

        int top = levels - 1;
        ReadOnlySpan<byte> innerPad = pads.Slice(top * PadPairSize, BlockSize);
        ReadOnlySpan<byte> outerPad = pads.Slice(top * PadPairSize + BlockSize, BlockSize);

        Span<byte> innerDigest = stackalloc byte[DigestSize];
        int innerLength = BlockSize + message.Length;
        byte[] rented = innerLength > MaxStackInput ? ArrayPool<byte>.Shared.Rent(innerLength) : Array.Empty<byte>();
        Span<byte> innerInput = rented.Length != 0 ? rented : stackalloc byte[MaxStackInput];
        try
        {
            innerPad.CopyTo(innerInput);
            message.CopyTo(innerInput[BlockSize..]);
            Compute(pads, labelStates, top, innerInput[..innerLength], innerDigest, schedule);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(innerInput[..innerLength]);
            if (rented.Length != 0)
                ArrayPool<byte>.Shared.Return(rented);
        }

        Span<byte> outerInput = stackalloc byte[BlockSize + DigestSize];
        outerPad.CopyTo(outerInput);
        innerDigest.CopyTo(outerInput[BlockSize..]);
        Compute(pads, labelStates, top, outerInput, destination, schedule);

        CryptographicOperations.ZeroMemory(innerDigest);
        CryptographicOperations.ZeroMemory(outerInput);
    }
}
