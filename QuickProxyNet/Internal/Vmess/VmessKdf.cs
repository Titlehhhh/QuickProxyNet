using System.Buffers;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// The VMessAEAD key-derivation function: a <b>nested / recursive HMAC-SHA256</b>
/// construction (<c>proxy/vmess/aead/kdf.go</c>). The innermost HMAC is keyed by the
/// ASCII seed <c>"VMess AEAD KDF"</c> over plain SHA-256; each subsequent path element
/// becomes the key of an HMAC whose <em>underlying hash function is the previous HMAC</em>.
/// The final HMAC hashes the supplied <c>key</c> (the 16-byte cmdKey) and produces
/// 32 bytes; the <c>Kdf16</c> overloads keep the first 16, the <c>Kdf12</c> overloads
/// the first 12.
/// </summary>
/// <remarks>
/// <para>
/// A plain <see cref="HMACSHA256"/> cannot express "an HMAC whose hash function is
/// another HMAC", so the generic RFC 2104 construction (block size 64, ipad <c>0x36</c>,
/// opad <c>0x5C</c>, keys longer than the block pre-hashed) is implemented by hand for
/// every level <em>above</em> the innermost one. The innermost level — HMAC-SHA256 keyed
/// by the constant seed — <b>is</b> a standard HMAC, so it is delegated to the one-shot
/// <see cref="HMACSHA256.HashData(ReadOnlySpan{byte},ReadOnlySpan{byte},Span{byte})"/>,
/// which is allocation-free and lets the platform run its own optimized HMAC instead of
/// two separate SHA-256 passes.
/// </para>
/// <para>
/// Evaluating an HMAC at level <c>n</c> requires two evaluations of level <c>n−1</c>
/// (inner and outer pass), so a chain of <c>n</c> levels above the base costs
/// <c>2^n</c> base HMAC computations — 8 for the four-element request-header
/// derivations. This fan-out is inherent to the construction. The implementation
/// therefore focuses on what <em>can</em> be fixed: it performs no heap allocations at
/// all (all pads and scratch live on the stack; a pooled buffer is used only in the
/// never-hit oversized-key fallback) and halves the number of platform-crypto calls via
/// the one-shot base HMAC.
/// </para>
/// <para>
/// <b>Do not replace the base HMAC with a hand-rolled midstate one. This was built and
/// measured, and it lost.</b> The seed is a constant, so its ipad/opad blocks can be
/// pre-hashed into SHA-256 midstates — which the platform cannot do, since neither
/// <see cref="HMACSHA256"/> nor <see cref="IncrementalHash"/> exports a chaining state.
/// Folding both the seed pads <em>and</em> the (per-derivation constant) innermost path
/// element into resumable midstates cuts a four-element derivation from 46 block
/// compressions to 24. It still does not pay, because the premise that the platform call
/// is dominated by CNG round-trip overhead is wrong: <see cref="IncrementalHash"/> costs
/// ~200 ns per 64-byte block here, i.e. it is compression-bound, while the managed
/// <see cref="Sha256Core"/> costs ~312 ns per block — 1.58x more. Halving the block count
/// only just cancels the per-block penalty. Measured interleaved on an Intel Xeon E5-2697
/// v4 (Broadwell, no SHA-NI): the four request-header derivations went 37.2 µs -> 34.7 µs
/// (0.94x), but a single one-element derivation went 1.93 µs -> 2.31 µs (1.20x), because
/// its fixed setup is amortized over far fewer blocks. A real connection does five
/// one-element derivations (<c>VmessAuthId</c> plus four in <c>VmessResponse</c>) and four
/// three-element ones, so the two effects cancel to about 1%. On a CPU with SHA-NI the
/// platform side gets faster still and the trade gets worse. <c>VmessKdfBenchmark</c> keeps
/// the midstate variant so the comparison can be re-run on other hardware.
/// </para>
/// </remarks>
internal static class VmessKdf
{
    private const int BlockSize = 64;
    private const int DigestSize = 32;

    // A level's precomputed pads: [K' XOR ipad (64)][K' XOR opad (64)].
    private const int PadPairSize = 2 * BlockSize;

    // The deepest chain VMess uses: label, arg1 (authid), arg2 (connection nonce).
    private const int MaxLevels = 3;

    // Largest ipad-concat input kept on the stack. The deepest VMess evaluation needs
    // 64 + 64 + 64 + 16 = 208 bytes; anything larger falls back to the pool.
    private const int MaxStackInput = 256;

    // ASCII seed that keys the innermost HMAC (verbatim from aead/consts.go).
    private static ReadOnlySpan<byte> Seed => "VMess AEAD KDF"u8;

    // Persistent seed-keyed HMAC-SHA256, one per thread. The seed is a public protocol
    // constant, so keeping the keyed state alive holds no secret material; reusing it
    // skips the per-call key import that HMACSHA256.HashData would repeat.
    [ThreadStatic]
    private static IncrementalHash? t_baseHmac;

    // ---- single path element (response-header + auth-id labels) ----

    /// <summary>
    /// Writes the first 16 bytes of <c>KDF(key, label)</c> into <paramref name="destination"/>.
    /// </summary>
    public static void Kdf16(ReadOnlySpan<byte> key, ReadOnlySpan<byte> label, Span<byte> destination)
        => Derive(key, label, default, default, levels: 1, destination, 16);

    /// <summary>
    /// Writes the first 12 bytes of <c>KDF(key, label)</c> into <paramref name="destination"/>.
    /// </summary>
    public static void Kdf12(ReadOnlySpan<byte> key, ReadOnlySpan<byte> label, Span<byte> destination)
        => Derive(key, label, default, default, levels: 1, destination, 12);

    // ---- three path elements (request-header labels: label ‖ authid ‖ nonce) ----

    /// <summary>
    /// Writes the first 16 bytes of <c>KDF(key, label, arg1, arg2)</c> into
    /// <paramref name="destination"/>. Used for the request-header key derivations
    /// where <paramref name="arg1"/> is the auth-id and <paramref name="arg2"/> the
    /// connection nonce.
    /// </summary>
    public static void Kdf16(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2, Span<byte> destination)
        => Derive(key, label, arg1, arg2, levels: 3, destination, 16);

    /// <summary>
    /// Writes the first 12 bytes of <c>KDF(key, label, arg1, arg2)</c> into
    /// <paramref name="destination"/> (request-header nonce derivations).
    /// </summary>
    public static void Kdf12(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2, Span<byte> destination)
        => Derive(key, label, arg1, arg2, levels: 3, destination, 12);

    private static void Derive(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> label, ReadOnlySpan<byte> arg1, ReadOnlySpan<byte> arg2,
        int levels, Span<byte> destination, int length)
    {
        if (destination.Length < length)
            throw new ArgumentException($"Destination must be at least {length} bytes.", nameof(destination));

        // Path order matters: label wraps the seed first (level 0), then arg1, then
        // arg2 (outermost). Pads for all levels live in one stack buffer.
        Span<byte> pads = stackalloc byte[MaxLevels * PadPairSize];
        InitLevel(pads, 0, label);
        if (levels == 3)
        {
            InitLevel(pads, 1, arg1);
            InitLevel(pads, 2, arg2);
        }

        Span<byte> full = stackalloc byte[DigestSize];
        Compute(pads, levels, key, full);
        full[..length].CopyTo(destination[..length]);

        CryptographicOperations.ZeroMemory(full);
        CryptographicOperations.ZeroMemory(pads);
    }

    // Precomputes the ipad/opad pair for one manual HMAC level, keyed by that level's
    // path element.
    private static void InitLevel(Span<byte> pads, int level, ReadOnlySpan<byte> key)
    {
        Span<byte> normalizedKey = stackalloc byte[BlockSize];
        normalizedKey.Clear();

        // RFC 2104: keys longer than the block are pre-hashed with the same hash
        // function this HMAC uses — the chain formed by the levels *below* this one.
        // None of the VMess path elements hit this branch, but it is kept for
        // correctness of the generic construction.
        if (key.Length > BlockSize)
            Compute(pads, level, key, normalizedKey[..DigestSize]);
        else
            key.CopyTo(normalizedKey);

        Span<byte> inner = pads.Slice(level * PadPairSize, BlockSize);
        Span<byte> outer = pads.Slice(level * PadPairSize + BlockSize, BlockSize);
        for (int i = 0; i < BlockSize; i++)
        {
            inner[i] = (byte)(normalizedKey[i] ^ 0x36);
            outer[i] = (byte)(normalizedKey[i] ^ 0x5C);
        }

        CryptographicOperations.ZeroMemory(normalizedKey);
    }

    /// <summary>
    /// Computes <c>H(opad ‖ H(ipad ‖ message))</c> for the HMAC formed by the first
    /// <paramref name="levels"/> pad pairs, where level 0's underlying hash function is
    /// the seed-keyed HMAC-SHA256 and each higher level's is the level below it.
    /// </summary>
    private static void Compute(
        ReadOnlySpan<byte> pads, int levels, ReadOnlySpan<byte> message, Span<byte> destination)
    {
        if (levels == 0)
        {
            // The innermost level is a *standard* HMAC-SHA256 keyed by the seed.
            IncrementalHash hmac = t_baseHmac ??=
                IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, Seed);
            hmac.AppendData(message);
            hmac.GetHashAndReset(destination);
            return;
        }

        int top = levels - 1;
        ReadOnlySpan<byte> innerPad = pads.Slice(top * PadPairSize, BlockSize);
        ReadOnlySpan<byte> outerPad = pads.Slice(top * PadPairSize + BlockSize, BlockSize);

        // --- inner pass: H_below(ipad ‖ message) ---
        Span<byte> innerDigest = stackalloc byte[DigestSize];
        int innerLength = BlockSize + message.Length;
        byte[]? rented = innerLength > MaxStackInput ? ArrayPool<byte>.Shared.Rent(innerLength) : null;
        // The recursion is bounded by MaxLevels, so stack use stays small.
        Span<byte> innerInput = rented ?? stackalloc byte[MaxStackInput];
        try
        {
            innerPad.CopyTo(innerInput);
            message.CopyTo(innerInput[BlockSize..]);
            Compute(pads, top, innerInput[..innerLength], innerDigest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(innerInput[..innerLength]);
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }

        // --- outer pass: H_below(opad ‖ innerDigest) ---
        Span<byte> outerInput = stackalloc byte[BlockSize + DigestSize];
        outerPad.CopyTo(outerInput);
        innerDigest.CopyTo(outerInput[BlockSize..]);
        Compute(pads, top, outerInput, destination);

        CryptographicOperations.ZeroMemory(innerDigest);
        CryptographicOperations.ZeroMemory(outerInput);
    }
}
