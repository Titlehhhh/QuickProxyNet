using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet.Reality.Managed;

/// <summary>
/// The TLS 1.3 key schedule (RFC 8446 §7.1) and its traffic-key derivation (§7.3).
/// </summary>
/// <remarks>
/// Nothing here is REALITY-specific — it is the ordinary TLS 1.3 schedule, which is exactly why
/// it can be tested against RFC 8448's published traces rather than against our own expectations.
/// Every method is a pure function of its inputs.
/// </remarks>
internal static class TlsKeySchedule
{
    /// <summary>The <c>"tls13 "</c> prefix every HkdfLabel carries.</summary>
    private static ReadOnlySpan<byte> LabelPrefix => "tls13 "u8;

    /// <summary>HKDF-Extract.</summary>
    /// <param name="hash">The hash of the negotiated cipher suite.</param>
    /// <param name="salt">The salt; an empty span means Hash.length zero bytes.</param>
    /// <param name="inputKeyMaterial">The IKM.</param>
    /// <param name="prk">Receives Hash.length bytes.</param>
    public static void Extract(
        HashAlgorithmName hash, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial, Span<byte> prk) =>
        HKDF.Extract(hash, inputKeyMaterial, salt, prk);

    /// <summary>
    /// HKDF-Expand-Label: <c>HKDF-Expand(secret, HkdfLabel, output.Length)</c>.
    /// </summary>
    /// <param name="hash">The hash of the negotiated cipher suite.</param>
    /// <param name="secret">The secret to expand.</param>
    /// <param name="label">The label, without the <c>tls13 </c> prefix.</param>
    /// <param name="context">The context — usually a transcript hash, sometimes empty.</param>
    /// <param name="output">Receives the expanded key material; its length is encoded into the label.</param>
    public static void ExpandLabel(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        Span<byte> output)
    {
        // HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
        int labelLength = LabelPrefix.Length + label.Length;
        Span<byte> info = stackalloc byte[2 + 1 + labelLength + 1 + context.Length];

        info[0] = (byte)(output.Length >> 8);
        info[1] = (byte)output.Length;
        info[2] = (byte)labelLength;
        LabelPrefix.CopyTo(info[3..]);
        label.CopyTo(info[(3 + LabelPrefix.Length)..]);
        info[3 + labelLength] = (byte)context.Length;
        context.CopyTo(info[(4 + labelLength)..]);

        HKDF.Expand(hash, secret, output, info);
    }

    /// <summary>
    /// Derive-Secret: <see cref="ExpandLabel"/> with a transcript hash as the context.
    /// </summary>
    /// <param name="hash">The hash of the negotiated cipher suite.</param>
    /// <param name="secret">The secret to derive from.</param>
    /// <param name="label">The label, without the <c>tls13 </c> prefix.</param>
    /// <param name="transcriptHash">The hash of the handshake messages so far.</param>
    /// <param name="output">Receives Hash.length bytes.</param>
    public static void DeriveSecret(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> transcriptHash,
        Span<byte> output) =>
        ExpandLabel(hash, secret, label, transcriptHash, output);

    /// <summary>Derives the record-protection key and IV for a traffic secret (RFC 8446 §7.3).</summary>
    /// <param name="hash">The hash of the negotiated cipher suite.</param>
    /// <param name="trafficSecret">The traffic secret.</param>
    /// <param name="key">Receives the AEAD key.</param>
    /// <param name="iv">Receives the 12-byte static IV.</param>
    public static void TrafficKeys(
        HashAlgorithmName hash, ReadOnlySpan<byte> trafficSecret, Span<byte> key, Span<byte> iv)
    {
        ExpandLabel(hash, trafficSecret, "key"u8, default, key);
        ExpandLabel(hash, trafficSecret, "iv"u8, default, iv);
    }

    /// <summary>
    /// Computes a Finished message's verify_data (RFC 8446 §4.4.4).
    /// </summary>
    /// <param name="hash">The hash of the negotiated cipher suite.</param>
    /// <param name="baseKey">The sender's handshake traffic secret.</param>
    /// <param name="transcriptHash">The transcript hash up to but excluding this Finished.</param>
    /// <param name="verifyData">Receives Hash.length bytes.</param>
    public static void FinishedVerifyData(
        HashAlgorithmName hash, ReadOnlySpan<byte> baseKey, ReadOnlySpan<byte> transcriptHash, Span<byte> verifyData)
    {
        Span<byte> finishedKey = stackalloc byte[verifyData.Length];
        try
        {
            ExpandLabel(hash, baseKey, "finished"u8, default, finishedKey);

            if (hash == HashAlgorithmName.SHA384)
                HMACSHA384.HashData(finishedKey, transcriptHash, verifyData);
            else
                HMACSHA256.HashData(finishedKey, transcriptHash, verifyData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(finishedKey);
        }
    }

    /// <summary>
    /// Builds the per-record nonce: the static IV xored with the sequence number, right-aligned
    /// (RFC 8446 §5.3).
    /// </summary>
    /// <param name="nonce">Receives the 12-byte nonce.</param>
    /// <param name="iv">The static IV from <see cref="TrafficKeys"/>.</param>
    /// <param name="sequenceNumber">The record sequence number, which starts at zero per key.</param>
    public static void BuildNonce(Span<byte> nonce, ReadOnlySpan<byte> iv, ulong sequenceNumber)
    {
        iv.CopyTo(nonce);

        for (int i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(sequenceNumber >> (8 * i));
    }

    /// <summary>Converts a label to bytes; for callers that do not have a UTF-8 literal.</summary>
    public static byte[] Label(string label) => Encoding.ASCII.GetBytes(label);
}
