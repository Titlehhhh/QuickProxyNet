namespace QuickProxyNet;

/// <summary>
/// The base64 share links carry, turned into what <see cref="Convert.TryFromBase64Chars"/>
/// accepts on every target framework.
/// </summary>
/// <remarks>
/// Links use either alphabet, with or without padding, sometimes wrapped with whitespace, and
/// sometimes with bits no decoded byte uses left set in the last character. Go's decoder, which
/// Xray and most producers run, accepts all of that. .NET accepts none of the first three, and the
/// last one depends on the version: .NET 10 ignores those bits, .NET 11 rejects the group. So the
/// same link decoded differently depending on the target it ran on, until the bits were cleared
/// here.
/// </remarks>
internal static class ShareLinkBase64
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>
    /// Writes <paramref name="payload"/> into <paramref name="destination"/> in the standard
    /// alphabet, without whitespace, padded to a whole group, with the unused trailing bits cleared.
    /// </summary>
    /// <param name="payload">The base64 as found in the link.</param>
    /// <param name="destination">At least <c>payload.Length + 3</c> characters.</param>
    /// <param name="length">
    /// The characters written, also when this returns false, so a caller holding a secret can
    /// clear exactly those.
    /// </param>
    /// <returns>False when no base64 text could have this many characters.</returns>
    public static bool TryNormalize(ReadOnlySpan<char> payload, Span<char> destination, out int length)
    {
        length = 0;

        foreach (char c in payload)
        {
            if (char.IsWhiteSpace(c))
                continue;

            destination[length++] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            };
        }

        // Trailing padding may already be present; only top it up to a whole group.
        int remainder = length % 4;
        if (remainder == 1 || length == 0)
            return false;

        for (int i = remainder; remainder != 0 && i < 4; i++)
            destination[length++] = '=';

        ClearUnusedTrailingBits(destination[..length]);
        return true;
    }

    /// <summary>
    /// In a group ending <c>==</c> the last data character carries 4 bits no byte uses; before a
    /// single <c>=</c>, 2. Cleared, the group decodes to the same bytes it did with them set.
    /// </summary>
    private static void ClearUnusedTrailingBits(Span<char> base64)
    {
        if (base64.Length < 4 || base64[^1] != '=')
            return;

        bool twoPads = base64[^2] == '=';
        int index = base64.Length - (twoPads ? 3 : 2);
        int value = Alphabet.IndexOf(base64[index]);
        if (value < 0)
            return; // not base64 at all; the decoder will say so

        base64[index] = Alphabet[value & (twoPads ? ~0x0F : ~0x03)];
    }
}
