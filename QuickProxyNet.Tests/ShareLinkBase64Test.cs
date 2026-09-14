namespace QuickProxyNet.Tests;

/// <summary>
/// What <see cref="ShareLinkBase64"/> turns share-link base64 into must decode identically on
/// .NET 10 and .NET 11, including the case where they disagree: unused bits set in the last
/// character, which .NET 10 ignores, .NET 11 rejects, and Go's decoder accepts.
/// </summary>
public class ShareLinkBase64Test
{
    private static byte[]? Decode(string text)
    {
        char[] chars = new char[text.Length + 3];
        byte[] bytes = new byte[text.Length + 3];
        return ShareLinkBase64.TryNormalize(text, chars, out int length)
               && Convert.TryFromBase64Chars(chars.AsSpan(0, length), bytes, out int written)
            ? bytes[..written]
            : null;
    }

    [Theory]
    [InlineData("YQ==", "61")]
    [InlineData("YR==", "61")] // the 4 unused bits before "==" set
    [InlineData("YR", "61")] // the same, unpadded
    [InlineData("YWI=", "6162")]
    [InlineData("YWJ=", "6162")] // the 2 unused bits before "=" set
    [InlineData("YWJ", "6162")]
    [InlineData("YWJj", "616263")]
    [InlineData("P/8+", "3fff3e")]
    [InlineData("P_8-", "3fff3e")] // url-safe alphabet
    [InlineData("YW\r\nJj ", "616263")] // whitespace, as a wrapped or `echo | base64` blob has
    public void Decodes_WhatShareLinksCarry(string text, string hex)
    {
        Assert.Equal(Convert.FromHexString(hex), Decode(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" \t")]
    [InlineData("Y")] // no base64 text is one character past a whole group
    [InlineData("YWJjZ")]
    [InlineData("Y*==")]
    public void Refuses_WhatIsNotBase64(string text)
    {
        Assert.Null(Decode(text));
    }
}
