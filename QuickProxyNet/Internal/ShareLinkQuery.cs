namespace QuickProxyNet;

/// <summary>
/// Helpers shared by the <c>vless://</c>, <c>trojan://</c> and <c>vmess://</c> query
/// scanners.
/// </summary>
internal static class ShareLinkQuery
{
    /// <summary>
    /// Removes the <c>amp;</c> prefix left on a query key when the whole link was
    /// HTML-escaped before being published.
    /// </summary>
    /// <remarks>
    /// Producers that paste share links into HTML emit <c>&amp;amp;</c> as the parameter
    /// separator. Splitting on <c>&amp;</c> then yields keys such as <c>amp;security</c> and
    /// <c>amp;flow</c>. Ignoring those as "unknown keys" is not harmless: a REALITY node
    /// would parse as <c>security=none</c> with an empty <c>flow</c>, pass the
    /// supported-configuration check, and connect in cleartext — sending the user's UUID
    /// unencrypted to a server expecting a REALITY handshake. That is exactly the silent
    /// downgrade these parsers refuse to make elsewhere.
    /// <para>
    /// 68 <c>vless</c> and 10 <c>trojan</c> links in a 17k real-world corpus arrive this
    /// way, 51 of them REALITY.
    /// </para>
    /// <para>
    /// This is safe to strip unconditionally: a literal <c>&amp;</c> inside a value must be
    /// percent-encoded as <c>%26</c>, so an unescaped <c>&amp;</c> is always a separator.
    /// </para>
    /// </remarks>
    public static ReadOnlySpan<char> StripHtmlAmpPrefix(ReadOnlySpan<char> key)
        => key.StartsWith("amp;", StringComparison.OrdinalIgnoreCase) ? key[4..] : key;
}
