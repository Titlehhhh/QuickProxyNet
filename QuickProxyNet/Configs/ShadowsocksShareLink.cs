using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// Parses <c>ss://</c> share links into <see cref="ShadowsocksOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Two grammars exist in the wild and both are handled:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Legacy</b> — <c>ss://base64(method:password@host:port)#tag</c>. The whole authority is one
/// base64 blob; the <c>#tag</c> sits outside it.
/// </description></item>
/// <item><description>
/// <b>SIP002</b> — <c>ss://userinfo@host:port[/][?plugin=…][#tag]</c>, where <c>userinfo</c> is
/// either base64 of <c>method:password</c> (URL-safe or standard alphabet, padding optional, padding
/// sometimes percent-encoded as <c>%3D</c>) or the literal <c>method:password</c>, percent-encoded.
/// The two are told apart the way shadowsocks-rust and v2rayN do: percent-decode first; a
/// <c>':'</c> in the result means plain text.
/// </description></item>
/// </list>
/// <para>
/// The authority is scanned by hand rather than through <see cref="Uri"/>: a standard-alphabet
/// base64 userinfo may contain <c>/</c>, which <see cref="Uri"/> would read as the start of the
/// path. A missing port defaults to <c>8388</c>. The query is scanned with
/// <see cref="ShareLinkQuery.StripHtmlAmpPrefix"/> so a <c>plugin=</c> cannot hide behind an
/// HTML-escaped <c>&amp;amp;</c> and be dropped as an unknown key — that would connect as plain
/// Shadowsocks to a server expecting an obfuscated stream.
/// </para>
/// <para>
/// Parsing accepts any cipher name and any plugin; <see cref="ShadowsocksClient"/> rejects the
/// unsupported ones by name. SIP008 JSON subscriptions are not a URI and are not handled here.
/// </para>
/// </remarks>
public static class ShadowsocksShareLink
{
    /// <summary>The port a share link without one means: <c>8388</c>.</summary>
    public const int DefaultPort = 8388;

    private const string Scheme = "ss://";

    /// <summary>
    /// Parses an <c>ss://</c> share link.
    /// </summary>
    /// <exception cref="FormatException">The link is malformed.</exception>
    public static ShadowsocksOptions Parse(string shareLink)
    {
        if (!TryParse(shareLink, out var options, out var error))
            throw new FormatException(error);
        return options;
    }

    /// <summary>
    /// Attempts to parse an <c>ss://</c> share link, returning <see langword="false"/> instead
    /// of throwing on malformed input.
    /// </summary>
    public static bool TryParse(string shareLink, [NotNullWhen(true)] out ShadowsocksOptions? options)
        => TryParse(shareLink, out options, out _);

    private static bool TryParse(
        string shareLink,
        [NotNullWhen(true)] out ShadowsocksOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        if (string.IsNullOrWhiteSpace(shareLink))
        {
            error = "Shadowsocks share link is empty.";
            return false;
        }

        string trimmed = shareLink.Trim();
        if (!trimmed.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            error = "Shadowsocks share link must start with 'ss://'.";
            return false;
        }

        ReadOnlySpan<char> body = trimmed.AsSpan(Scheme.Length);

        // '#tag' is outside both grammars' payload and is percent-encoded.
        string? remark = null;
        int hash = body.IndexOf('#');
        if (hash >= 0)
        {
            ReadOnlySpan<char> fragment = body.Slice(hash + 1);
            remark = fragment.IsEmpty ? null : Uri.UnescapeDataString(fragment.ToString());
            body = body.Slice(0, hash);
        }

        // Neither base64 alphabet contains '?', and a plain userinfo must percent-encode one.
        ReadOnlySpan<char> query = default;
        int question = body.IndexOf('?');
        if (question >= 0)
        {
            query = body.Slice(question + 1);
            body = body.Slice(0, question);
        }

        string method, password, host;
        int port;

        // Neither base64 alphabet contains '@' either, so its presence decides the grammar.
        // The LAST '@' separates userinfo from host: a base64 userinfo has none, a plain one
        // must encode a literal '@' as %40.
        int at = body.LastIndexOf('@');
        if (at < 0)
        {
            if (!TryParseLegacy(body, out method, out password, out host, out port, out error))
                return false;
        }
        else
        {
            ReadOnlySpan<char> hostPort = body.Slice(at + 1);
            int slash = hostPort.IndexOf('/');
            if (slash >= 0)
                hostPort = hostPort.Slice(0, slash); // the optional trailing '/' (path)

            if (!TryDecodeUserInfo(body.Slice(0, at), out method, out password, out error))
                return false;
            if (!TryParseHostPort(hostPort, out host, out port, out error))
                return false;
        }

        if (method.Length == 0)
        {
            error = "Shadowsocks share link is missing the cipher name (the 'method' before ':').";
            return false;
        }

        if (password.Length == 0)
        {
            error = "Shadowsocks share link is missing the password.";
            return false;
        }

        string? plugin = null;
        while (!query.IsEmpty)
        {
            int amp = query.IndexOf('&');
            ReadOnlySpan<char> pair = amp < 0 ? query : query.Slice(0, amp);
            query = amp < 0 ? default : query.Slice(amp + 1);

            int eq = pair.IndexOf('=');
            if (eq < 0)
                continue;

            ReadOnlySpan<char> key = ShareLinkQuery.StripHtmlAmpPrefix(pair.Slice(0, eq));
            ReadOnlySpan<char> rawVal = pair.Slice(eq + 1);
            if (rawVal.IsEmpty)
                continue;

            if (key.Equals("plugin", StringComparison.OrdinalIgnoreCase))
                plugin = Decode(rawVal);
        }

        options = new ShadowsocksOptions
        {
            Method = method,
            Password = password,
            Host = host,
            Port = port,
            Plugin = plugin,
            Remark = remark
        };
        error = null;
        return true;
    }

    // Legacy form: the whole body is base64(method:password@host:port), possibly followed by a
    // '/' that some producers append. A standard-alphabet blob can legitimately END in '/', so the
    // untrimmed text is tried first and the trailing slashes are only dropped if that fails.
    private static bool TryParseLegacy(
        ReadOnlySpan<char> body,
        out string method, out string password, out string host, out int port,
        [NotNullWhen(false)] out string? error)
    {
        method = password = host = string.Empty;
        port = 0;
        error = null;

        if (TryDecodeBase64Utf8(body, out DecodedText text))
        {
            using (text)
            {
                if (TrySplitLegacy(text.Span, out method, out password, out host, out port, out error))
                    return true;
            }
        }

        ReadOnlySpan<char> trimmed = body.TrimEnd('/');
        if (trimmed.Length != body.Length && TryDecodeBase64Utf8(trimmed, out text))
        {
            using (text)
            {
                if (TrySplitLegacy(text.Span, out method, out password, out host, out port, out error))
                    return true;
            }
        }

        error ??= "Shadowsocks share link has no '@' and is not base64 of 'method:password@host:port' (the legacy form).";
        return false;
    }

    private static bool TrySplitLegacy(
        ReadOnlySpan<char> text,
        out string method, out string password, out string host, out int port,
        [NotNullWhen(false)] out string? error)
    {
        method = password = host = string.Empty;
        port = 0;

        // A hand-made blob often carries the newline `echo | base64` appended; the outer link was
        // trimmed, this is the decoded text. Only the ends go, so a password keeps its own spaces.
        text = text.Trim();

        // The password is raw here and may itself contain '@' — the host follows the LAST one.
        int at = text.LastIndexOf('@');
        if (at < 0)
        {
            error = "Shadowsocks legacy share link decodes to text without '@' between the credentials and the host.";
            return false;
        }

        int colon = text.IndexOf(':');
        if (colon < 0 || colon > at)
        {
            error = "Shadowsocks legacy share link decodes to text without ':' between the cipher name and the password.";
            return false;
        }

        method = text.Slice(0, colon).ToString();
        password = text.Slice(colon + 1, at - colon - 1).ToString();
        return TryParseHostPort(text.Slice(at + 1), out host, out port, out error);
    }

    // SIP002 userinfo: percent-decode, then ':' means plain 'method:password'; otherwise base64.
    // Percent-decoding needs a string; without a '%' (the common case) the span is split as is.
    private static bool TryDecodeUserInfo(
        ReadOnlySpan<char> userInfo,
        out string method, out string password,
        [NotNullWhen(false)] out string? error)
    {
        method = password = string.Empty;

        if (userInfo.IsEmpty)
        {
            error = "Shadowsocks share link is missing the userinfo (cipher name and password) before '@'.";
            return false;
        }

        if (userInfo.IndexOf('%') < 0)
            return TrySplitUserInfo(userInfo, out method, out password, out error);

        return TrySplitUserInfo(Uri.UnescapeDataString(userInfo.ToString()), out method, out password, out error);
    }

    private static bool TrySplitUserInfo(
        ReadOnlySpan<char> decoded,
        out string method, out string password,
        [NotNullWhen(false)] out string? error)
    {
        method = password = string.Empty;

        int colon = decoded.IndexOf(':');
        if (colon >= 0)
        {
            method = decoded.Slice(0, colon).ToString();
            password = decoded.Slice(colon + 1).ToString();
            error = null;
            return true;
        }

        if (!TryDecodeBase64Utf8(decoded, out DecodedText text))
        {
            error = "Shadowsocks share link userinfo is neither base64 nor a percent-encoded 'method:password'.";
            return false;
        }

        using (text)
        {
            ReadOnlySpan<char> plain = text.Span;
            colon = plain.IndexOf(':');
            if (colon < 0)
            {
                error = "Shadowsocks share link userinfo decodes to text without ':' between the cipher name and the password.";
                return false;
            }

            method = plain.Slice(0, colon).ToString();
            password = plain.Slice(colon + 1).ToString();
            error = null;
            return true;
        }
    }

    // host[:port], with a bracketed IPv6 literal allowed. Port defaults to 8388.
    private static bool TryParseHostPort(
        ReadOnlySpan<char> hostPort,
        out string host, out int port,
        [NotNullWhen(false)] out string? error)
    {
        host = string.Empty;
        port = DefaultPort;

        if (hostPort.IsEmpty)
        {
            error = "Shadowsocks share link is missing the server host.";
            return false;
        }

        ReadOnlySpan<char> portText = default;
        if (hostPort[0] == '[')
        {
            int close = hostPort.IndexOf(']');
            if (close < 0)
            {
                error = "Shadowsocks share link has an unterminated '[' in the server host.";
                return false;
            }

            // Uri.Host would keep the brackets; the raw address is what the socket needs.
            host = hostPort.Slice(1, close - 1).ToString();
            ReadOnlySpan<char> rest = hostPort.Slice(close + 1);
            if (!rest.IsEmpty)
            {
                if (rest[0] != ':')
                {
                    error = "Shadowsocks share link has stray characters after the bracketed IPv6 host.";
                    return false;
                }

                portText = rest.Slice(1);
            }
        }
        else
        {
            int colon = hostPort.LastIndexOf(':');
            if (colon >= 0 && hostPort.IndexOf(':') != colon)
            {
                // More than one ':' without brackets. '2001:db8::1:9000' is a valid IPv6 address
                // AND almost certainly meant '[2001:db8::1]:9000'; there is no reading that does
                // not guess, so — like Uri and the url crate shadowsocks-rust parses with — refuse.
                error = "Shadowsocks share link has an IPv6 server host that is not bracketed; write it as '[addr]:port'.";
                return false;
            }

            if (colon >= 0)
            {
                host = hostPort.Slice(0, colon).ToString();
                portText = hostPort.Slice(colon + 1);
            }
            else
            {
                host = hostPort.ToString();
            }
        }

        if (host.Length == 0)
        {
            error = "Shadowsocks share link is missing the server host.";
            return false;
        }

        if (!portText.IsEmpty)
        {
            if (!int.TryParse(portText, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out port) ||
                port <= 0 || port > 65535)
            {
                error = "Shadowsocks share link does not have a valid server port.";
                return false;
            }
        }

        error = null;
        return true;
    }

    // Decodes base64 in either alphabet, with or without padding, into UTF-8 text held in a
    // pooled buffer the caller disposes. The text is decoded into the same char[] that held the
    // normalized base64 — the UTF-8 char count never exceeds the byte count, which never exceeds
    // the base64 length — so the only strings built are the final method, password and host.
    private static bool TryDecodeBase64Utf8(ReadOnlySpan<char> payload, out DecodedText text)
    {
        text = default;
        if (payload.IsEmpty)
            return false;

        // Padding may add up to 3 characters to the normalized form.
        char[] chars = ArrayPool<char>.Shared.Rent(payload.Length + 3);
        byte[] bytes = ArrayPool<byte>.Shared.Rent(payload.Length); // decoded is always shorter
        int length = 0;
        int decoded = 0;
        bool handedOver = false;
        try
        {
            for (int i = 0; i < payload.Length; i++)
            {
                char c = payload[i];
                if (char.IsWhiteSpace(c))
                    continue;

                chars[length++] = c switch
                {
                    '-' => '+',
                    '_' => '/',
                    _ => c
                };
            }

            int remainder = length % 4;
            if (remainder == 1)
                return false; // no base64 string has this length

            for (int i = remainder; remainder != 0 && i < 4; i++)
                chars[length++] = '=';

            if (!Convert.TryFromBase64Chars(chars.AsSpan(0, length), bytes, out decoded) || decoded == 0)
                return false;

            int textLength = Encoding.UTF8.GetChars(bytes.AsSpan(0, decoded), chars);
            text = new DecodedText(chars, textLength, length);
            handedOver = true;
            return true;
        }
        finally
        {
            // Both may have held the password; only the bytes actually written need clearing.
            Array.Clear(bytes, 0, decoded);
            ArrayPool<byte>.Shared.Return(bytes);
            if (!handedOver)
            {
                Array.Clear(chars, 0, length);
                ArrayPool<char>.Shared.Return(chars);
            }
        }
    }

    /// <summary>
    /// Decoded text in a pooled <c>char[]</c>: <see cref="Span"/> is the text, <see cref="Dispose"/>
    /// clears every character the buffer was written with (the text and the base64 it came from)
    /// and returns the array.
    /// </summary>
    private readonly struct DecodedText(char[] rented, int length, int dirtyLength) : IDisposable
    {
        public ReadOnlySpan<char> Span => rented.AsSpan(0, length);

        public void Dispose()
        {
            if (rented is null)
                return;

            Array.Clear(rented, 0, Math.Max(length, dirtyLength));
            ArrayPool<char>.Shared.Return(rented);
        }
    }

    private static string Decode(ReadOnlySpan<char> value)
    {
        // Only pay for unescaping when the value actually contains an escape.
        return value.IndexOf('%') < 0 ? value.ToString() : Uri.UnescapeDataString(value.ToString());
    }
}
