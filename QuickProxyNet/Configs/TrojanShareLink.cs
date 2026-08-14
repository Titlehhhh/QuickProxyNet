using System.Diagnostics.CodeAnalysis;

namespace QuickProxyNet;

/// <summary>
/// Parses <c>trojan://</c> share links into <see cref="TrojanOptions"/>.
/// </summary>
/// <remarks>
/// Grammar: <c>trojan://{password}@{host}:{port}?{query}#{remark}</c>. The query is
/// scanned with a single-pass span parser (no <c>NameValueCollection</c> allocation);
/// only the recognized keys are materialized. Unknown keys are ignored.
/// </remarks>
public static class TrojanShareLink
{
    /// <summary>
    /// Parses a <c>trojan://</c> share link.
    /// </summary>
    /// <exception cref="FormatException">The link is malformed or missing the password.</exception>
    public static TrojanOptions Parse(string shareLink)
    {
        if (!TryParse(shareLink, out var options, out var error))
            throw new FormatException(error);
        return options;
    }

    /// <summary>
    /// Attempts to parse a <c>trojan://</c> share link, returning <see langword="false"/>
    /// instead of throwing on malformed input.
    /// </summary>
    public static bool TryParse(string shareLink, [NotNullWhen(true)] out TrojanOptions? options)
        => TryParse(shareLink, out options, out _);

    private static bool TryParse(
        string shareLink,
        [NotNullWhen(true)] out TrojanOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        if (string.IsNullOrWhiteSpace(shareLink))
        {
            error = "Trojan share link is empty.";
            return false;
        }

        string trimmed = shareLink.Trim();
        if (!trimmed.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
        {
            error = "Trojan share link must start with 'trojan://'.";
            return false;
        }

        // Say what is actually wrong rather than blaming the scheme, which is plainly right.
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            error =
                "Trojan share link is not a well-formed URI. Expected " +
                "'trojan://{password}@{host}:{port}?{query}#{remark}'; check for stray " +
                "characters in the host:port part.";
            return false;
        }

        string password = Uri.UnescapeDataString(uri.UserInfo);
        if (password.Length == 0)
        {
            error = "Trojan share link is missing the password.";
            return false;
        }

        // Uri.Host keeps the brackets on an IPv6 literal ("[2001:db8::1]"), which would
        // then fail to resolve at socket.ConnectAsync. Strip them so the raw address flows through.
        string host = uri.Host;
        if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
            host = host.Substring(1, host.Length - 2);
        if (host.Length == 0)
        {
            error = "Trojan share link is missing the server host.";
            return false;
        }

        int port = uri.Port;
        if (port <= 0 || port > 65535)
        {
            error = "Trojan share link is missing a valid server port.";
            return false;
        }

        // Defaults.
        string transport = "tcp";
        string? sni = null, path = null, hostHeader = null;
        IReadOnlyList<string>? alpn = null;
        bool allowInsecure = false;

        // Single-pass query scan. uri.Query includes a leading '?'.
        ReadOnlySpan<char> query = uri.Query;
        if (query.Length > 1)
        {
            query = query.Slice(1);
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

                if (key.Equals("type", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("network", StringComparison.OrdinalIgnoreCase))
                    transport = rawVal.ToString();
                else if (key.Equals("sni", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("serverName", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("peer", StringComparison.OrdinalIgnoreCase))
                    sni = Decode(rawVal);
                else if (key.Equals("alpn", StringComparison.OrdinalIgnoreCase))
                    alpn = ParseAlpn(rawVal);
                else if (key.Equals("allowInsecure", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("insecure", StringComparison.OrdinalIgnoreCase))
                    allowInsecure = IsTruthy(rawVal);
                else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
                    path = Decode(rawVal);
                else if (key.Equals("host", StringComparison.OrdinalIgnoreCase))
                    hostHeader = Decode(rawVal);
            }
        }

        string? remark = uri.Fragment.Length > 1
            ? Uri.UnescapeDataString(uri.Fragment.Substring(1))
            : null;

        options = new TrojanOptions
        {
            Password = password,
            Host = host,
            Port = port,
            Transport = transport,
            Sni = sni,
            Alpn = alpn,
            Path = path,
            HostHeader = hostHeader,
            AllowInsecure = allowInsecure,
            Remark = remark
        };
        error = null;
        return true;
    }

    private static bool IsTruthy(ReadOnlySpan<char> value)
        => value.Equals("1", StringComparison.Ordinal) ||
           value.Equals("true", StringComparison.OrdinalIgnoreCase);

    private static string[] ParseAlpn(ReadOnlySpan<char> value)
    {
        string decoded = Decode(value);
        return decoded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static string Decode(ReadOnlySpan<char> value)
    {
        // Only pay for unescaping when the value actually contains an escape.
        return value.IndexOf('%') < 0 ? value.ToString() : Uri.UnescapeDataString(value.ToString());
    }
}
