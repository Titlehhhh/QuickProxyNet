using System.Diagnostics.CodeAnalysis;

namespace QuickProxyNet;

/// <summary>
/// Parses <c>vless://</c> share links into <see cref="VlessOptions"/>.
/// </summary>
/// <remarks>
/// Grammar: <c>vless://{uuid}@{host}:{port}?{query}#{remark}</c>. The query is scanned
/// with a single-pass span parser (no <c>NameValueCollection</c> allocation); only the
/// recognized keys are materialized. Unknown keys are ignored.
/// </remarks>
public static class VlessShareLink
{
    /// <summary>
    /// Parses a <c>vless://</c> share link.
    /// </summary>
    /// <exception cref="FormatException">The link is malformed or the id is not a valid UUID.</exception>
    public static VlessOptions Parse(string shareLink)
    {
        if (!TryParse(shareLink, out var options, out var error))
            throw new FormatException(error);
        return options;
    }

    /// <summary>
    /// Attempts to parse a <c>vless://</c> share link, returning <see langword="false"/>
    /// instead of throwing on malformed input.
    /// </summary>
    public static bool TryParse(string shareLink, [NotNullWhen(true)] out VlessOptions? options)
        => TryParse(shareLink, out options, out _);

    private static bool TryParse(
        string shareLink,
        [NotNullWhen(true)] out VlessOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        if (string.IsNullOrWhiteSpace(shareLink))
        {
            error = "VLESS share link is empty.";
            return false;
        }

        if (!Uri.TryCreate(shareLink.Trim(), UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
        {
            error = "VLESS share link must start with 'vless://'.";
            return false;
        }

        string id = Uri.UnescapeDataString(uri.UserInfo);
        if (id.Length == 0)
        {
            error = "VLESS share link is missing the user id.";
            return false;
        }

        Span<byte> probe = stackalloc byte[UuidCodec.Size];
        if (!UuidCodec.TryWriteBigEndian(id, probe))
        {
            error = $"VLESS user id '{id}' is not a valid UUID.";
            return false;
        }

        // Uri.Host keeps the brackets on an IPv6 literal ("[2001:db8::1]"), which would
        // then fail to resolve at socket.ConnectAsync. Strip them so the raw address flows through.
        string host = uri.Host;
        if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
            host = host.Substring(1, host.Length - 2);
        if (host.Length == 0)
        {
            error = "VLESS share link is missing the server host.";
            return false;
        }

        int port = uri.Port;
        if (port <= 0 || port > 65535)
        {
            error = "VLESS share link is missing a valid server port.";
            return false;
        }

        // Defaults.
        var security = VlessSecurity.None;
        string transport = "tcp";
        string? sni = null, flow = null, fp = null, pbk = null, sid = null;
        IReadOnlyList<string>? alpn = null;

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

                ReadOnlySpan<char> key = pair.Slice(0, eq);
                ReadOnlySpan<char> rawVal = pair.Slice(eq + 1);
                if (rawVal.IsEmpty)
                    continue;

                if (key.Equals("type", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("network", StringComparison.OrdinalIgnoreCase))
                    transport = rawVal.ToString();
                else if (key.Equals("security", StringComparison.OrdinalIgnoreCase))
                {
                    if (!TryParseSecurity(rawVal, out security))
                    {
                        // Do NOT default an unknown value to None — that would silently send
                        // the VLESS header (with the UUID) in cleartext to a TLS/REALITY server.
                        error = $"Unrecognized VLESS security '{rawVal.ToString()}'.";
                        return false;
                    }
                }
                else if (key.Equals("sni", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("serverName", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("peer", StringComparison.OrdinalIgnoreCase))
                    sni = Decode(rawVal);
                else if (key.Equals("alpn", StringComparison.OrdinalIgnoreCase))
                    alpn = ParseAlpn(rawVal);
                else if (key.Equals("flow", StringComparison.OrdinalIgnoreCase))
                    flow = Decode(rawVal);
                else if (key.Equals("fp", StringComparison.OrdinalIgnoreCase))
                    fp = Decode(rawVal);
                else if (key.Equals("pbk", StringComparison.OrdinalIgnoreCase))
                    pbk = Decode(rawVal);
                else if (key.Equals("sid", StringComparison.OrdinalIgnoreCase))
                    sid = Decode(rawVal);
            }
        }

        string? remark = uri.Fragment.Length > 1
            ? Uri.UnescapeDataString(uri.Fragment.Substring(1))
            : null;

        options = new VlessOptions
        {
            Id = id,
            Host = host,
            Port = port,
            Security = security,
            Transport = transport,
            Sni = sni,
            Alpn = alpn,
            Flow = string.IsNullOrEmpty(flow) ? null : flow,
            Fingerprint = fp,
            RealityPublicKey = pbk,
            RealityShortId = sid,
            Remark = remark
        };
        error = null;
        return true;
    }

    private static bool TryParseSecurity(ReadOnlySpan<char> value, out VlessSecurity security)
    {
        if (value.IsEmpty || value.Equals("none", StringComparison.OrdinalIgnoreCase))
            security = VlessSecurity.None;
        else if (value.Equals("tls", StringComparison.OrdinalIgnoreCase))
            security = VlessSecurity.Tls;
        else if (value.Equals("reality", StringComparison.OrdinalIgnoreCase))
            security = VlessSecurity.Reality;
        else
        {
            security = VlessSecurity.None;
            return false;
        }
        return true;
    }

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
