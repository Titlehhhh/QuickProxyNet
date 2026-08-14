using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;

namespace QuickProxyNet;

/// <summary>
/// Parses <c>vmess://</c> share links into <see cref="VmessOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Two grammars exist in the wild and both are accepted:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>v2rayN base64-JSON</b> — <c>vmess://</c> followed by base64-encoded UTF-8 JSON.
/// Both the standard and the URL-safe alphabets are accepted, with or without padding,
/// embedded whitespace is ignored, and a <c>#remark</c> fragment appended <em>after</em>
/// the base64 is treated as the remark rather than as payload. Real-world links violate
/// all four rules.
/// </description></item>
/// <item><description>
/// <b>Standard URI</b> — <c>vmess://{uuid}@{host}:{port}?{query}#{remark}</c>. Note that
/// the query keys carry different meanings from the JSON fields: <c>type</c> is the
/// transport, <c>headerType</c> the obfuscation, <c>encryption</c> the body cipher and
/// <c>security</c> the transport security.
/// </description></item>
/// </list>
/// <para>
/// A payload containing <c>@</c> selects the second grammar; that character occurs in
/// neither base64 alphabet, so the choice is unambiguous.
/// </para>
/// <para>
/// Recognized JSON fields: <c>add</c>, <c>port</c>, <c>id</c>, <c>aid</c>/<c>alterId</c>,
/// <c>scy</c>/<c>security</c>, <c>net</c>, <c>type</c>, <c>tls</c>, <c>sni</c>,
/// <c>host</c>, <c>alpn</c>, <c>allowInsecure</c>/<c>skip-cert-verify</c> and <c>ps</c>.
/// Numbers may be encoded as JSON numbers or as JSON strings; both are handled. Unknown
/// fields are ignored.
/// </para>
/// <para>
/// The parser <b>fails loudly</b> rather than silently downgrading: a non-zero
/// <c>alterId</c> (legacy MD5 authentication), an unrecognized <c>scy</c>, a
/// <c>reality</c> transport security, or a header-obfuscation <c>type</c> are all
/// rejected, because accepting them would produce a connection that cannot work — or, for
/// <c>reality</c>, one that leaks the request to a server expecting a different handshake.
/// </para>
/// </remarks>
public static class VmessShareLink
{
    private const string Scheme = "vmess://";

    /// <summary>
    /// Parses a <c>vmess://</c> share link.
    /// </summary>
    /// <exception cref="FormatException">
    /// The link is malformed, the payload is not valid base64 JSON, a required field is
    /// missing or invalid, or the configuration is outside VMessAEAD.
    /// </exception>
    public static VmessOptions Parse(string shareLink)
    {
        if (!TryParse(shareLink, out var options, out var error))
            throw new FormatException(error);
        return options;
    }

    /// <summary>
    /// Attempts to parse a <c>vmess://</c> share link, returning <see langword="false"/>
    /// instead of throwing on malformed input.
    /// </summary>
    public static bool TryParse(string shareLink, [NotNullWhen(true)] out VmessOptions? options)
        => TryParse(shareLink, out options, out _);

    private static bool TryParse(
        string shareLink,
        [NotNullWhen(true)] out VmessOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        if (string.IsNullOrWhiteSpace(shareLink))
        {
            error = "VMess share link is empty.";
            return false;
        }

        ReadOnlySpan<char> link = shareLink.AsSpan().Trim();
        if (!link.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            error = "VMess share link must start with 'vmess://'.";
            return false;
        }

        ReadOnlySpan<char> payload = link[Scheme.Length..];
        if (payload.IsEmpty)
        {
            error = "VMess share link has no payload.";
            return false;
        }

        // Two grammars exist in the wild. Neither base64 alphabet contains '@', so its
        // presence unambiguously means the standard URI form.
        if (payload.IndexOf('@') >= 0)
            return TryParseStandardUri(link.ToString(), out options, out error);

        // v2rayN base64-JSON. Producers routinely append the remark as a '#fragment'
        // *after* the base64, which then fails to decode. '#' is not in either alphabet
        // either, so everything from it onwards is the remark, not payload.
        string? fragmentRemark = null;
        int hash = payload.IndexOf('#');
        if (hash >= 0)
        {
            ReadOnlySpan<char> fragment = payload[(hash + 1)..];
            if (!fragment.IsEmpty)
                fragmentRemark = Uri.UnescapeDataString(fragment.ToString());
            payload = payload[..hash];
        }

        if (payload.IsEmpty)
        {
            error = "VMess share link has no base64 payload.";
            return false;
        }

        byte[] json = ArrayPool<byte>.Shared.Rent((payload.Length + 3) / 4 * 3);
        try
        {
            // Fast path: standard, correctly padded base64 (what v2rayN emits). Whitespace
            // is tolerated by the BCL decoder, so only the URL-safe alphabet and missing
            // padding need the normalization pass below.
            if (!Convert.TryFromBase64Chars(payload, json, out int jsonLength) &&
                !TryDecodeRelaxed(payload, json, out jsonLength))
            {
                error = "VMess share link payload is not valid base64.";
                return false;
            }

            return TryParseJson(json.AsMemory(0, jsonLength), fragmentRemark, out options, out error);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(json, clearArray: true);
        }
    }

    /// <summary>
    /// Parses the standard URI grammar
    /// <c>vmess://{uuid}@{host}:{port}?{query}#{remark}</c>.
    /// </summary>
    /// <remarks>
    /// The query keys do <b>not</b> mean the same thing as the JSON fields: here
    /// <c>type</c> is the <em>transport</em> (what JSON calls <c>net</c>),
    /// <c>headerType</c> is the header obfuscation (what JSON calls <c>type</c>),
    /// <c>encryption</c> is the VMess body cipher (what JSON calls <c>scy</c>), and
    /// <c>security</c> is the transport security (what JSON calls <c>tls</c>). Getting
    /// this mapping backwards silently produces a client that negotiates the wrong cipher.
    /// </remarks>
    private static bool TryParseStandardUri(
        string shareLink,
        [NotNullWhen(true)] out VmessOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        if (!Uri.TryCreate(shareLink, UriKind.Absolute, out var uri))
        {
            error =
                "VMess share link is not a well-formed URI. Expected either base64-encoded " +
                "JSON or 'vmess://{id}@{host}:{port}?{query}#{remark}'.";
            return false;
        }

        string id = Uri.UnescapeDataString(uri.UserInfo);
        if (id.Length == 0)
        {
            error = "VMess share link is missing the user id.";
            return false;
        }

        Span<byte> probe = stackalloc byte[UuidCodec.Size];
        if (!UuidCodec.TryWriteBigEndian(id, probe))
        {
            error =
                $"VMess user id '{id}' is unusable: it is neither a canonical UUID nor a " +
                "string of 1..30 characters (which would be mapped to a UUID).";
            return false;
        }

        // Uri.Host keeps the brackets on an IPv6 literal, which would then fail to resolve.
        string host = uri.Host;
        if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
            host = host.Substring(1, host.Length - 2);
        if (host.Length == 0)
        {
            error = "VMess share link is missing the server address.";
            return false;
        }

        int port = uri.Port;
        if (port <= 0 || port > 65535)
        {
            error = "VMess share link is missing a valid server port.";
            return false;
        }

        string? encryption = null, transportSecurity = null, headerType = null;
        string transport = "tcp";
        string? sni = null, transportHost = null, path = null;
        string[]? alpn = null;
        bool allowInsecure = false;

        ReadOnlySpan<char> query = uri.Query;
        if (query.Length > 1)
        {
            query = query[1..];
            while (!query.IsEmpty)
            {
                int amp = query.IndexOf('&');
                ReadOnlySpan<char> pair = amp < 0 ? query : query[..amp];
                query = amp < 0 ? default : query[(amp + 1)..];

                int eq = pair.IndexOf('=');
                if (eq < 0)
                    continue;

                ReadOnlySpan<char> key = ShareLinkQuery.StripHtmlAmpPrefix(pair[..eq]);
                ReadOnlySpan<char> rawVal = pair[(eq + 1)..];
                if (rawVal.IsEmpty)
                    continue;

                if (key.Equals("type", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("network", StringComparison.OrdinalIgnoreCase))
                    transport = Decode(rawVal);
                else if (key.Equals("encryption", StringComparison.OrdinalIgnoreCase))
                    encryption = Decode(rawVal);
                else if (key.Equals("security", StringComparison.OrdinalIgnoreCase))
                    transportSecurity = Decode(rawVal);
                else if (key.Equals("headerType", StringComparison.OrdinalIgnoreCase))
                    headerType = Decode(rawVal);
                else if (key.Equals("sni", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("serverName", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("peer", StringComparison.OrdinalIgnoreCase))
                    sni = Decode(rawVal);
                else if (key.Equals("host", StringComparison.OrdinalIgnoreCase))
                    transportHost = Decode(rawVal);
                else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
                    path = Decode(rawVal);
                else if (key.Equals("alpn", StringComparison.OrdinalIgnoreCase))
                    alpn = SplitAlpn(Decode(rawVal));
                else if (key.Equals("allowInsecure", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("insecure", StringComparison.OrdinalIgnoreCase) ||
                         key.Equals("skip-cert-verify", StringComparison.OrdinalIgnoreCase))
                    allowInsecure = IsTruthy(Decode(rawVal));
            }
        }

        // 'security' means two different things in the wild, and which one is meant can be
        // recovered from the value instead of guessed. The URI grammar defines it as the
        // transport security (what the JSON form calls 'tls'), and links pairing it with a
        // VLESS-style 'encryption=none' do use it that way. But 611 links — 27% of every
        // vmess link in a 17k real-world corpus — put the *body cipher* there instead, which
        // the JSON form calls 'scy'. The two value sets are disjoint apart from 'none':
        //
        //   auto | aes-128-gcm | chacha20-poly1305   -> body cipher
        //   tls  | reality     | none                -> transport security
        //
        // 'none' stays transport security. That is its documented meaning, and both readings
        // agree the connection is not TLS, so nothing is downgraded by keeping it.
        //
        // Reading 'security=auto' as "no TLS" cannot leak a credential the way the VLESS
        // downgrade did: VMessAEAD seals the request header under a key derived from the id,
        // so the id never reaches the wire in cleartext. A wrong guess costs a failed
        // handshake — the server cannot parse a plaintext header and drops the connection.
        if (LooksLikeBodyCipher(transportSecurity))
        {
            encryption ??= transportSecurity;
            transportSecurity = null;
        }

        // VMess has no 'encryption' key of its own; producers copy it from the VLESS grammar,
        // where 'encryption=none' is mandatory boilerplate. Treat it as unspecified rather
        // than as a request for VMess's unencrypted body mode, which no real server runs.
        if (encryption is not null && encryption.Equals("none", StringComparison.OrdinalIgnoreCase))
            encryption = null;

        if (!TryParseSecurity(encryption, out VmessSecurityKind security))
        {
            error = UnsupportedSecurityMessage(encryption);
            return false;
        }

        if (!TryValidateHeaderType(headerType, transport, out error))
            return false;

        bool useTls = false;
        if (!string.IsNullOrEmpty(transportSecurity) &&
            !transportSecurity.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            if (transportSecurity.Equals("reality", StringComparison.OrdinalIgnoreCase))
            {
                error = "VMess over REALITY is not supported: it requires a uTLS ClientHello fingerprint.";
                return false;
            }

            if (!transportSecurity.Equals("tls", StringComparison.OrdinalIgnoreCase))
            {
                // Never default an unknown value to plaintext — that would send the sealed
                // request header to a server expecting TLS.
                error =
                    $"Unrecognized VMess transport security '{transportSecurity}': expected " +
                    "'none' or 'tls'.";
                return false;
            }

            useTls = true;
        }

        if (string.IsNullOrEmpty(sni))
            sni = transportHost;
        if (string.IsNullOrEmpty(sni))
            sni = host;

        options = new VmessOptions
        {
            Id = id,
            Host = host,
            Port = port,
            Security = security,
            AlterId = 0,
            Transport = transport,
            UseTls = useTls,
            Sni = sni,
            Alpn = alpn,
            Path = path,
            HostHeader = transportHost,
            AllowInsecure = allowInsecure,
            Remark = uri.Fragment.Length > 1
                ? Uri.UnescapeDataString(uri.Fragment[1..])
                : null
        };
        error = null;
        return true;
    }

    /// <summary>
    /// Validates the header-obfuscation field, which is only meaningful on the raw TCP
    /// transport. Every real client ignores it on <c>ws</c>, <c>httpupgrade</c> and
    /// <c>grpc</c>, where producers routinely leave junk in it, so rejecting it there would
    /// reject otherwise-valid links.
    /// </summary>
    private static bool TryValidateHeaderType(
        string? headerType, string transport, [NotNullWhen(false)] out string? error)
    {
        error = null;

        if (string.IsNullOrEmpty(headerType) ||
            headerType.Equals("none", StringComparison.OrdinalIgnoreCase))
            return true;

        // "raw" is Xray's current name for the plain TCP transport.
        bool isTcp = transport.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
                     transport.Equals("raw", StringComparison.OrdinalIgnoreCase);
        if (!isTcp)
            return true;

        error =
            $"VMess header obfuscation type '{headerType}' is not supported on the " +
            $"'{transport}' transport; only 'none' is.";
        return false;
    }

    private static string UnsupportedSecurityMessage(string? value) =>
        $"Unrecognized VMess security '{value}': only 'auto', 'aes-128-gcm' and " +
        "'chacha20-poly1305' are supported.";

    private static string[]? SplitAlpn(string value)
    {
        string[] parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 0 ? null : parts;
    }

    private static string Decode(ReadOnlySpan<char> value)
        => value.IndexOf('%') < 0 ? value.ToString() : Uri.UnescapeDataString(value.ToString());

    /// <summary>
    /// Decodes a payload that uses the URL-safe alphabet and/or omits its padding.
    /// </summary>
    private static bool TryDecodeRelaxed(ReadOnlySpan<char> payload, Span<byte> destination, out int length)
    {
        // Padding may add up to 3 characters to the normalized form.
        char[] chars = ArrayPool<char>.Shared.Rent(payload.Length + 3);
        try
        {
            if (!TryNormalizeBase64(payload, chars, out int charCount))
            {
                length = 0;
                return false;
            }

            return Convert.TryFromBase64Chars(chars.AsSpan(0, charCount), destination, out length);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(chars);
        }
    }

    /// <summary>
    /// Copies <paramref name="payload"/> into <paramref name="destination"/>, translating
    /// the URL-safe alphabet to the standard one, dropping whitespace, and appending the
    /// <c>=</c> padding <see cref="Convert.TryFromBase64Chars"/> requires.
    /// </summary>
    private static bool TryNormalizeBase64(
        ReadOnlySpan<char> payload, Span<char> destination, out int length)
    {
        length = 0;

        for (int i = 0; i < payload.Length; i++)
        {
            char c = payload[i];
            if (char.IsWhiteSpace(c))
                continue;

            destination[length++] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            };
        }

        // Trailing padding may already be present; only top it up to a 4-character group.
        int remainder = length % 4;
        if (remainder == 1)
            return false; // no base64 string can have this length

        if (remainder != 0)
        {
            for (int i = remainder; i < 4; i++)
                destination[length++] = '=';
        }

        return length > 0;
    }

    private static bool TryParseJson(
        ReadOnlyMemory<byte> utf8Json,
        string? fragmentRemark,
        [NotNullWhen(true)] out VmessOptions? options,
        [NotNullWhen(false)] out string? error)
    {
        options = null;

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8Json);
        }
        catch (JsonException)
        {
            error = "VMess share link payload is not valid JSON.";
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "VMess share link payload must be a JSON object.";
                return false;
            }

            // Single pass over the object. JsonElement.TryGetProperty rescans the whole
            // document (and re-encodes the name to UTF-8) on every call, so the recognized
            // fields are captured once here instead. NameEquals is given UTF-8 literals so
            // each key is compared as raw bytes — no transcoding, no string materialized.
            // Unrecognized fields are ignored.
            JsonElement idField = default, addField = default, portField = default;
            JsonElement aidField = default, alterIdField = default;
            JsonElement scyField = default, securityField = default;
            JsonElement netField = default, typeField = default, tlsField = default;
            JsonElement sniField = default, hostField = default, pathField = default;
            JsonElement alpnField = default, psField = default;
            JsonElement allowInsecureField = default, skipCertVerifyField = default;

            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (property.NameEquals("id"u8)) idField = property.Value;
                else if (property.NameEquals("add"u8)) addField = property.Value;
                else if (property.NameEquals("port"u8)) portField = property.Value;
                else if (property.NameEquals("aid"u8)) aidField = property.Value;
                else if (property.NameEquals("alterId"u8)) alterIdField = property.Value;
                else if (property.NameEquals("scy"u8)) scyField = property.Value;
                else if (property.NameEquals("security"u8)) securityField = property.Value;
                else if (property.NameEquals("net"u8)) netField = property.Value;
                else if (property.NameEquals("type"u8)) typeField = property.Value;
                else if (property.NameEquals("tls"u8)) tlsField = property.Value;
                else if (property.NameEquals("sni"u8)) sniField = property.Value;
                else if (property.NameEquals("host"u8)) hostField = property.Value;
                else if (property.NameEquals("path"u8)) pathField = property.Value;
                else if (property.NameEquals("alpn"u8)) alpnField = property.Value;
                else if (property.NameEquals("ps"u8)) psField = property.Value;
                else if (property.NameEquals("allowInsecure"u8)) allowInsecureField = property.Value;
                else if (property.NameEquals("skip-cert-verify"u8)) skipCertVerifyField = property.Value;
            }

            // ---- id: a canonical UUID is mandatory ----
            string? id = GetString(idField);
            if (string.IsNullOrEmpty(id))
            {
                error = "VMess share link is missing the user id.";
                return false;
            }

            Span<byte> probe = stackalloc byte[UuidCodec.Size];
            if (!UuidCodec.TryWriteBigEndian(id, probe))
            {
                error =
                    $"VMess user id '{id}' is unusable: it is neither a canonical UUID nor a " +
                    "string of 1..30 characters (which would be mapped to a UUID).";
                return false;
            }

            // ---- add / port ----
            string? host = GetString(addField);
            if (string.IsNullOrEmpty(host))
            {
                error = "VMess share link is missing the server address.";
                return false;
            }

            // Uri-style IPv6 literals keep their brackets, which would then fail to resolve
            // at socket.ConnectAsync. Strip them so the raw address flows through.
            if (host.Length > 1 && host[0] == '[' && host[^1] == ']')
                host = host.Substring(1, host.Length - 2);
            if (host.Length == 0)
            {
                error = "VMess share link is missing the server address.";
                return false;
            }

            if (GetInt32(portField, out int port) != FieldState.Ok || port <= 0 || port > 65535)
            {
                error = "VMess share link is missing a valid server port.";
                return false;
            }

            // ---- alterId: AEAD only ----
            FieldState alterState = GetInt32(aidField, out int alterId);
            if (alterState == FieldState.Missing)
                alterState = GetInt32(alterIdField, out alterId);

            if (alterState == FieldState.Invalid)
            {
                error = "VMess share link has an invalid 'aid' (alterId) value.";
                return false;
            }

            if (alterId != 0)
            {
                // Never pretend: alterId > 0 selects the legacy MD5-authenticated header,
                // which this implementation does not speak at all.
                error =
                    $"VMess alterId {alterId} is not supported: only alterId 0 (VMessAEAD) is " +
                    "implemented, and a non-zero value selects the legacy MD5 authentication format.";
                return false;
            }

            // ---- scy / security ----
            string? scy = GetString(scyField) ?? GetString(securityField);
            if (!TryParseSecurity(scy, out VmessSecurityKind security))
            {
                error = UnsupportedSecurityMessage(scy);
                return false;
            }

            // ---- net / type ----
            // 'net' is the transport; 'type' is header obfuscation (e.g. "http"), which
            // only applies to the raw TCP transport.
            string? net = GetString(netField);
            string transport = string.IsNullOrEmpty(net) ? "tcp" : net;

            if (!TryValidateHeaderType(GetString(typeField), transport, out error))
                return false;

            // ---- tls ----
            string? tls = GetString(tlsField);
            bool useTls = false;
            if (!string.IsNullOrEmpty(tls) && !tls.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                if (tls.Equals("reality", StringComparison.OrdinalIgnoreCase))
                {
                    // Connecting with a plain SslStream would send the sealed request header
                    // to a server expecting a uTLS ClientHello fingerprint. Fail instead.
                    error = "VMess over REALITY is not supported: it requires a uTLS ClientHello fingerprint.";
                    return false;
                }

                useTls = true;
            }

            // ---- sni: explicit, else the transport 'host' header, else the server address ----
            string? sni = GetString(sniField);
            if (string.IsNullOrEmpty(sni))
                sni = GetString(hostField);
            if (string.IsNullOrEmpty(sni))
                sni = host;

            options = new VmessOptions
            {
                Id = id,
                Host = host,
                Port = port,
                Security = security,
                AlterId = 0,
                Transport = transport,
                UseTls = useTls,
                Sni = sni,
                Alpn = GetAlpn(alpnField),
                Path = GetString(pathField),
                HostHeader = GetString(hostField),
                AllowInsecure = GetBoolean(allowInsecureField) || GetBoolean(skipCertVerifyField),
                // 'ps' is authoritative; the '#fragment' form is the fallback for producers
                // that append the remark after the base64 instead of putting it in the JSON.
                Remark = GetString(psField) ?? fragmentRemark
            };
            error = null;
            return true;
        }
    }

    /// <summary>
    /// True when a value found in the URI's <c>security</c> key is unambiguously a body
    /// cipher rather than a transport security mode. <c>none</c> is excluded on purpose: it
    /// is valid in both vocabularies.
    /// </summary>
    private static bool LooksLikeBodyCipher(string? value) =>
        value is not null &&
        (value.Equals("auto", StringComparison.OrdinalIgnoreCase) ||
         value.Equals("aes-128-gcm", StringComparison.OrdinalIgnoreCase) ||
         value.Equals("chacha20-poly1305", StringComparison.OrdinalIgnoreCase));

    private static bool TryParseSecurity(string? value, out VmessSecurityKind security)
    {
        if (string.IsNullOrEmpty(value) || value.Equals("auto", StringComparison.OrdinalIgnoreCase))
            security = VmessSecurityKind.Auto;
        else if (value.Equals("aes-128-gcm", StringComparison.OrdinalIgnoreCase))
            security = VmessSecurityKind.Aes128Gcm;
        else if (value.Equals("chacha20-poly1305", StringComparison.OrdinalIgnoreCase))
            security = VmessSecurityKind.ChaCha20Poly1305;
        else
        {
            // 'none', 'zero' and 'aes-128-cfb' are deliberately rejected rather than
            // defaulted: they would silently change how the body is protected.
            security = VmessSecurityKind.Auto;
            return false;
        }

        return true;
    }

    // ================================ JSON helpers ================================

    private enum FieldState
    {
        /// <summary>The property is absent, null, or an empty string.</summary>
        Missing,

        /// <summary>The property is present but cannot be read as the requested type.</summary>
        Invalid,

        /// <summary>The property was read successfully.</summary>
        Ok
    }

    /// <summary>
    /// Reads a string value. JSON numbers are accepted and returned verbatim, because
    /// producers disagree about whether e.g. <c>aid</c> is a string or a number. An absent
    /// field (<c>default(JsonElement)</c>, i.e. <see cref="JsonValueKind.Undefined"/>)
    /// yields <see langword="null"/>.
    /// </summary>
    private static string? GetString(JsonElement element)
        => element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };

    /// <summary>
    /// Reads an integer value encoded either as a JSON number or as a JSON string.
    /// </summary>
    private static FieldState GetInt32(JsonElement element, out int value)
    {
        value = 0;

        switch (element.ValueKind)
        {
            case JsonValueKind.Number:
                return element.TryGetInt32(out value) ? FieldState.Ok : FieldState.Invalid;

            case JsonValueKind.String:
                string? text = element.GetString();
                if (string.IsNullOrWhiteSpace(text))
                    return FieldState.Missing;
                return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value)
                    ? FieldState.Ok
                    : FieldState.Invalid;

            case JsonValueKind.Null or JsonValueKind.Undefined:
                return FieldState.Missing;

            default:
                return FieldState.Invalid;
        }
    }

    private static bool GetBoolean(JsonElement element)
        => element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.Number => element.TryGetInt32(out int n) && n != 0,
            JsonValueKind.String => IsTruthy(element.GetString()),
            _ => false
        };

    private static bool IsTruthy(string? value) =>
        value is not null &&
        (value.Equals("1", StringComparison.Ordinal) ||
         value.Equals("true", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Reads <c>alpn</c>, which producers encode either as a comma-separated string or as
    /// a JSON array of strings.
    /// </summary>
    private static string[]? GetAlpn(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>(element.GetArrayLength());
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                    continue;

                string? value = item.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                    list.Add(value.Trim());
            }

            return list.Count == 0 ? null : list.ToArray();
        }

        if (element.ValueKind != JsonValueKind.String)
            return null;

        string? raw = element.GetString();
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        string[] parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 0 ? null : parts;
    }
}
