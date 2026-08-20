using System.Text.Json;

namespace QuickProxyNet.Reality;

/// <summary>
/// Builds the Xray-core client configuration that fronts a VLESS outbound with a local
/// SOCKS5 inbound.
/// </summary>
/// <remarks>
/// <para>
/// The generated document is handed to Xray on <b>standard input</b> (<c>run -c stdin:</c>),
/// never written to a file. It contains the VLESS id — a credential — and a config file would
/// leave that credential on disk with the lifetime of the process at best, and past a crash at
/// worst. Xray accepting stdin is what makes that avoidable.
/// </para>
/// <para>
/// This is deliberately the only piece of the package with no process in it: the JSON is a pure
/// function of <see cref="VlessOptions"/> plus a port, so the mapping can be tested exactly
/// without spawning anything.
/// </para>
/// </remarks>
internal static class XrayClientConfig
{
    /// <summary>Fingerprint used when the share link carries no <c>fp</c>.</summary>
    /// <remarks>
    /// Xray treats an empty fingerprint as "no uTLS", which produces Go's own ClientHello —
    /// the single most identifiable handshake a REALITY client can emit. Defaulting to
    /// <c>chrome</c> is therefore a safety default, not a cosmetic one.
    /// </remarks>
    public const string DefaultFingerprint = "chrome";

    /// <summary>
    /// Renders the client configuration for <paramref name="options"/> with a SOCKS5 inbound
    /// on <paramref name="listenAddress"/>:<paramref name="socksPort"/>.
    /// </summary>
    /// <param name="options">The VLESS outbound to drive.</param>
    /// <param name="listenAddress">Loopback address for the local inbound.</param>
    /// <param name="socksPort">Port for the local inbound.</param>
    /// <param name="logLevel">Xray <c>loglevel</c>.</param>
    /// <returns>UTF-8 JSON.</returns>
    /// <exception cref="NotSupportedException">
    /// The options select something this package does not render. Never silently reduced to
    /// something weaker — an unrendered field would mean connecting with less protection than
    /// the share link asked for.
    /// </exception>
    public static byte[] Build(VlessOptions options, string listenAddress, int socksPort, string logLevel)
    {
        ArgumentNullException.ThrowIfNull(options);

        string security = options.Security switch
        {
            VlessSecurity.Reality => "reality",
            VlessSecurity.Tls => "tls",
            _ => throw new NotSupportedException(
                $"QuickProxyNet.Reality drives TLS and REALITY outbounds; this one is " +
                $"'{options.Security}'. Plain VLESS needs no external process — use " +
                $"QuickProxyNet's VlessClient directly.")
        };

        if (options.Security == VlessSecurity.Reality && string.IsNullOrEmpty(options.RealityPublicKey))
            throw new NotSupportedException(
                "A REALITY outbound requires a public key ('pbk' in the share link); this one has none. " +
                "Connecting without it would fall back to an ordinary TLS handshake and send the VLESS id " +
                "to a server that is not expecting one.");

        string network = ResolveNetwork(options.Transport);

        // Xray refuses this combination outright: "REALITY only supports RAW, XHTTP and gRPC for
        // now." Rendering it anyway would produce a document the process rejects at startup, and
        // the caller would see a generic launch failure instead of the actual reason.
        if (options.Security == VlessSecurity.Reality && network != "tcp")
            throw new NotSupportedException(
                $"REALITY runs only over the raw/tcp transport (and, in Xray, xhttp and gRPC); this link " +
                $"asks for '{options.Transport}'. A REALITY link with a WebSocket transport is malformed — " +
                "no server can serve it.");

        var buffer = new MemoryStream(1024);
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            w.WriteStartObject();

            w.WriteStartObject("log");
            w.WriteString("loglevel", logLevel);
            w.WriteEndObject();

            w.WriteStartArray("inbounds");
            w.WriteStartObject();
            w.WriteString("listen", listenAddress);
            w.WriteNumber("port", socksPort);
            w.WriteString("protocol", "socks");
            w.WriteStartObject("settings");
            w.WriteString("auth", "noauth");
            // UDP would need the inbound to hand out a relay address, and nothing in
            // QuickProxyNet consumes UDP. Off, rather than advertised and broken.
            w.WriteBoolean("udp", false);
            w.WriteEndObject();
            w.WriteEndObject();
            w.WriteEndArray();

            w.WriteStartArray("outbounds");
            w.WriteStartObject();
            w.WriteString("protocol", "vless");

            w.WriteStartObject("settings");
            w.WriteStartArray("vnext");
            w.WriteStartObject();
            w.WriteString("address", options.Host);
            w.WriteNumber("port", options.Port);
            w.WriteStartArray("users");
            w.WriteStartObject();
            w.WriteString("id", options.Id);
            w.WriteString("encryption", "none");
            if (!string.IsNullOrEmpty(options.Flow))
                w.WriteString("flow", options.Flow);
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();

            w.WriteStartObject("streamSettings");
            w.WriteString("network", network);
            w.WriteString("security", security);

            if (options.Security == VlessSecurity.Reality)
            {
                w.WriteStartObject("realitySettings");
                w.WriteString("serverName", options.Sni ?? options.Host);
                w.WriteString("fingerprint", string.IsNullOrEmpty(options.Fingerprint)
                    ? DefaultFingerprint
                    : options.Fingerprint);
                w.WriteString("publicKey", options.RealityPublicKey!);
                if (!string.IsNullOrEmpty(options.RealityShortId))
                    w.WriteString("shortId", options.RealityShortId);
                w.WriteEndObject();
            }
            else
            {
                w.WriteStartObject("tlsSettings");
                w.WriteString("serverName", options.Sni ?? options.HostHeader ?? options.Host);
                w.WriteString("fingerprint", string.IsNullOrEmpty(options.Fingerprint)
                    ? DefaultFingerprint
                    : options.Fingerprint);
                if (options.Alpn is { Count: > 0 })
                {
                    w.WriteStartArray("alpn");
                    foreach (string alpn in options.Alpn)
                        w.WriteStringValue(alpn);
                    w.WriteEndArray();
                }
                w.WriteEndObject();
            }

            WriteTransportSettings(w, network, options);

            w.WriteEndObject(); // streamSettings
            w.WriteEndObject(); // outbound
            w.WriteEndArray();

            w.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteTransportSettings(Utf8JsonWriter w, string network, VlessOptions options)
    {
        if (network == "tcp")
            return;

        w.WriteStartObject(network == "ws" ? "wsSettings" : "httpupgradeSettings");
        w.WriteString("path", string.IsNullOrEmpty(options.Path) ? "/" : options.Path);

        // Xray's own key for the Host header. Same fallback chain the core package uses, so a
        // link behaves identically whichever client drives it.
        string? host = options.HostHeader ?? options.Sni;
        if (!string.IsNullOrEmpty(host))
            w.WriteString("host", host);

        w.WriteEndObject();
    }

    /// <summary>Maps a share-link <c>type</c> to Xray's <c>network</c>.</summary>
    private static string ResolveNetwork(string? transport) =>
        (transport ?? "tcp").ToLowerInvariant() switch
        {
            "" or "tcp" or "raw" or "none" => "tcp",
            "ws" or "websocket" => "ws",
            "httpupgrade" => "httpupgrade",
            // grpc and xhttp are things Xray can speak, but their share links carry fields
            // (serviceName, mode) that VlessOptions does not model yet. Rendering them from
            // the fields we do have would produce a config that connects to the wrong path.
            var other => throw new NotSupportedException(
                $"Transport '{other}' is not rendered yet; supported: tcp/raw, ws, httpupgrade.")
        };
}
