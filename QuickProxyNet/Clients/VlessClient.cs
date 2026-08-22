using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

/// <summary>
/// Connects to a target host through a VLESS proxy. Supports <c>security=none</c> (plain TCP),
/// <c>security=tls</c> (over <see cref="SslStream"/>) and <c>security=reality</c> (over this
/// library's own TLS 1.3), with or without <c>flow=xtls-rprx-vision</c>, each over the
/// <c>tcp</c>/<c>raw</c>, <c>ws</c> or <c>httpupgrade</c> transport. Other flows and the
/// remaining transports are rejected with <see cref="NotSupportedException"/>.
/// </summary>
/// <remarks>
/// REALITY needs no external process and no Xray binary: the handshake is
/// <see cref="RealityTlsClient"/>, in-process. What it does <b>not</b> yet do is look like a
/// browser on the wire — see <c>TlsClientHello</c> for why that matters and what is missing.
/// </remarks>
public sealed class VlessClient : ProxyClient
{
    private readonly List<SslApplicationProtocol>? _alpn;

    /// <summary>Creates a VLESS client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The options carry an invalid UUID.</exception>
    public VlessClient(VlessOptions options)
        : base("vless", (options ?? throw new ArgumentNullException(nameof(options))).Host, options.Port)
    {
        // Validate the id up front so a bad one fails at construction rather than mid-connect
        // (the share-link path already validated it, but a directly-built VlessOptions may not
        // have). This must use the same rule as the wire encoder: Guid.TryParse alone would
        // reject the short non-UUID ids that UuidCodec — and Xray — map to a derived UUID.
        Span<byte> probe = stackalloc byte[UuidCodec.Size];
        if (!UuidCodec.TryWriteBigEndian(options.Id, probe))
            throw new ArgumentException(
                $"VLESS user id is unusable ({options.Id.Length} characters): it is neither a canonical UUID nor " +
                "a string of 1..30 characters (which would be mapped to a UUID).",
                nameof(options));

        Options = options;
        _alpn = BuildAlpn(options.Alpn);
    }

    /// <summary>Creates a VLESS client by parsing a <c>vless://</c> share link.</summary>
    /// <exception cref="FormatException">The link is malformed.</exception>
    public static VlessClient FromShareLink(string shareLink) => new(VlessShareLink.Parse(shareLink));

    /// <summary>The parsed VLESS configuration this client connects with.</summary>
    public VlessOptions Options { get; }

    public override ProxyType Type => ProxyType.Vless;

    /// <summary>
    /// Overrides validation of the proxy server's TLS certificate (only used when
    /// <see cref="VlessOptions.Security"/> is <see cref="VlessSecurity.Tls"/>).
    /// </summary>
    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    /// <summary>TLS protocol versions offered to the proxy. Defaults to TLS 1.2 and 1.3.</summary>
    public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>
    /// Writes the VLESS request header over <paramref name="stream"/> (inside TLS when
    /// <see cref="VlessOptions.Security"/> is <see cref="VlessSecurity.Tls"/>) and returns the
    /// tunnel to <paramref name="host"/>:<paramref name="port"/>.
    /// </summary>
    /// <remarks>
    /// Only the request header is written here. The server response header is validated lazily
    /// on the first read (see <c>VlessResponseStream</c>), because neither Xray nor sing-box
    /// flushes it until the target produces data — reading it eagerly would deadlock every
    /// client-speaks-first protocol.
    /// </remarks>
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        TransportKind transport = EnsureSupported();

        // Each layer takes ownership of the one below it, so tracking the outermost stream is
        // enough to unwind the whole stack on failure.
        Stream layered = stream;
        try
        {
            if (Options.Security == VlessSecurity.Tls)
            {
                // SslStream(leaveInnerStreamOpen:false) disposes the inner stream too.
                var ssl = new SslStream(layered, leaveInnerStreamOpen: false);
                layered = ssl;
                await ssl.AuthenticateAsClientAsync(BuildSslOptions(), cancellationToken).ConfigureAwait(false);
            }
            else if (Options.Security == VlessSecurity.Reality)
            {
                layered = await RealityTlsClient
                    .HandshakeAsync(layered, BuildRealityOptions(), cancellationToken)
                    .ConfigureAwait(false);
            }

            layered = await ProxyTransport.ApplyAsync(
                transport,
                layered,
                Options.Path,
                ProxyTransport.ResolveHostHeader(Options.HostHeader, Options.Sni, Options.Host),
                cancellationToken).ConfigureAwait(false);

            return await VlessHelper.EstablishVlessTunnelAsync(layered, Options, host, port, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await layered.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private TransportKind EnsureSupported()
    {
        TransportKind transport = Options.TransportKind;
        if (transport == TransportKind.Unsupported)
            throw new NotSupportedException(
                $"VLESS transport '{Options.Transport}' is not supported; 'tcp'/'raw', 'ws' and " +
                "'httpupgrade' are implemented.");

        if (Options.Security == VlessSecurity.Reality && string.IsNullOrEmpty(Options.RealityPublicKey))
            throw new NotSupportedException(
                "VLESS REALITY needs the server's public key ('pbk' in the share link); this configuration has none.");

        if (!string.IsNullOrEmpty(Options.Flow) && !VlessHelper.IsVision(Options.Flow))
            throw new NotSupportedException(
                $"VLESS flow '{Options.Flow}' is not supported; '{VisionStream.FlowName}' is the only XTLS flow implemented.");

        return transport;
    }

    /// <summary>
    /// Translates the share link's REALITY fields into handshake options.
    /// </summary>
    /// <remarks>
    /// The ALPN default matches what Xray's own client offers when a link names none. It is not
    /// cosmetic: the value is covered by the ClientHello the server authenticates against, and a
    /// list nobody else sends is one more way to stand out.
    /// </remarks>
    private RealityTlsOptions BuildRealityOptions() => new()
    {
        ServerName = Options.Sni ?? Options.HostHeader ?? Options.Host,
        PublicKey = DecodeBase64Url(Options.RealityPublicKey!),
        ShortId = string.IsNullOrEmpty(Options.RealityShortId) ? null : Options.RealityShortId,
        Alpn = Options.Alpn is { Count: > 0 } ? Options.Alpn : ["h2", "http/1.1"]
    };

    /// <summary>Decodes the unpadded base64url that share links carry <c>pbk</c> in.</summary>
    private static byte[] DecodeBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };

        byte[] key;
        try
        {
            key = Convert.FromBase64String(padded);
        }
        catch (FormatException ex)
        {
            throw new FormatException(
                $"The REALITY public key '{value}' is not valid base64url (expected the 'pbk' value from the share link).", ex);
        }

        // Checked here, before any byte is written, so a truncated pbk fails as a configuration
        // error with the value named — not as an ArgumentException from inside the handshake.
        if (key.Length != X25519.KeySize)
            throw new FormatException(
                $"The REALITY public key '{value}' decodes to {key.Length} bytes; an X25519 key is {X25519.KeySize}.");

        return key;
    }

    private SslClientAuthenticationOptions BuildSslOptions() => new()
    {
        // Same precedence Xray applies: explicit SNI, else the transport Host header, else the
        // server address. A ws+tls node commonly sets only 'host'.
        TargetHost = Options.Sni ?? Options.HostHeader ?? Options.Host,
        EnabledSslProtocols = SslProtocols,
        RemoteCertificateValidationCallback = ServerCertificateValidationCallback,
        ApplicationProtocols = _alpn
    };

    // Built once per client from immutable options. Common ALPN ids map to the
    // allocation-free static instances instead of encoding a fresh byte[] each time.
    private static List<SslApplicationProtocol>? BuildAlpn(IReadOnlyList<string>? alpn)
    {
        if (alpn is not { Count: > 0 })
            return null;

        var list = new List<SslApplicationProtocol>(alpn.Count);
        for (int i = 0; i < alpn.Count; i++)
        {
            string p = alpn[i];
            list.Add(p switch
            {
                "h2" => SslApplicationProtocol.Http2,
                "http/1.1" => SslApplicationProtocol.Http11,
                "h3" => SslApplicationProtocol.Http3,
                _ => new SslApplicationProtocol(p)
            });
        }
        return list;
    }
}
