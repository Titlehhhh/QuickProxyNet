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
    private readonly byte[]? _realityPublicKey;

    /// <summary>Creates a VLESS client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The options carry an invalid UUID, or, for REALITY, a public key or short id that cannot be
    /// decoded.
    /// </exception>
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

        // The same for REALITY's key and short id, and for the same reason: decoded inside
        // ConnectAsync, a bad one left it as a FormatException, which that call may not throw.
        // A missing key is still reported at connect, as the NotSupportedException it has always been.
        if (options.Security == VlessSecurity.Reality)
        {
            if (!string.IsNullOrEmpty(options.RealityPublicKey) &&
                !RealityAuth.TryDecodePublicKey(options.RealityPublicKey, out _realityPublicKey, out string? keyError))
                throw new ArgumentException(keyError, nameof(options));

            Span<byte> shortId = stackalloc byte[RealityAuth.ShortIdSize];
            if (!RealityAuth.TryParseShortId(shortId, options.RealityShortId, out string? shortIdError))
                throw new ArgumentException(shortIdError, nameof(options));
        }

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
        ValidateArguments(host, port);
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
                await TlsHandshake.AuthenticateAsync(
                    ssl, BuildSslOptions(), Options.Sni ?? Options.Host, cancellationToken).ConfigureAwait(false);
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
        // Decoded and length-checked by the constructor; EnsureSupported has already refused a
        // REALITY configuration without a key.
        PublicKey = _realityPublicKey!,
        ShortId = string.IsNullOrEmpty(Options.RealityShortId) ? null : Options.RealityShortId,
        Alpn = Options.Alpn is { Count: > 0 } ? Options.Alpn : ["h2", "http/1.1"]
    };

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
