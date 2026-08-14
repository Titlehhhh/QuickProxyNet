using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

/// <summary>
/// Connects to a target host through a Trojan proxy. Trojan is TLS-mandatory: the request
/// header is written inside an <see cref="SslStream"/> session, over the <c>tcp</c>/<c>raw</c>,
/// <c>ws</c> or <c>httpupgrade</c> transport. The remaining transports are rejected with
/// <see cref="NotSupportedException"/>.
/// </summary>
public sealed class TrojanClient : ProxyClient
{
    private readonly List<SslApplicationProtocol>? _alpn;

    /// <summary>Creates a Trojan client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The password is empty.</exception>
    public TrojanClient(TrojanOptions options)
        : base("trojan", (options ?? throw new ArgumentNullException(nameof(options))).Host, options.Port)
    {
        // Fail fast: an empty password would authenticate as hex(SHA224("")), which no
        // server accepts, so reject it at construction rather than mid-connect.
        if (string.IsNullOrEmpty(options.Password))
            throw new ArgumentException("Trojan password must not be empty.", nameof(options));

        Options = options;
        _alpn = BuildAlpn(options.Alpn);
    }

    /// <summary>Creates a Trojan client by parsing a <c>trojan://</c> share link.</summary>
    /// <exception cref="FormatException">The link is malformed.</exception>
    public static TrojanClient FromShareLink(string shareLink) => new(TrojanShareLink.Parse(shareLink));

    /// <summary>The parsed Trojan configuration this client connects with.</summary>
    public TrojanOptions Options { get; }

    /// <inheritdoc />
    public override ProxyType Type => ProxyType.Trojan;

    /// <summary>
    /// Overrides validation of the proxy server's TLS certificate. Ignored when
    /// <see cref="TrojanOptions.AllowInsecure"/> is true (all certificates are then accepted).
    /// </summary>
    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    /// <summary>TLS protocol versions offered to the proxy. Defaults to TLS 1.2 and 1.3.</summary>
    public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <inheritdoc />
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        // Reject unsupported transports before writing any bytes or starting the handshake.
        TransportKind transport = EnsureSupported();

        // SslStream(leaveInnerStreamOpen:false) disposes the inner stream too, and every layer
        // above it likewise owns the one below — so unwinding the outermost unwinds all of them.
        Stream layered = new SslStream(stream, leaveInnerStreamOpen: false);
        try
        {
            await ((SslStream)layered).AuthenticateAsClientAsync(BuildSslOptions(), cancellationToken)
                .ConfigureAwait(false);

            layered = await ProxyTransport.ApplyAsync(
                transport,
                layered,
                Options.Path,
                ProxyTransport.ResolveHostHeader(Options.HostHeader, Options.Sni, Options.Host),
                cancellationToken).ConfigureAwait(false);

            await TrojanHelper.EstablishTrojanTunnelAsync(layered, Options, host, port, cancellationToken)
                .ConfigureAwait(false);
            return layered;
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
                $"Trojan transport '{Options.Transport}' is not supported; 'tcp'/'raw', 'ws' and " +
                "'httpupgrade' are implemented.");

        return transport;
    }

    private SslClientAuthenticationOptions BuildSslOptions() => new()
    {
        // Same precedence Xray applies: explicit SNI, else the transport Host header, else the
        // server address. A ws+tls node commonly sets only 'host'.
        TargetHost = Options.Sni ?? Options.HostHeader ?? Options.Host,
        EnabledSslProtocols = SslProtocols,
        RemoteCertificateValidationCallback = Options.AllowInsecure
            ? static (_, _, _, _) => true
            : ServerCertificateValidationCallback,
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
