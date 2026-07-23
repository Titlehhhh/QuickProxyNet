using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

/// <summary>
/// Connects to a target host through a VLESS proxy. Supports <c>security=none</c> (plain
/// TCP) and <c>security=tls</c> (over <see cref="SslStream"/>) with <c>tcp</c>/<c>raw</c>
/// transport. REALITY, non-empty <c>flow</c>, and alternate transports are rejected with
/// <see cref="NotSupportedException"/>.
/// </summary>
public sealed class VlessClient : ProxyClient
{
    private readonly List<SslApplicationProtocol>? _alpn;

    /// <summary>Creates a VLESS client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The options carry an invalid UUID.</exception>
    public VlessClient(VlessOptions options)
        : base("vless", (options ?? throw new ArgumentNullException(nameof(options))).Host, options.Port)
    {
        // Validate the id up front so a bad UUID fails at construction rather than mid-connect
        // (the share-link path already validated it, but a directly-built VlessOptions may not have).
        if (!Guid.TryParse(options.Id, out _))
            throw new ArgumentException($"VLESS user id '{options.Id}' is not a valid UUID.", nameof(options));

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

    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        EnsureSupported();

        if (Options.Security == VlessSecurity.Tls)
        {
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            try
            {
                await ssl.AuthenticateAsClientAsync(BuildSslOptions(), cancellationToken).ConfigureAwait(false);
                await VlessHelper.EstablishVlessTunnelAsync(ssl, Options, host, port, cancellationToken)
                    .ConfigureAwait(false);
                return ssl;
            }
            catch
            {
                // SslStream(leaveInnerStreamOpen:false) disposes the inner stream too.
                await ssl.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        try
        {
            await VlessHelper.EstablishVlessTunnelAsync(stream, Options, host, port, cancellationToken)
                .ConfigureAwait(false);
            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void EnsureSupported()
    {
        if (!Options.IsRawTcp)
            throw new NotSupportedException(
                $"VLESS transport '{Options.Transport}' is not supported; only 'tcp'/'raw' is implemented.");

        if (Options.Security == VlessSecurity.Reality)
            throw new NotSupportedException(
                "VLESS REALITY is not supported: it requires a uTLS ClientHello fingerprint that SslStream cannot produce.");

        if (!string.IsNullOrEmpty(Options.Flow))
            throw new NotSupportedException(
                $"VLESS flow '{Options.Flow}' (XTLS) is not supported in this release.");
    }

    private SslClientAuthenticationOptions BuildSslOptions() => new()
    {
        TargetHost = Options.Sni ?? Options.Host,
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
