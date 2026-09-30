using System.Net;

namespace QuickProxyNet;

internal static class ProxyConnector
{
    /// <summary>
    /// Negotiates a SOCKS or HTTP CONNECT tunnel over a stream already connected to the proxy,
    /// disposing the stream when negotiation fails or is cancelled.
    /// </summary>
    /// <remarks>
    /// HTTPS is not negotiated here. Its TLS session is with the proxy and belongs to
    /// <see cref="HttpsProxyClient"/>, which runs it through <see cref="TlsHandshake"/> so that a
    /// certificate failure reaches the caller as a proxy error rather than as a raw
    /// <c>AuthenticationException</c>.
    /// </remarks>
    public static async ValueTask<Stream> ConnectToProxyAsync(Stream stream, ProxyType type, string host, int port,
        NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        await using (cancellationToken.Register(static s => ((Stream)s!).Dispose(), stream))
        {
            try
            {
                switch (type)
                {
                    case ProxyType.Socks5:
                        await SocksHelper.EstablishSocks5TunnelAsync(stream, host, port, credentials, cancellationToken)
                            .ConfigureAwait(false);
                        return stream;

                    case ProxyType.Socks4:
                    case ProxyType.Socks4a:
                        await SocksHelper
                            .EstablishSocks4TunnelAsync(stream, type == ProxyType.Socks4a, host, port, credentials,
                                cancellationToken)
                            .ConfigureAwait(false);
                        return stream;

                    case ProxyType.Http:
                        return await HttpHelper
                            .EstablishHttpTunnelAsync(stream, host, port, credentials, cancellationToken)
                            .ConfigureAwait(false);

                    default:
                        throw new ArgumentOutOfRangeException(nameof(type), type,
                            "Only SOCKS and plain HTTP tunnels are negotiated here.");
                }
            }
            catch
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
