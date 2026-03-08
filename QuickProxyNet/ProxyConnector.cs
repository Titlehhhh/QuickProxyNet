using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

internal static class ProxyConnector
{
    public static async ValueTask<Stream> ConnectToProxyAsync(Stream stream, Uri proxyUri, string host, int port,
        NetworkCredential? proxyCredentials, CancellationToken cancellationToken)
    {
        await using (cancellationToken.Register(static s => ((Stream)s!).Dispose(), stream))
        {
            try
            {
                var credentials = proxyCredentials?.GetCredential(proxyUri, proxyUri.Scheme);

                if (string.Equals(proxyUri.Scheme, "socks5", StringComparison.OrdinalIgnoreCase))
                {
                    await SocksHelper.EstablishSocks5TunnelAsync(stream, host, port, credentials, cancellationToken)
                        .ConfigureAwait(false);
                    return stream;
                }

                if (string.Equals(proxyUri.Scheme, "socks4a", StringComparison.OrdinalIgnoreCase))
                {
                    await SocksHelper
                        .EstablishSocks4TunnelAsync(stream, true, host, port, credentials, cancellationToken)
                        .ConfigureAwait(false);
                    return stream;
                }

                if (string.Equals(proxyUri.Scheme, "socks4", StringComparison.OrdinalIgnoreCase))
                {
                    await SocksHelper
                        .EstablishSocks4TunnelAsync(stream, false, host, port, credentials, cancellationToken)
                        .ConfigureAwait(false);
                    return stream;
                }

                if (string.Equals(proxyUri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
                {
                    var result = await HttpHelper.EstablishHttpTunnelAsync(stream, proxyUri, host, port, credentials,
                        cancellationToken);
                    return result;
                }

                if (string.Equals(proxyUri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
                {
                    var ssl = new SslStream(stream, false);
                    try
                    {
                        await ssl.AuthenticateAsClientAsync(DefaultSslOptions(proxyUri.Host), cancellationToken);
                        return await HttpHelper.EstablishHttpTunnelAsync(ssl, proxyUri, host, port, credentials,
                            cancellationToken);
                    }
                    catch
                    {
                        await ssl.DisposeAsync().ConfigureAwait(false);
                        // SslStream(leaveOpen:false) disposes inner stream,
                        // so skip the outer catch to avoid double-dispose.
                        throw;
                    }
                }

                throw new NotSupportedException($"Unsupported proxy scheme: {proxyUri.Scheme}");
            }
            catch
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }

    private static SslClientAuthenticationOptions DefaultSslOptions(string targetHost) => new()
    {
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        TargetHost = targetHost
    };
}