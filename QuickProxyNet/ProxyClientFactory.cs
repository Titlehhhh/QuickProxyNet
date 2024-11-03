using System.Net;

namespace QuickProxyNet;

/// <summary>
/// Provides a factory for creating proxy client instances based on a specified URI or configuration.
/// This class simplifies the process of selecting the correct proxy type and configuring it with the necessary settings.
/// </summary>
public sealed class ProxyClientFactory
{
    /// <summary>
    /// Gets a singleton instance of the ProxyClientFactory.
    /// </summary>
    public static ProxyClientFactory Instance => new();

    /// <summary>
    /// Creates an IProxyClient instance based on the provided URI, automatically determining the proxy type
    /// and extracting credentials if they are present in the URI.
    /// </summary>
    /// <param name="proxyUri">The URI of the proxy server, including scheme, host, port, and optional credentials.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy.</returns>
    /// <exception cref="NotSupportedException">Thrown if the URI scheme is not supported.</exception>
    public IProxyClient Create(Uri proxyUri)
    {
        NetworkCredential? credential = null;
        ProxyType type = proxyUri.Scheme switch
        {
            "http" => ProxyType.Http,
            "https" => ProxyType.Https,
            "socks4" => ProxyType.Socks4,
            "socks4a" => ProxyType.Socks4a,
            "socks5" => ProxyType.Socks5,
            _ => throw new NotSupportedException($"Scheme: {proxyUri.Scheme}")
        };

        if (!string.IsNullOrEmpty(proxyUri.UserInfo))
        {
            var userAndPass = proxyUri.UserInfo.Split(':');
            credential = new NetworkCredential(userAndPass[0], userAndPass[1]);
        }

        return Create(type, proxyUri.Host, proxyUri.Port, credential);
    }

    /// <summary>
    /// Creates an IProxyClient instance based on the specified proxy type, host, and port.
    /// </summary>
    /// <param name="type">The type of proxy to create (e.g., HTTP, SOCKS5).</param>
    /// <param name="host">The hostname or IP address of the proxy server.</param>
    /// <param name="port">The port number of the proxy server.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy type.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the proxy type is unsupported.</exception>
    private IProxyClient Create(ProxyType type, string host, int port)
    {
        return type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port),
            ProxyType.Https => new HttpsProxyClient(host, port),
            ProxyType.Socks4 => new Socks4Client(host, port),
            ProxyType.Socks4a => new Socks4aClient(host, port),
            ProxyType.Socks5 => new Socks5Client(host, port),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }

    /// <summary>
    /// Creates an IProxyClient instance with optional credentials, based on the specified proxy type, host, and port.
    /// </summary>
    /// <param name="type">The type of proxy to create (e.g., HTTP, SOCKS5).</param>
    /// <param name="host">The hostname or IP address of the proxy server.</param>
    /// <param name="port">The port number of the proxy server.</param>
    /// <param name="networkCredential">Optional credentials for authenticating with the proxy server.</param>
    /// <returns>An instance of IProxyClient configured for the specified proxy type with the provided credentials.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the proxy type is unsupported.</exception>
    public IProxyClient Create(ProxyType type, string host, int port, NetworkCredential? networkCredential)
    {
        if (networkCredential is null)
        {
            return Create(type, host, port);
        }

        return type switch
        {
            ProxyType.Http => new HttpProxyClient(host, port, networkCredential),
            ProxyType.Https => new HttpsProxyClient(host, port, networkCredential),
            ProxyType.Socks4 => new Socks4Client(host, port, networkCredential),
            ProxyType.Socks4a => new Socks4aClient(host, port, networkCredential),
            ProxyType.Socks5 => new Socks5Client(host, port, networkCredential),
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }
}