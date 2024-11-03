using System.Net;

namespace QuickProxyNet;

public sealed class ProxyClientFactory
{
    public static ProxyClientFactory Instance => new();

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