using System.Net;

namespace QuickProxyNet;

/// <summary>
/// Provides functionality for connecting to a server using a SOCKS5 proxy.
/// Supports more advanced features than SOCKS4, including domain name resolution
/// through the proxy and authentication mechanisms if required.
/// </summary>
public class Socks5Client : ProxyClient
{
    public Socks5Client(string host, int port) : base("socks5", host, port)
    {
    }

    public Socks5Client(string host, int port, NetworkCredential credentials) : base("socks5", host, port, credentials)
    {
    }

    public override ProxyType Type => ProxyType.Socks5;


    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var result =
            await ProxyConnector.ConnectToProxyAsync(stream, ProxyUri, host, port, ProxyCredentials, cancellationToken);
        return result;
    }
}