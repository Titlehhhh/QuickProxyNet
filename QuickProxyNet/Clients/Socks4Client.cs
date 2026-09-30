using System.Net;

namespace QuickProxyNet;

/// <summary>
/// Provides functionality for connecting to a server using a SOCKS4 proxy.
/// Supports basic SOCKS4 proxy features, such as IP-based connections, 
/// but does not support domain name resolution through the proxy.
/// </summary>
public class Socks4Client : ProxyClient
{
    public Socks4Client(string host, int port) : base("socks4", host, port)
    {
    }

    /// <exception cref="ArgumentException"><paramref name="credentials"/> has a NUL in its user name.</exception>
    public Socks4Client(string host, int port, NetworkCredential credentials) : base("socks4", host, port, credentials)
    {
        SocksHelper.ValidateUserId(credentials, nameof(credentials));
    }

    public override ProxyType Type => ProxyType.Socks4;


    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);
        return await ProxyConnector.ConnectToProxyAsync(stream, Type, host, port, ProxyCredentials, cancellationToken);
    }
}