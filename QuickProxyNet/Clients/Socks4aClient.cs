using System.Net;
using System.Runtime.CompilerServices;

namespace QuickProxyNet;

/// <summary>
/// Provides functionality for connecting to a server using a SOCKS4a proxy.
/// Extends SOCKS4 to allow domain name resolution through the proxy itself,
/// making it useful in networks where direct DNS resolution is restricted.
/// </summary>
public class Socks4aClient : ProxyClient
{
    public Socks4aClient(string host, int port) : base("socks4a", host, port)
    {
    }

    public Socks4aClient(string host, int port, NetworkCredential credentials) : base("socks4a", host, port,
        credentials)
    {
    }


    public override ProxyType Type => ProxyType.Socks4a;


    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var result =
            await ProxyConnector.ConnectToProxyAsync(stream, ProxyUri, host, port, ProxyCredentials, cancellationToken);
        return result;
    }
}