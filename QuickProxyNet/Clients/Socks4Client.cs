using System.Net;
using System.Runtime.CompilerServices;

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

    public Socks4Client(string host, int port, NetworkCredential credentials) : base("socks4", host, port, credentials)
    {
    }

    public override ProxyType Type => ProxyType.Socks4;


    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var result =
            await ProxyConnector.ConnectToProxyAsync(stream, ProxyUri, host, port, ProxyCredentials, cancellationToken);
        return result;
    }
}