using System.Net;
using System.Runtime.CompilerServices;

namespace QuickProxyNet;

/// <summary>
/// Provides functionality for connecting to a server using an HTTP proxy.
/// Supports the HTTP CONNECT method for tunneling connections.
/// </summary>
public class HttpProxyClient : ProxyClient
{
    public HttpProxyClient(string host, int port) : base("http", host, port)
    {
    }

    public HttpProxyClient(string host, int port, NetworkCredential credentials) : base("http", host, port, credentials)
    {
    }

    public override ProxyType Type => ProxyType.Http;

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        var result =
            await ProxyConnector.ConnectToProxyAsync(stream, ProxyUri, host, port, ProxyCredentials, cancellationToken);
        return result;
    }
}