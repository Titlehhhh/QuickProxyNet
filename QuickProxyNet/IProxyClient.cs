using System.Net;
using System.Net.Sockets;

namespace QuickProxyNet;


/// <summary>
/// Represents a client for connecting through a proxy server.
/// </summary>
public interface IProxyClient
{
    Uri ProxyUri { get; }
    
    /// <summary>
    /// Gets the credentials used to authenticate with the proxy server, if required.
    /// </summary>
    NetworkCredential? ProxyCredentials { get; }

    /// <summary>
    /// Gets the hostname or IP address of the proxy server.
    /// </summary>
    string ProxyHost { get; }

    /// <summary>
    /// Gets the port number of the proxy server.
    /// </summary>
    int ProxyPort { get; }

    /// <summary>
    /// Gets the type of the proxy, such as HTTP, SOCKS4, SOCKS4a, or SOCKS5.
    /// </summary>
    ProxyType Type { get; }

    /// <summary>
    /// Gets or sets the local endpoint to use when establishing a connection.
    /// If not set, the default endpoint will be used.
    /// </summary>
    IPEndPoint? LocalEndPoint { get; set; }

    /// <summary>
    /// Gets or sets the linger state for the connection, determining how to handle lingering connections when closing.
    /// </summary>
    LingerOption? LingerState { get; set; }

    /// <summary>
    /// Gets or sets a value that specifies whether to disable the Nagle algorithm for this connection.
    /// If set to true, it reduces latency for small data transfers by sending packets immediately.
    /// </summary>
    bool NoDelay { get; set; }

    /// <summary>
    /// Gets or sets the write timeout in milliseconds for sending data through the proxy.
    /// </summary>
    int WriteTimeout { get; set; }

    /// <summary>
    /// Gets or sets the read timeout in milliseconds for receiving data through the proxy.
    /// </summary>
    int ReadTimeout { get; set; }

    /// <summary>
    /// Asynchronously connects to a target host and port through the proxy.
    /// </summary>
    /// <param name="host">The target host to connect to.</param>
    /// <param name="port">The target port on the host.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the connection attempt.</param>
    /// <returns>A <see cref="ValueTask"/> representing the asynchronous operation and yielding the connected <see cref="Stream"/>.</returns>
    ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously connects to a target host and port through the proxy, using an existing stream.
    /// </summary>
    /// <param name="source">The source <see cref="Stream"/> to use for establishing the connection.</param>
    /// <param name="host">The target host to connect to.</param>
    /// <param name="port">The target port on the host.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the connection attempt.</param>
    /// <returns>A <see cref="ValueTask"/> representing the asynchronous operation and yielding the connected <see cref="Stream"/>.</returns>
    ValueTask<Stream> ConnectAsync(Stream source, string host, int port, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously connects to a target host and port through the proxy, with a specified timeout.
    /// </summary>
    /// <param name="host">The target host to connect to.</param>
    /// <param name="port">The target port on the host.</param>
    /// <param name="timeout">The maximum time, in milliseconds, to wait for a connection to the host.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the connection attempt.</param>
    /// <returns>A <see cref="ValueTask"/> representing the asynchronous operation and yielding the connected <see cref="Stream"/>.</returns>
    ValueTask<Stream> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken = default);
}