using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace QuickProxyNet.Tests.Helpers;

/// <summary>
/// A real HTTP CONNECT proxy on a loopback socket, for what an in-memory stream cannot show:
/// which address family the client's socket can reach, and what a TLS handshake with the proxy
/// actually names. Serves one connection: reads the request head, answers 200, and holds the
/// connection open until disposed so the client never races a close against the reply.
/// </summary>
internal sealed class LoopbackConnectProxy : IDisposable
{
    private readonly TcpListener _listener;
    private readonly X509Certificate2? _certificate;
    private TcpClient? _accepted;

    /// <param name="address">The loopback address to listen on.</param>
    /// <param name="certificate">When set, the proxy speaks TLS first, as an HTTPS proxy does.</param>
    public LoopbackConnectProxy(IPAddress address, X509Certificate2? certificate = null)
    {
        _certificate = certificate;
        _listener = new TcpListener(address, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Request = ServeAsync();
    }

    public int Port { get; }

    /// <summary>The request head the client sent; completes once the 200 has been written.</summary>
    public Task<string> Request { get; }

    /// <summary>The server name the client's TLS handshake carried, when the proxy speaks TLS.</summary>
    public string? ServerName { get; private set; }

    private async Task<string> ServeAsync()
    {
        _accepted = await _listener.AcceptTcpClientAsync();
        Stream stream = _accepted.GetStream();

        if (_certificate is { } certificate)
        {
            var tls = new SslStream(stream);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificateSelectionCallback = (_, name) =>
                {
                    ServerName = name;
                    return certificate;
                }
            });
            stream = tls;
        }

        var buffer = new byte[4096];
        int length = 0;
        while (buffer.AsSpan(0, length).IndexOf("\r\n\r\n"u8) < 0)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(length));
            if (read == 0)
                throw new IOException("The client closed the connection before finishing its request.");
            length += read;
        }

        await stream.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray());
        return Encoding.ASCII.GetString(buffer, 0, length);
    }

    public void Dispose()
    {
        _accepted?.Dispose();
        _listener.Stop();
    }
}
