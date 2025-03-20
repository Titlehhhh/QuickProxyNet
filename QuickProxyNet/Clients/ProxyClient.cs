using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace QuickProxyNet;

public abstract class ProxyClient : IProxyClient
{
    private ProxyClient(Uri uri)
    {
        ProxyUri = uri;

        ProxyHost = uri.Host;
        ProxyPort = uri.Port;

        if (!string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            var credentials = uri.UserInfo.Split(':');
            if (credentials.Length != 2)
            {
                throw new ArgumentException("Invalid credentials format.", nameof(uri.UserInfo));
            }

            ProxyCredentials = new NetworkCredential(credentials[0], credentials[1]);
        }
    }

    protected ProxyClient(string protocol, string host, int port)
    {
        ProxyUri = new Uri($"{protocol}://{host}:{port}");

        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port < 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        ProxyHost = host;
        ProxyPort = port == 0 ? 1080 : port;
    }

    protected ProxyClient(string protocol, string host, int port, NetworkCredential credentials)
    {
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port < 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        if (credentials == null)
            throw new ArgumentNullException(nameof(credentials));

        ProxyHost = host;
        ProxyPort = port == 0 ? 1080 : port;

        ProxyUri = new Uri($"{protocol}://{credentials.UserName}:{credentials.Password}@{host}:{port}");
        ProxyCredentials = credentials;
    }

    public Uri ProxyUri { get; private set; }
    public abstract ProxyType Type { get; }

    public NetworkCredential? ProxyCredentials { get; }

    public string ProxyHost { get; }

    public int ProxyPort { get; }

    public IPEndPoint? LocalEndPoint { get; set; }

    public LingerOption? LingerState { get; set; } = new LingerOption(true, 0);
    public bool NoDelay { get; set; } = true;

    public int WriteTimeout { get; set; }
    public int ReadTimeout { get; set; }
    
    private static void OnDisposeSocket(object? state)
    {
        if (state is Socket socket)
        {
            socket.Dispose();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private Socket CreateSocket()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = this.NoDelay,
            LingerState = this.LingerState,
            SendTimeout = this.WriteTimeout,
            ReceiveTimeout = this.ReadTimeout
        };
        if (LocalEndPoint is not null)
            socket.Bind(LocalEndPoint);
        return socket;
    }

    public async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        cancellationToken.ThrowIfCancellationRequested();

        var socket = CreateSocket();

        await using var reg = cancellationToken.Register(OnDisposeSocket, socket);
        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var stream = new NetworkStream(socket, true);
        try
        {
            return await ConnectAsync(stream, host, port, cancellationToken);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    


    public virtual async ValueTask<Stream> ConnectAsync(string host, int port, TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        cancellationToken.ThrowIfCancellationRequested();

        var socket = CreateSocket();
        await using var reg = cancellationToken.Register(s => ((IDisposable)s).Dispose(), socket);
        
        await using ITimer timer =
            TimeProvider.System.CreateTimer(OnDisposeSocket, socket, timeout, Timeout.InfiniteTimeSpan);


        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var stream = new NetworkStream(socket, true);
        try
        {
            return await ConnectAsync(stream, host, port, cancellationToken);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    public abstract ValueTask<Stream> ConnectAsync(Stream source, string host, int port,
        CancellationToken cancellationToken = default);

    internal static void ValidateArguments(string host, int port)
    {
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port <= 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));
    }
}