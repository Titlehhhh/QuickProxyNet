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
            var sep = uri.UserInfo.IndexOf(':');
            if (sep < 0)
                throw new ArgumentException("Invalid credentials format.", nameof(uri.UserInfo));

            ProxyCredentials = new NetworkCredential(
                uri.UserInfo.Substring(0, sep),
                uri.UserInfo.Substring(sep + 1));
        }
    }

    protected ProxyClient(string protocol, string host, int port)
    {
        if (host == null)
            throw new ArgumentNullException(nameof(host));

        if (host.Length == 0 || host.Length > 255)
            throw new ArgumentException("The length of the host name must be between 0 and 256 characters.",
                nameof(host));

        if (port < 0 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));

        ProxyHost = host;
        ProxyPort = port == 0 ? 1080 : port;
        ProxyUri = new Uri($"{protocol}://{host}:{port}");
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

    private Socket CreateSocket()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = this.NoDelay,
            SendTimeout = this.WriteTimeout,
            ReceiveTimeout = this.ReadTimeout
        };
        if (LingerState is not null)
            socket.LingerState = LingerState;
        if (LocalEndPoint is not null)
            socket.Bind(LocalEndPoint);
        return socket;
    }

    public async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        cancellationToken.ThrowIfCancellationRequested();

        var socket = CreateSocket();

        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch (Exception ex)
        {
            socket.Dispose();
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Failed to connect to proxy {ProxyHost}:{ProxyPort} for target {host}:{port}.", ex);
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
        var timedOut = new StrongBox<bool>(false);

        await using ITimer timer = TimeProvider.System.CreateTimer(
            static s =>
            {
                var state = (Tuple<Socket, StrongBox<bool>>)s!;
                Volatile.Write(ref state.Item2.Value, true);
                state.Item1.Dispose();
            },
            Tuple.Create(socket, timedOut), timeout, Timeout.InfiniteTimeSpan);

        try
        {
            await socket.ConnectAsync(ProxyHost, ProxyPort, cancellationToken);
        }
        catch (Exception ex)
        {
            socket.Dispose();
            if (Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {ProxyHost}:{ProxyPort} timed out after {timeout}.", ex);
            throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                $"Failed to connect to proxy {ProxyHost}:{ProxyPort} for target {host}:{port}.", ex);
        }

        var stream = new NetworkStream(socket, true);
        try
        {
            return await ConnectAsync(stream, host, port, cancellationToken);
        }
        catch (Exception ex)
        {
            await stream.DisposeAsync();
            if (Volatile.Read(ref timedOut.Value))
                throw new ProxyProtocolException(ProxyErrorCode.Timeout,
                    $"Connection to proxy {ProxyHost}:{ProxyPort} timed out after {timeout}.", ex);
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
