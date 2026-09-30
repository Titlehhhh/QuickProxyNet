using System.Net;
using System.Net.Sockets;

namespace QuickProxyNet.Tests;

/// <summary>
/// How a connect attempt ends when it is stopped rather than refused. The caller's own
/// cancellation is <see cref="OperationCanceledException"/> with the caller's token, a timeout is
/// <see cref="ProxyErrorCode.Timeout"/>, and a timeout that is still pending must not turn the
/// caller's cancellation into a timeout.
/// </summary>
/// <remarks>
/// Every case stops the attempt during the SOCKS5 handshake: the proxy accepts and never answers
/// the greeting. Stopping the TCP connect itself would need an address that neither answers nor
/// refuses, and no such address is reliable on a developer machine or in CI.
/// </remarks>
public class ConnectCancellationTest
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task CallerCancel_IsOperationCanceled_WithTheCallersToken()
    {
        using var proxy = new SilentProxy();
        var client = new Socks5Client("127.0.0.1", proxy.Port);
        using var cts = new CancellationTokenSource(Short);

        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await client.ConnectAsync("example.com", 80, cts.Token));

        Assert.Equal(cts.Token, ex.CancellationToken);
    }

    [Fact]
    public async Task CallerCancel_WhileATimeoutIsPending_IsOperationCanceled_NotTimeout()
    {
        using var proxy = new SilentProxy();
        var client = new Socks5Client("127.0.0.1", proxy.Port);
        using var cts = new CancellationTokenSource(Short);

        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await client.ConnectAsync("example.com", 80, Long, cts.Token));

        Assert.Equal(cts.Token, ex.CancellationToken);
    }

    [Fact]
    public async Task Timeout_IsTimeout()
    {
        using var proxy = new SilentProxy();
        var client = new Socks5Client("127.0.0.1", proxy.Port);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => await client.ConnectAsync("example.com", 80, Short));

        Assert.Equal(ProxyErrorCode.Timeout, ex.ErrorCode);
    }

    [Fact]
    public async Task Timeout_WithACallerTokenThatNeverFires_IsStillTimeout()
    {
        using var proxy = new SilentProxy();
        var client = new Socks5Client("127.0.0.1", proxy.Port);
        using var cts = new CancellationTokenSource();

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(
            async () => await client.ConnectAsync("example.com", 80, Short, cts.Token));

        Assert.Equal(ProxyErrorCode.Timeout, ex.ErrorCode);
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(-5000)]
    public async Task NegativeTimeout_IsArgumentOutOfRange(int milliseconds)
    {
        var client = new Socks5Client("127.0.0.1", 1080);

        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            async () => await client.ConnectAsync("example.com", 80, TimeSpan.FromMilliseconds(milliseconds)));

        Assert.Equal("timeout", ex.ParamName);
    }

    [Fact]
    public async Task InfiniteTimeout_IsAccepted()
    {
        using var proxy = new SilentProxy();
        var client = new Socks5Client("127.0.0.1", proxy.Port);
        using var cts = new CancellationTokenSource(Short);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await client.ConnectAsync("example.com", 80, Timeout.InfiniteTimeSpan, cts.Token));
    }

    /// <summary>Accepts one connection and never writes a byte.</summary>
    private sealed class SilentProxy : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly Task<TcpClient> _accepted;

        public SilentProxy()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _accepted = _listener.AcceptTcpClientAsync();
        }

        public int Port { get; }

        public void Dispose()
        {
            _listener.Stop();
            if (_accepted.IsCompletedSuccessfully)
                _accepted.Result.Dispose();
        }
    }
}
