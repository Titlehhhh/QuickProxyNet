using System.Net;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

/// <summary>
/// The socket opened to the proxy must reach it by either address family. It used to be created
/// IPv4-only, so a proxy at an IPv6 address failed with <see cref="NotSupportedException"/> inside
/// the connect guard and reached the caller as <see cref="ProxyErrorCode.ConnectionFailed"/>: a
/// healthy node, reported dead.
/// </summary>
public class DualStackConnectTest
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    [IPv6LoopbackFact]
    public async Task Client_ReachesProxyOnIPv6()
    {
        using var proxy = new LoopbackConnectProxy(IPAddress.IPv6Loopback);
        var client = new HttpProxyClient("::1", proxy.Port);
        using var cts = new CancellationTokenSource(Deadline);

        await using Stream stream = await client.ConnectAsync("example.com", 80, cts.Token);

        Assert.StartsWith("CONNECT example.com:80 HTTP/1.1\r\n", await proxy.Request);
    }

    [IPv6LoopbackFact]
    public async Task Client_WithTimeout_ReachesProxyOnIPv6()
    {
        using var proxy = new LoopbackConnectProxy(IPAddress.IPv6Loopback);
        var client = new HttpProxyClient("::1", proxy.Port);

        await using Stream stream = await client.ConnectAsync("example.com", 80, Deadline);

        Assert.StartsWith("CONNECT example.com:80 HTTP/1.1\r\n", await proxy.Request);
    }

    [IPv6LoopbackFact]
    public async Task UriFastPath_ReachesProxyOnIPv6()
    {
        using var proxy = new LoopbackConnectProxy(IPAddress.IPv6Loopback);

        await using Stream stream = await Proxy.ConnectAsync(
            new Uri($"http://[::1]:{proxy.Port}"), "example.com", 80, Deadline);

        Assert.StartsWith("CONNECT example.com:80 HTTP/1.1\r\n", await proxy.Request);
    }

    [Fact]
    public async Task Client_BoundToIPv4LocalEndPoint_ReachesProxyOnIPv4()
    {
        // A LocalEndPoint decides the family: an IPv4 address must be bound on an IPv4 socket,
        // not tried on the dual-mode one an unbound client gets.
        using var proxy = new LoopbackConnectProxy(IPAddress.Loopback);
        var client = new HttpProxyClient("127.0.0.1", proxy.Port)
        {
            LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 0)
        };

        await using Stream stream = await client.ConnectAsync("example.com", 80, Deadline);

        Assert.StartsWith("CONNECT example.com:80 HTTP/1.1\r\n", await proxy.Request);
    }
}
