using System.Net;
using System.Net.Sockets;
using System.Text;
using QuickProxyNet.Tests.Helpers;

namespace QuickProxyNet.Tests;

/// <summary>
/// <c>ConnectAsync(EndPoint)</c> names the target the way <see cref="Socket"/> does: a
/// <see cref="DnsEndPoint"/> or an <see cref="IPEndPoint"/>, never an address spelled as text.
/// </summary>
public class EndPointConnectTest
{
    private static byte[] HttpOk => Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");

    private static string Sent(FakeProxyStream stream) => Encoding.ASCII.GetString(stream.WrittenBytes);

    [Fact]
    public async Task DnsEndPoint_IsSentAsTheName()
    {
        var stream = new FakeProxyStream(HttpOk);
        var client = new HttpProxyClient("proxy.example", 8080);

        await client.ConnectAsync(stream, new DnsEndPoint("target.example", 443));

        Assert.StartsWith("CONNECT target.example:443 HTTP/1.1\r\n", Sent(stream));
    }

    [Fact]
    public async Task IPv6EndPoint_IsBracketedInConnect()
    {
        var stream = new FakeProxyStream(HttpOk);
        var client = new HttpProxyClient("proxy.example", 8080);

        await client.ConnectAsync(stream, new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));

        Assert.StartsWith("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n", Sent(stream));
    }

    [Fact]
    public async Task IPv4MappedEndPoint_GoesOnTheWireAsIPv4()
    {
        // A dual-mode socket reports an IPv4 peer as ::ffff:a.b.c.d. Passed through, SOCKS5 would
        // send address type 4 and sixteen bytes for what is an IPv4 host.
        byte[] reply = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        var stream = new FakeProxyStream(reply);
        var client = new Socks5Client("proxy.example", 1080);

        await client.ConnectAsync(stream, new IPEndPoint(IPAddress.Parse("::ffff:192.0.2.1"), 443));

        byte[] greeting = [5, 1, 0];
        byte[] request = [5, 1, 0, 1, 192, 0, 2, 1, 443 >> 8, 443 & 0xFF];
        Assert.Equal([.. greeting, .. request], stream.WrittenBytes);
    }

    [Fact]
    public async Task EndPointOfAnotherKind_IsAnArgumentException()
    {
        var client = new HttpProxyClient("proxy.example", 8080);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ConnectAsync(new FakeProxyStream(HttpOk), new UnixDomainSocketEndPoint("proxy.sock")).AsTask());
    }

    [Fact]
    public async Task NullEndPoint_IsAnArgumentNullException()
    {
        var client = new HttpProxyClient("proxy.example", 8080);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.ConnectAsync(new FakeProxyStream(HttpOk), (EndPoint)null!).AsTask());
    }

    [Fact]
    public async Task InterfaceDefaults_ForwardToTheHostAndPortOverloads()
    {
        // An IProxyClient that does not derive from ProxyClient gets the EndPoint overloads for free.
        var recording = new RecordingClient();
        IProxyClient client = recording;
        var target = new IPEndPoint(IPAddress.Parse("::ffff:192.0.2.1"), 443);

        await client.ConnectAsync(target);
        Assert.Equal(("192.0.2.1", 443, "host, port"), recording.Last);

        await client.ConnectAsync(target, TimeSpan.FromSeconds(1));
        Assert.Equal(("192.0.2.1", 443, "host, port, timeout"), recording.Last);

        await client.ConnectAsync(Stream.Null, target);
        Assert.Equal(("192.0.2.1", 443, "source, host, port"), recording.Last);
    }

    [Fact]
    public async Task ProxyConnect_WithEndPoint_TunnelsToIt()
    {
        using var proxy = new LoopbackConnectProxy(IPAddress.Loopback);

        await using Stream stream = await Proxy.ConnectAsync(
            $"http://127.0.0.1:{proxy.Port}", new DnsEndPoint("target.example", 80), TimeSpan.FromSeconds(10));

        Assert.StartsWith("CONNECT target.example:80 HTTP/1.1\r\n", await proxy.Request);
    }

    private sealed class RecordingClient : IProxyClient
    {
        public (string Host, int Port, string Overload) Last { get; private set; }

        public Uri ProxyUri { get; } = new("socks5://proxy.example:1080");
        public NetworkCredential? ProxyCredentials => null;
        public string ProxyHost => "proxy.example";
        public int ProxyPort => 1080;
        public ProxyType Type => ProxyType.Socks5;
        public IPEndPoint? LocalEndPoint { get; set; }
        public LingerOption? LingerState { get; set; }
        public bool NoDelay { get; set; }
        public int WriteTimeout { get; set; }
        public int ReadTimeout { get; set; }

        public ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default) =>
            Record(host, port, "host, port");

        public ValueTask<Stream> ConnectAsync(Stream source, string host, int port,
            CancellationToken cancellationToken = default) =>
            Record(host, port, "source, host, port");

        public ValueTask<Stream> ConnectAsync(string host, int port, TimeSpan timeout,
            CancellationToken cancellationToken = default) =>
            Record(host, port, "host, port, timeout");

        private ValueTask<Stream> Record(string host, int port, string overload)
        {
            Last = (host, port, overload);
            return ValueTask.FromResult(Stream.Null);
        }
    }
}
