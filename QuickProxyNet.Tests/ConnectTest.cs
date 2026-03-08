using System.Text;

namespace QuickProxyNet.Tests;

/// <summary>
/// Integration tests against real proxies.
/// Set environment variables to run:
///   HTTP_PROXY_URI  = http://[user:pass@]host:port
///   SOCKS5_PROXY_URI = socks5://[user:pass@]host:port
/// Tests are skipped if the variable is not set.
/// </summary>
public class ConnectTest
{
    private const string TargetHost = "example.com";
    private const int TargetPort = 80;

    private static string? GetEnv(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

    [Fact]
    public async Task HttpProxy_ConnectAndSendRequest()
    {
        var proxyUrl = GetEnv("HTTP_PROXY_URI");
        if (proxyUrl is null) return; // skip: "HTTP_PROXY_URI not set");

        var uri = new Uri(proxyUrl);
        await using var stream = await Proxy.ConnectAsync(uri, TargetHost, TargetPort,
            TimeSpan.FromSeconds(10));

        // Send a minimal HTTP GET and verify we get a response
        var request = Encoding.UTF8.GetBytes($"GET / HTTP/1.1\r\nHost: {TargetHost}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request);

        var buf = new byte[1024];
        int read = await stream.ReadAsync(buf);
        Assert.True(read > 0);

        var response = Encoding.UTF8.GetString(buf, 0, read);
        Assert.StartsWith("HTTP/1.", response);
    }

    [Fact]
    public async Task Socks5Proxy_ConnectAndSendRequest()
    {
        var proxyUrl = GetEnv("SOCKS5_PROXY_URI");
        if (proxyUrl is null) return; // skip: "SOCKS5_PROXY_URI not set");

        var uri = new Uri(proxyUrl);
        await using var stream = await Proxy.ConnectAsync(uri, TargetHost, TargetPort,
            TimeSpan.FromSeconds(10));

        var request = Encoding.UTF8.GetBytes($"GET / HTTP/1.1\r\nHost: {TargetHost}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request);

        var buf = new byte[1024];
        int read = await stream.ReadAsync(buf);
        Assert.True(read > 0);

        var response = Encoding.UTF8.GetString(buf, 0, read);
        Assert.StartsWith("HTTP/1.", response);
    }

    [Fact]
    public async Task ExtensionMethod_ConnectThroughProxy()
    {
        var proxyUrl = GetEnv("HTTP_PROXY_URI") ?? GetEnv("SOCKS5_PROXY_URI");
        if (proxyUrl is null) return; // skip: "No proxy URI set");

        var uri = new Uri(proxyUrl);
        await using var stream = await uri.ConnectThroughProxyAsync(TargetHost, TargetPort,
            TimeSpan.FromSeconds(10));

        var request = Encoding.UTF8.GetBytes($"GET / HTTP/1.1\r\nHost: {TargetHost}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request);

        var buf = new byte[1024];
        int read = await stream.ReadAsync(buf);
        Assert.True(read > 0);
    }
}
