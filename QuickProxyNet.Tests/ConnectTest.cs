using System.Text;

namespace QuickProxyNet.Tests;

/// <summary>
/// Integration tests against real proxies.
/// Set environment variables to run:
///   HTTP_PROXY_URI  = http://[user:pass@]host:port
///   SOCKS5_PROXY_URI = socks5://[user:pass@]host:port
/// A test whose variable is not set reports as <b>skipped</b> — never as passed.
/// </summary>
public class ConnectTest
{
    private const string TargetHost = "example.com";
    private const int TargetPort = 80;

    private static string Env(string name) => Environment.GetEnvironmentVariable(name)!;

    [EnvFact("HTTP_PROXY_URI")]
    public async Task HttpProxy_ConnectAndSendRequest()
    {
        var uri = new Uri(Env("HTTP_PROXY_URI"));
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

    [EnvFact("SOCKS5_PROXY_URI")]
    public async Task Socks5Proxy_ConnectAndSendRequest()
    {
        var uri = new Uri(Env("SOCKS5_PROXY_URI"));
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

    [AnyEnvFact("HTTP_PROXY_URI", "SOCKS5_PROXY_URI")]
    public async Task ExtensionMethod_ConnectThroughProxy()
    {
        var proxyUrl = SkipGates.IsSet("HTTP_PROXY_URI") ? Env("HTTP_PROXY_URI") : Env("SOCKS5_PROXY_URI");

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
