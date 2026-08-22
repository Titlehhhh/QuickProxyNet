using System.Text;
using QuickProxyNet;

// Paste any supported link — the library reads the scheme itself:
//   socks5://user:pass@host:1080
//   http://host:8080
//   vless://uuid@host:443?security=reality&pbk=...&sid=...&sni=...&flow=xtls-rprx-vision
//   trojan://password@host:443?sni=...
//   vmess://<base64 json>
Console.Write("Proxy link: ");
string? link = Console.ReadLine();
if (string.IsNullOrWhiteSpace(link))
    return;

const string Host = "example.com";

try
{
    await using Stream stream = await Proxy.ConnectAsync(link, Host, 80, TimeSpan.FromSeconds(10));

    await stream.WriteAsync(Encoding.ASCII.GetBytes(
        $"GET / HTTP/1.1\r\nHost: {Host}\r\nConnection: close\r\n\r\n"));
    await stream.FlushAsync();

    using var reader = new StreamReader(stream, Encoding.ASCII);
    Console.WriteLine(await reader.ReadToEndAsync());
}
catch (ProxyProtocolException ex)
{
    // Every protocol failure — classic or VPN-style, REALITY included — arrives here with a code.
    Console.Error.WriteLine($"{ex.ErrorCode}: {ex.Message}");
}
catch (NotSupportedException ex)
{
    // The link parsed, but names a transport or flow this library does not implement.
    Console.Error.WriteLine(ex.Message);
}
