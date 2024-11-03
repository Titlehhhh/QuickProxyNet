[![NuGet version (QuickProxyNet )](https://img.shields.io/nuget/v/QuickProxyNet?style=flat-square)](https://www.nuget.org/packages/QuickProxyNet/)

# QuickProxyNet

High performance asynchronous library for connecting to Http, Https, Socks4, Socks4a, Socks5 proxy servers.

## Usage

```csharp
using QuickProxyNet;

IProxyClient client = ProxyClientFactory.Instance.Create(ProxyType.Http, "123.123.123.123", "5500");

Stream stream = await client.ConnectAsync("example.com", 80);
```