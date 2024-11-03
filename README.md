[![NuGet version (QuickProxyNet )](https://img.shields.io/nuget/v/QuickProxyNet?style=flat-square)](https://www.nuget.org/packages/QuickProxyNet/)

# QuickProxyNet

High performance asynchronous library for connecting to Http, Https, Socks4, Socks4a, Socks5 proxy servers.

## Usage

### Simple example

```csharp
using QuickProxyNet;

IProxyClient client = ProxyClientFactory.Instance.Create(ProxyType.Http, host, por);

Stream stream = await client.ConnectAsync("example.com", 80);
```

### With Login and Password

```csharp
using QuickProxyNet;
using System.Net;

IProxyClient client = ProxyClientFactory.Instance.Create(ProxyType.Http, host, port, new NetworkCredential("login","password"));

Stream stream = await client.ConnectAsync("example.com", 80);
```

### From URI

```csharp
Uri uri = new Uri("<protocol>://<user?>:<pass?>@host:port");
IProxyClient client = ProxyClientFactory.Instance.Create(uri);
```

### Only HTTP

```csharp
var client = new HttpProxyClient(host,port);
await client.ConnectAsync(targetHost,targetPort);
```

### Settings

ProxyClient has several settings:

