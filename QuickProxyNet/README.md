# QuickProxyNet

QuickProxyNet is a high-performance .NET library for connecting to servers via various types of proxies (HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5). It offers raw Stream access for direct data handling, making it ideal for applications needing low-level network control.

## Features
- Supports HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5 proxies
- High-performance and minimal latency
- Raw Stream Access for low-level data operations
- Customizable timeout and connection settings

## Usage Example

```csharp
using QuickProxyNet;
using System;
using System.Net;

// Define the proxy URI with optional credentials
Uri proxyUri = new Uri("http://username:password@proxyserver.com:8080");

// Create a proxy client
var proxyClient = ProxyClientFactory.Instance.Create(proxyUri);

// Connect through the proxy and get a raw Stream for direct data access
using (var connectionStream = await proxyClient.ConnectAsync("destinationserver.com", 80))
{
// Work directly with the Stream
}
```