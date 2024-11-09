![](icon.png)

[![NuGet version (QuickProxyNet)](https://img.shields.io/nuget/v/QuickProxyNet?style=flat-square)](https://www.nuget.org/packages/QuickProxyNet/)

# QuickProxyNet

**QuickProxyNet** is a high-performance C# library for connecting to servers via various types of proxies, providing direct and efficient access to the underlying data stream. It supports a range of proxy protocols, including HTTP, HTTPS, SOCKS4, SOCKS4a, and SOCKS5, enabling seamless integration into .NET applications requiring proxy connections.

## Features

- **High-Performance Connection Handling**: Designed for minimal latency and optimal resource usage, allowing for efficient handling of high-load scenarios.
- **Support for Multiple Proxy Types**: Connect via HTTP, HTTPS, SOCKS4, SOCKS4a, and SOCKS5 proxies.
- **Raw Stream Access**: Upon connection, QuickProxyNet provides a raw Stream to directly interact with data, making it highly suitable for applications needing low-level network control.
- **Customizable Timeout and Connection Settings**: Configure timeouts, connection endpoints, and proxy settings for optimal network performance.

## Installation

Clone the repository or install via your preferred NuGet package manager (if available):

```dotnet add package QuickProxyNet```


## Usage

The library offers a ProxyClientFactory class to easily create proxy connections. Here’s a quick guide on how to use it.

### Example: Creating a Proxy Client

The following example shows how to create a proxy client using a URI and connect to a remote server through it:
```csharp
using System;
using System.Net;
using QuickProxyNet;

// URI of the proxy server, including protocol (e.g., "http", "socks5")
Uri proxyUri = new Uri("http://username:password@proxyserver.com:8080");

// Create a proxy client
var client = ProxyClientFactory.Instance.Create(proxyUri);

// Connect to the target server through the proxy and get a raw Stream for direct data access
using (var connectionStream = await client.ConnectAsync("destinationserver.com", 80))
{
    // Work with the Stream directly (e.g., send and receive data)
    // Example: Send HTTP request, work with binary data, etc.
}
```
### Example: Creating a Proxy Client with Custom Configuration

You can also specify the proxy type, host, port, and optional credentials:
```csharp
using System;
using System.Net;
using QuickProxyNet;

// Define proxy details
ProxyType proxyType = ProxyType.Socks5;
string proxyHost = "proxyserver.com";
int proxyPort = 1080;
NetworkCredential credentials = new NetworkCredential("username", "password");

// Create the proxy client with specified configuration
var client = ProxyClientFactory.Instance.Create(proxyType, proxyHost, proxyPort, credentials);

// Connect to the target server and obtain a raw Stream
using (var connectionStream = await client.ConnectAsync("destinationserver.com", 80))
{
    // Directly work with the Stream for low-level network operations
}
```
### Supported Proxy Types

- **HTTP**: Standard HTTP proxy with CONNECT support for tunneling.
- **HTTPS**: Supports SSL/TLS tunneling.
- **SOCKS4**: Supports IP-based connections only.
- **SOCKS4a**: Adds support for domain name resolution through the proxy.
- **SOCKS5**: Full-featured SOCKS proxy with authentication and DNS support.

## Configuration Options

Each proxy client supports various configurations to fine-tune network behavior, including:

- **WriteTimeout** and **ReadTimeout**: Specify timeouts for data send/receive operations.
- **LocalEndPoint**: Set a local endpoint for the connection if required.
- **NoDelay**: Option to disable the Nagle algorithm for reduced latency in data transmission.
- **LingerState**: Configure linger behavior for connection closure.

## License

This library is licensed under the MIT License