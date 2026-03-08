![](icon.png)

[![NuGet version (QuickProxyNet)](https://img.shields.io/nuget/v/QuickProxyNet?style=flat-square)](https://www.nuget.org/packages/QuickProxyNet/)
[![Build](https://img.shields.io/github/actions/workflow/status/Titlehhhh/QuickProxyNet/build.yaml?branch=master&style=flat-square)](https://github.com/Titlehhhh/QuickProxyNet/actions)

# QuickProxyNet

**QuickProxyNet** is a high-performance, zero-dependency C# library for connecting to servers through proxy protocols. It provides direct `Stream` access with minimal allocations and latency — ideal for mass proxy checking, crawlers, and any scenario where thousands of proxy connections are made in parallel.

**Targets:** .NET 8 / .NET 9 / .NET 10

## Features

- **Zero runtime dependencies** — BCL only, no third-party packages
- **Zero-alloc protocol logic** — `ArrayPool`, `stackalloc`, `Utf8Formatter`, `ValueTask` throughout
- **5 proxy protocols** — HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5
- **Static one-liner API** — `Proxy.ConnectAsync(uri, host, port)` for mass checkers
- **Structured error codes** — `ProxyProtocolException` with `ProxyErrorCode` enum for programmatic error handling
- **Timeout support** — per-connection timeouts with `ProxyErrorCode.Timeout`
- **Raw Stream access** — full control over the tunneled connection

## Installation

```
dotnet add package QuickProxyNet
```

## Quick Start

### One-liner (recommended for mass checking)

```csharp
// Single call — no intermediate objects allocated
await using var stream = await Proxy.ConnectAsync(
    new Uri("socks5://user:pass@127.0.0.1:1080"),
    "example.com", 443,
    TimeSpan.FromSeconds(5));
```

### Extension method on Uri

```csharp
var proxy = new Uri("http://proxy.example.com:8080");
await using var stream = await proxy.ConnectThroughProxyAsync("example.com", 443);
```

### Factory API (when you need to configure the client)

```csharp
var client = ProxyClientFactory.Instance.Create(new Uri("socks5://proxy:1080"));
client.NoDelay = true;
client.ReadTimeout = 5000;

await using var stream = await client.ConnectAsync("example.com", 443);
```

### With explicit proxy type and credentials

```csharp
var creds = new NetworkCredential("user", "pass");
var client = ProxyClientFactory.Instance.Create(
    ProxyType.Socks5, "proxy.example.com", 1080, creds);

await using var stream = await client.ConnectAsync("example.com", 80,
    TimeSpan.FromSeconds(10));
```

## Error Handling

All proxy protocol errors throw `ProxyProtocolException` with a specific `ProxyErrorCode`:

```csharp
try
{
    await using var stream = await Proxy.ConnectAsync(proxyUri, host, port,
        TimeSpan.FromSeconds(5));
}
catch (ProxyProtocolException ex)
{
    switch (ex.ErrorCode)
    {
        case ProxyErrorCode.Timeout:
            // Connection timed out
            break;
        case ProxyErrorCode.ConnectionFailed:
            // Could not reach the proxy (includes proxy host:port in message)
            break;
        case ProxyErrorCode.AuthRequired:
            // Proxy requires credentials (HTTP 407)
            break;
        case ProxyErrorCode.AuthFailed:
            // Wrong username/password
            break;
        case ProxyErrorCode.InvalidResponse:
            // Proxy returned garbage
            break;
    }
    // ex.Message includes proxy host:port and target host:port
    // ex.InnerException contains the original SocketException/IOException
}
```

### Error Codes

| Code | Description |
|---|---|
| `Timeout` | Connection timed out |
| `ConnectionFailed` | Failed to connect to the proxy server |
| `AuthRequired` | Proxy requires authentication (HTTP 407) |
| `AuthFailed` | Authentication credentials rejected |
| `InvalidResponse` | Proxy returned an invalid/unparseable response |
| `SocksUnexpectedVersion` | SOCKS protocol version mismatch |
| `SocksNoAuthMethod` | No suitable SOCKS5 auth method |
| `SocksBadAddressType` | Unknown SOCKS5 address type |
| `SocksIPv6NotSupported` | SOCKS4 does not support IPv6 |
| `SocksNoIPv4Address` | Failed to resolve host to IPv4 (SOCKS4) |
| `SocksStringTooLong` | SOCKS field exceeded 255-byte limit |

## Supported Proxy Types

| Type | Protocol | Auth | DNS through proxy |
|---|---|---|---|
| `Http` | HTTP CONNECT | Basic | No |
| `Https` | HTTPS CONNECT + TLS | Basic | No |
| `Socks4` | SOCKS4 | UserId | No (resolved locally) |
| `Socks4a` | SOCKS4a | UserId | Yes |
| `Socks5` | SOCKS5 (RFC 1928) | Username/Password (RFC 1929) | Yes |

## Configuration Options

When using the factory/client API, each client supports:

| Property | Default | Description |
|---|---|---|
| `NoDelay` | `true` | Disable Nagle algorithm |
| `LingerState` | `Linger(true, 0)` | Socket linger on close |
| `ReadTimeout` | `0` (infinite) | Read timeout in ms |
| `WriteTimeout` | `0` (infinite) | Write timeout in ms |
| `LocalEndPoint` | `null` | Bind to specific local IP |

## License

MIT
