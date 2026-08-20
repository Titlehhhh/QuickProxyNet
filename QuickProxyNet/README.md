# QuickProxyNet

High-performance, zero-dependency C# library for connecting through HTTP, HTTPS, SOCKS4, SOCKS4a and SOCKS5 proxies, and through the VPN-style protocols VLESS, VMess and Trojan. Returns a raw `Stream` for direct data access.

VLESS REALITY lives in the separate `QuickProxyNet.Reality` package, so the core keeps its zero-dependency promise.

**Targets:** .NET 8 / .NET 9 / .NET 10 / .NET 11

## Quick Start

```csharp
// One-liner — ideal for mass proxy checking
await using var stream = await Proxy.ConnectAsync(
    new Uri("socks5://user:pass@127.0.0.1:1080"),
    "example.com", 443,
    TimeSpan.FromSeconds(5));
```

Or via extension method:

```csharp
await using var stream = await new Uri("http://proxy:8080")
    .ConnectThroughProxyAsync("example.com", 443);
```

## Features

- Zero runtime dependencies (BCL only)
- Zero-alloc protocol logic (`ArrayPool`, `stackalloc`, `Utf8Formatter`, `ValueTask`)
- Structured errors: `ProxyProtocolException` with `ProxyErrorCode` enum
- Per-connection timeouts with `ProxyErrorCode.Timeout`
- Static API (`Proxy.ConnectAsync`) and factory API (`ProxyClientFactory`)

## Error Handling

```csharp
try
{
    await using var stream = await Proxy.ConnectAsync(proxyUri, host, port,
        TimeSpan.FromSeconds(5));
}
catch (ProxyProtocolException ex) when (ex.ErrorCode == ProxyErrorCode.Timeout)
{
    // Timed out — ex.Message includes proxy and target host:port
}
catch (ProxyProtocolException ex) when (ex.ErrorCode == ProxyErrorCode.AuthFailed)
{
    // Wrong credentials
}
```

See [full documentation](https://github.com/Titlehhhh/QuickProxyNet) for all error codes and configuration options.
