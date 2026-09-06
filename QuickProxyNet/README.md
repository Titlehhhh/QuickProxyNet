# QuickProxyNet

High-performance, zero-dependency C# library for connecting through HTTP, HTTPS, SOCKS4, SOCKS4a and SOCKS5 proxies, and through the VPN-style protocols VLESS, VMess and Trojan. Returns a raw `Stream` for direct data access.

VLESS REALITY works in-process — the TLS 1.3 handshake it needs is implemented here (including the `xtls-rprx-vision` flow), so it costs no extra package and no external binary, and the zero-dependency promise still holds. Its ClientHello is not yet a browser fingerprint; see `docs/reality-fingerprint-plan.md` in the repository for what that means.

No companion package and no external binary are involved. The `grpc` and `xhttp` transports, Vision's TLS-in-TLS splice, and a genuine uTLS browser fingerprint are not implemented.

**Targets:** .NET 8 / .NET 9 / .NET 10 / .NET 11

## Quick Start

`Proxy.ConnectAsync` takes the share link as a string and dispatches on the scheme itself — including `vmess://` links, whose base64 payload `System.Uri` cannot parse.

```csharp
// Works for http/https/socks4/socks4a/socks5/vless/trojan/vmess links
await using var stream = await Proxy.ConnectAsync(
    "socks5://user:pass@127.0.0.1:1080",
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
- VLESS REALITY and `xtls-rprx-vision` in-process, no Xray binary
- Structured errors: `ProxyProtocolException` with `ProxyErrorCode` enum
- Per-connection timeouts with `ProxyErrorCode.Timeout`
- Static API (`Proxy.ConnectAsync`) and factory API (`Proxy.Create(link)`)

## Error Handling

```csharp
try
{
    await using var stream = await Proxy.ConnectAsync(proxyLink, host, port,
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

See [full documentation](https://github.com/Titlehhhh/QuickProxyNet) for all error codes, the support matrix, and configuration options.
