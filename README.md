![](icon.png)

[![NuGet version (QuickProxyNet)](https://img.shields.io/nuget/v/QuickProxyNet?style=flat-square)](https://www.nuget.org/packages/QuickProxyNet/)
[![Build](https://img.shields.io/github/actions/workflow/status/Titlehhhh/QuickProxyNet/build.yaml?branch=master&style=flat-square)](https://github.com/Titlehhhh/QuickProxyNet/actions)

# QuickProxyNet

**QuickProxyNet** is a high-performance, zero-dependency C# library for connecting to servers through proxy protocols. It provides direct `Stream` access with minimal allocations and latency — ideal for mass proxy checking, crawlers, and any scenario where thousands of proxy connections are made in parallel.

**Targets:** .NET 8 / .NET 9 / .NET 10 / .NET 11

## Features

- **Zero runtime dependencies** — BCL only, no third-party packages
- **Zero-alloc protocol logic** — `ArrayPool`, `stackalloc`, `Utf8Formatter`, `ValueTask` throughout
- **5 classic proxy protocols** — HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5
- **3 VPN-style protocols** — VLESS, VMess (VMessAEAD), Trojan, over `tcp`, `ws` or `httpupgrade`
- **VLESS REALITY in-process** — no external binary: a managed TLS 1.3 client (ClientHello, X25519, key schedule, record layer) lives in the core package, and `VlessClient` uses it automatically when `security=reality`
- **XTLS `xtls-rprx-vision`** — the flow used by ~95% of real-world REALITY nodes
- **Share-link parsing** — pass a `vless://`, `vmess://`, `trojan://`, `socks5://`, `http://`, … string directly; no `Uri` gymnastics
- **Static one-liner API** — `Proxy.ConnectAsync(link, host, port)` for mass checkers
- **Structured error codes** — `ProxyProtocolException` with `ProxyErrorCode` enum for programmatic error handling
- **Timeout support** — per-connection timeouts with `ProxyErrorCode.Timeout`
- **Raw Stream access** — full control over the tunneled connection

## Installation

```
dotnet add package QuickProxyNet
```

## Quick Start

### One-liner from a share link (recommended)

`Proxy.ConnectAsync` and `ProxyClientFactory.Instance.Create` accept the link as a **string** and dispatch on the scheme themselves. This matters for `vmess://` links: they are base64-encoded JSON, and `System.Uri` rejects most real-world ones (host length limit, base64 padding). You no longer have to inspect the scheme yourself to pick a parser.

```csharp
// Works for http/https/socks4/socks4a/socks5/vless/trojan/vmess links
await using var stream = await Proxy.ConnectAsync(
    "socks5://user:pass@127.0.0.1:1080",
    "example.com", 443,
    TimeSpan.FromSeconds(5));
```

```csharp
// A VLESS REALITY share link — handled in-process, no Xray required
await using var stream = await Proxy.ConnectAsync(
    "vless://uuid@1.2.3.4:443?security=reality&pbk=...&sni=www.example.com&flow=xtls-rprx-vision",
    "example.com", 443,
    TimeSpan.FromSeconds(10));
```

### Extension method on Uri

```csharp
var proxy = new Uri("http://proxy.example.com:8080");
await using var stream = await proxy.ConnectThroughProxyAsync("example.com", 443);
```

### Factory API (when you need to configure the client)

```csharp
var client = ProxyClientFactory.Instance.Create("socks5://proxy:1080");
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

## VLESS REALITY

REALITY support is implemented in managed code inside the core package (`QuickProxyNet/Internal/Reality/`): a hand-written TLS 1.3 client — ClientHello construction, X25519 key exchange, the HKDF key schedule, and the record layer. There is no external process and no extra package; the zero-dependency promise holds. The `xtls-rprx-vision` flow is supported, including its padding protocol in both directions (`VisionStream`).

**Honest limitation:** the ClientHello is not yet a real browser fingerprint. There is no GREASE, no padding extension, the extension order does not match Chrome, and key_share offers bare X25519 where Chrome sends X25519MLKEM768. This does not prevent connecting or carrying traffic — verified against live servers — but DPI that fingerprints ClientHellos can tell it apart from a browser. See [docs/reality-fingerprint-plan.md](docs/reality-fingerprint-plan.md) and the `TlsClientHello` class comment for the byte-level details and the plan.

Also not implemented: Vision's TLS-in-TLS splice. It is a throughput optimization and does not affect the wire format.

## What's supported, what's not

Percentages are measured by this library's own parsers over a real-world corpus of 20 228 share links (snapshot of 2026-08-21; the list changes daily, so treat these as proportions, not constants).

| | Share of corpus | Status |
|---|---|---|
| Plain VLESS / VMess / Trojan (`tcp`, `ws`, `httpupgrade`) | 41% | Works in-process |
| VLESS REALITY (incl. `xtls-rprx-vision`) | 46% | Works in-process |
| `grpc` transport | 6.0% | Not supported in-process — use `QuickProxyNet.Reality` |
| Hysteria2 | 2.9% | No client — QUIC/datagram model doesn't fit the library's `Stream` model |
| `xhttp` transport | 2.9% | Not supported in-process — use `QuickProxyNet.Reality` |
| `xtls-rprx-vision-udp443` flow | 0.1% | Not supported |

UDP is not supported as a class: the whole library is built around `ConnectAsync(...) -> Stream`.

### The `QuickProxyNet.Reality` package

The companion package no longer exists "for REALITY" — that moved into the core. It now covers what the managed stack cannot do yet: the `grpc` and `xhttp` transports, Vision's TLS-in-TLS splice, and a genuine uTLS browser fingerprint, by driving a child Xray process. You bring the Xray binary.

## Error Handling

All proxy protocol errors throw `ProxyProtocolException` with a specific `ProxyErrorCode`:

```csharp
try
{
    await using var stream = await Proxy.ConnectAsync(proxyLink, host, port,
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
| `Vless` | VLESS (incl. REALITY, `xtls-rprx-vision`) | UUID | Yes |
| `Vmess` | VMess (VMessAEAD) | UUID | Yes |
| `Trojan` | Trojan | Password | Yes |

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
