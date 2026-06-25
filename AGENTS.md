# QuickProxyNet Agent Guide

## Project Overview

QuickProxyNet is a high-performance C#/.NET library for opening direct `Stream`
connections through proxy protocols. The current core library supports HTTP,
HTTPS, SOCKS4, SOCKS4a, and SOCKS5.

- NuGet package: `QuickProxyNet`
- Author: Titlehhhh
- License: MIT
- Core targets: `net8.0`, `net9.0`, `net10.0`

## Repository Layout

```text
QuickProxyNet/            Core library and protocol logic
QuickProxyNet.Tests/      xUnit tests
QuickProxyNet.Benchmarks/ BenchmarkDotNet benchmarks
Sample/                   Console usage example
build/                    NUKE build automation
docs/                     Protocol notes and implementation research
```

## Public API Shape

All public library types live in the `QuickProxyNet` namespace.

- `Proxy` exposes static one-call `ConnectAsync(...)` helpers.
- `ProxyUriExtensions` adds `Uri.ConnectThroughProxyAsync(...)`.
- `IProxyClient` is the client contract; connection methods return
  `ValueTask<Stream>`.
- `ProxyClient` owns common socket setup, timeout handling, and argument
  validation.
- `ProxyClientFactory` creates clients from `Uri` or explicit proxy settings.
- `ProxyProtocolException` carries a structured `ProxyErrorCode`.

## Current Protocol Implementations

| Class | Protocol |
| --- | --- |
| `HttpProxyClient` | HTTP CONNECT |
| `HttpsProxyClient` | HTTPS CONNECT over TLS |
| `Socks4Client` | SOCKS4 |
| `Socks4aClient` | SOCKS4a |
| `Socks5Client` | SOCKS5 with optional username/password auth |

Internal protocol helpers live under `QuickProxyNet/Internal/`:

- `HttpHelper.cs`
- `HttpResponseParser.cs`
- `SocksHelper.cs`

## Development Rules

- Keep hot protocol paths allocation-conscious: prefer `Span<T>`,
  `Memory<T>`, `ArrayPool<byte>`, `stackalloc`, and `ValueTask`.
- Return rented buffers in `finally`.
- Use `BinaryPrimitives` for network byte order.
- Avoid LINQ in protocol hot paths.
- Keep protocol helpers `internal` unless a public API is intentionally needed.
- Public API additions must have XML documentation.
- Add new proxy types through `ProxyType`, client implementation, factory
  registration, protocol helper, error codes, and tests.
- Preserve multi-target compatibility for `net8.0`, `net9.0`, and `net10.0`.

## Testing

Run the test project directly:

```bash
dotnet test QuickProxyNet.Tests/QuickProxyNet.Tests.csproj
```

Integration tests that require real proxies use environment variables such as
`HTTP_PROXY_URI` and `SOCKS5_PROXY_URI`; they no-op when the variables are not
set.

## Build

NUKE build scripts are available from the repository root:

```bash
./build.cmd <target>   # Windows
./build.sh <target>    # Linux/macOS
```

Useful targets include restore, compile, tests, pack, and push. Versioning is
derived from git tags through MinVer.

## VPN-Style Protocol Research

Detailed notes for VLESS, VMess, Trojan, Hysteria2, hy2, and TUIC live in
`docs/`. Treat those documents as planning notes until implementation and
tests are added.
