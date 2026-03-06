# QuickProxyNet — CLAUDE.md

## Project Overview

**QuickProxyNet** is a high-performance C# .NET library for connecting to servers through proxy protocols (HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5). It provides direct `Stream` access for low-level networking with minimal allocations and latency.

- **NuGet package:** `QuickProxyNet`
- **Author:** Titlehhhh
- **License:** MIT
- **Targets:** net8.0, net9.0, net10.0

## Solution Structure

```
QuickProxyNet/           — Core library (public API + internal protocol logic)
QuickProxyNet.Tests/     — XUnit tests (net8.0)
QuickProxyNet.Benchmarks/— BenchmarkDotNet benchmarks (net8.0)
QuickProxyNet.Pipelines/ — Experimental System.IO.Pipelines rewrite (net8.0)
Sample/                  — Usage example console app
build/                   — Nuke build automation
```

## Core Architecture

**Namespace:** `QuickProxyNet` (all public types)

### Public API

- **`IProxyClient`** — main interface: `ConnectAsync(host, port, ...)` returns `ValueTask<Stream>`
- **`ProxyClient`** — abstract base with socket creation, timeout, and error handling
- **`ProxyClientFactory`** — singleton factory: creates clients from `Uri` or explicit parameters
- **`ProxyType`** — enum: `Http`, `Https`, `Socks4`, `Socks4a`, `Socks5`
- **`ProxyProtocolException`** — custom exception with `ProxyErrorCode` enum

### Client Implementations (`QuickProxyNet/Clients/`)

| Class | Protocol |
|---|---|
| `HttpProxyClient` | HTTP CONNECT tunnel |
| `HttpsProxyClient` | HTTPS CONNECT + SSL/TLS |
| `Socks4Client` | SOCKS4 (IP only) |
| `Socks4aClient` | SOCKS4a (domain names) |
| `Socks5Client` | SOCKS5 (full, with auth) |

### Internal Helpers (`QuickProxyNet/Internal/`)

- **`SocksHelper.cs`** — SOCKS4/4a/5 binary protocol (RFC-compliant, 313 lines)
- **`HttpHelper.cs`** — HTTP CONNECT with `PreallocatedStream` for header reuse (314 lines)
- **`ProxyConnector.cs`** — routes to the right tunnel method
- **`HttpResponseParser.cs`** — HTTP response parsing
- **`ConnectHelper.cs`** — SSL/TLS helpers with cert validation mapping
- **`CancellationHelper.cs`** — cancellation + exception utilities

## Key Dependencies

| Package | Purpose |
|---|---|
| `DotNext` 5.25.x | Advanced .NET utilities (buffers, memory, text) |
| `DotNext.IO` 5.25.x | I/O pipeline utilities, `SpanWriter<T>` |
| `ZString` 2.6.0 | Zero-alloc string building (Cysharp) |
| `ConfigureAwait.Fody` | IL weaving — ConfigureAwait on all awaits |
| `System.IO.Pipelines` | Pipelines project only |

## Code Style & Patterns

### C# Settings (all projects)
- `ImplicitUsings`, `Nullable`, `LangVersion: latest`
- `AllowUnsafeBlocks: true` (performance-critical paths)

### Performance Patterns (follow these in all changes)
- **`ValueTask<T>`** everywhere for async — no unnecessary `Task` allocations
- **`ArrayPool<byte>.Shared.Rent/Return`** for temporary buffers
- **`stackalloc`** for small stack buffers (`stackalloc char[256]`)
- **`ReadOnlySpan<T>` / `Memory<T>`** for buffer slices
- **`SpanWriter<byte>`** (from DotNext) for binary protocol writing
- **`[MethodImpl(AggressiveInlining | AggressiveOptimization)]`** on hot paths
- **`PreallocatedStream`** pattern to recycle response buffers without allocation
- **`BinaryPrimitives.WriteUInt16BigEndian`** for big-endian network byte order

### Architecture Patterns
- Factory pattern (`ProxyClientFactory`)
- Template method / abstract base (`ProxyClient`)
- Strategy pattern (proxy type selection)
- Internal implementation hidden behind `internal` keyword

### Error Handling
- All proxy errors → `ProxyProtocolException` with specific `ProxyErrorCode`
- Socket exceptions translated to protocol exceptions in `ProxyClient`
- Timeout via `TimeProvider.System.CreateTimer()`

## Build System

**NUKE** build automation (`build/Build.cs`).

```bash
# Run via scripts in repo root:
./build.sh <target>       # Linux/macOS
./build.cmd <target>      # Windows

# Key targets:
Restore    # Restore NuGet packages
Compile    # Build all projects
Tests      # Run xUnit tests
Pack       # Create NuGet package (Release mode)
Push       # Publish to NuGet / GitHub Packages
```

Versioning: **GitVersion** 5.12.0 (git-based semantic versioning).

## Testing

**Framework:** xUnit 2.5.3, coverlet for coverage

```bash
dotnet test QuickProxyNet.Tests/
```

Test files:
- `FactoryTest.cs` — URI parsing, credentials, unsupported protocols
- `InternalTest.cs` — HTTP response parser (in progress)
- `ConnectTest.cs` — connection tests (in progress)

Tests are sparse — prefer adding integration tests for new protocol behavior.

## Experimental Branch: `experimental/pipelines-lib`

The `QuickProxyNet.Pipelines/` project rewrites the internals using `System.IO.Pipelines`:
- Uses `IDuplexPipe` instead of `Stream`
- `IBufferWriter<byte>` + `SpanWriter<byte>` for writing
- Sequence-based reading (eliminates manual `ArrayPool` management)
- Currently covers SOCKS4/4a protocol; work in progress

## Important Notes for Development

1. **No LINQ** in hot paths — allocates enumerators.
2. **No `async void`** — always use `async Task` or `async ValueTask`.
3. **Always release `ArrayPool` rentals** in `finally` blocks.
4. **Public API must be XML-documented** — `GenerateDocumentationFile` is enabled.
5. **ConfigureAwait** is handled by Fody weaving — do not add manually.
6. **Multi-targeting** — changes in `QuickProxyNet/` must be compatible with net8, net9, net10.
7. **`ProxyErrorCode`** — add new codes there before throwing new exception types.
8. When editing protocol logic, validate against the relevant RFC:
   - SOCKS4/4a: no official RFC, de-facto standard
   - SOCKS5: RFC 1928 + RFC 1929 (auth)
   - HTTP CONNECT: RFC 9110

## Common Tasks

### Add a new proxy type
1. Add value to `ProxyType` enum
2. Create `NewProxyClient.cs` in `Clients/` extending `ProxyClient`
3. Register in `ProxyClientFactory` switch
4. Add `ProxyErrorCode` values as needed
5. Write tests in `FactoryTest.cs` and a connection test

### Add/modify protocol helper
- Edit `Internal/SocksHelper.cs` or `Internal/HttpHelper.cs`
- Keep all types `internal`
- Prefer `SpanWriter<byte>` over manual array indexing
- Use `ReadExactlyAsync()` (from `Ext.cs`) for exact-length reads

### Run benchmarks
```bash
cd QuickProxyNet.Benchmarks
dotnet run -c Release
```
