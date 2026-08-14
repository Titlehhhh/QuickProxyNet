# QuickProxyNet Agent Guide

## Project Overview

QuickProxyNet is a high-performance C#/.NET library for opening direct `Stream`
connections through proxy protocols. It covers the classic proxy family (HTTP,
HTTPS, SOCKS4, SOCKS4a, SOCKS5) and the VPN-style family (VLESS, Trojan, VMess).

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
tools/CorpusCheck/        Manual diagnostic: share-link parsers vs a real-world corpus
tests/docker/             Xray + sing-box servers for the integration tests
```

`tools/CorpusCheck` is deliberately **not** in `QuickProxyNet.slnx`: it is a
hand-run diagnostic, and keeping it out of the solution keeps it out of CI.

## Public API Shape

All public library types live in the `QuickProxyNet` namespace.

- `Proxy` exposes static one-call `ConnectAsync(...)` helpers.
- `ProxyUriExtensions` adds `Uri.ConnectThroughProxyAsync(...)`.
- `IProxyClient` is the client contract; connection methods return
  `ValueTask<Stream>`.
- `ProxyClient` owns common socket setup, timeout handling, and argument
  validation.
- `ProxyClientFactory` creates clients from a share-link `string`, from a `Uri`,
  or from explicit proxy settings.
- `ProxyProtocolException` carries a structured `ProxyErrorCode`.
- `VlessOptions` / `TrojanOptions` / `VmessOptions` plus the matching
  `*ShareLink.Parse` / `TryParse` describe a VPN-style endpoint.

## Current Protocol Implementations

| Class | Protocol |
| --- | --- |
| `HttpProxyClient` | HTTP CONNECT |
| `HttpsProxyClient` | HTTPS CONNECT over TLS |
| `Socks4Client` | SOCKS4 |
| `Socks4aClient` | SOCKS4a |
| `Socks5Client` | SOCKS5 with optional username/password auth |
| `VlessClient` | VLESS, `security=none` or `tls` |
| `TrojanClient` | Trojan over TLS |
| `VmessClient` | VMess (VMessAEAD, `alterId=0`), optional TLS |

All three run over any of three transports: `tcp`/`raw`, `ws`/`websocket`, `httpupgrade`.
`grpc`, `xhttp` and `h2` are rejected with `NotSupportedException` before any byte is
written.

Internal protocol helpers live under `QuickProxyNet/Internal/`:

```text
Internal/HttpHelper.cs            HTTP CONNECT request/response
Internal/HttpResponseParser.cs
Internal/SocksHelper.cs           SOCKS4/4a/5
Internal/ProxyAddress.cs          shared atyp/host/port encoding
Internal/VlessHelper.cs           VLESS request header
Internal/VlessResponseStream.cs   lazy VLESS response-header reader
Internal/TrojanHelper.cs          Trojan request header
Internal/PrefixedStream.cs        replays handshake overread bytes
Internal/Transports/ProxyTransport.cs        transport resolution + layering
Internal/Transports/HttpUpgradeHandshake.cs  the shared HTTP upgrade exchange
Internal/Transports/WebSocketStream.cs       RFC 6455 framing as a Stream
Internal/Crypto/Sha224.cs         SHA-224/SHA-256 core (Trojan password hash, VMess KDF)
Internal/Crypto/Crc32.cs          CRC-32/IEEE (VMess header checksum)
Internal/Crypto/Fnv1a32.cs        FNV-1a (VMess body chunk verification)
Internal/Crypto/UuidCodec.cs      big-endian UUID encoding + Xray's non-UUID id derivation
Internal/Vmess/VmessKdf.cs        VMessAEAD KDF
Internal/Vmess/VmessAuthId.cs     16-byte encrypted auth id
Internal/Vmess/VmessCmdKey.cs     cmdKey derivation
Internal/Vmess/VmessRequest.cs    sealed request header
Internal/Vmess/VmessResponse.cs   response header
Internal/Vmess/VmessResponseStream.cs  lazy response-header reader
Internal/Vmess/VmessStream.cs     AEAD chunk framing
```

## Hard-Won Protocol Knowledge

Every item below cost a separate investigation. Do not re-derive them, and do
not "clean up" any of them without reading the reasoning first.

1. **The namespace is flat.** Every type is in `QuickProxyNet` regardless of its
   folder. This is load-bearing: it lets files move between folders without a
   breaking API change. `IDE0130` (namespace must match folder) is suppressed in
   `.editorconfig` on purpose. Do **not** "fix" it by renaming namespaces.

2. **VMess *and VLESS* read their response header lazily.**
   `VmessResponseStream` decodes the sealed response header, and
   `VlessResponseStream` validates `ver + addonsLen`, on the first `Read` — not in
   `ConnectAsync`. Reading either eagerly deadlocks every protocol where the
   client speaks first (HTTP, TLS, Minecraft): the server only flushes its header
   once the target has replied.

   VLESS was originally eager, and the byte-exact vectors could not see it —
   `FakeProxyStream` always has the response already buffered. `DockerProtocolTests`
   caught it immediately: all five VLESS cases timed out against **both** Xray and
   sing-box. A raw probe confirmed the cause: writing the VLESS request and then
   reading two bytes hangs on both servers, while writing the request and an HTTP
   GET together returns `00 00` followed by the HTTP response. This is why the
   integration tests exist — a vector proves the bytes are right, not that a server
   will talk to us.

   Consequence: a rejected VLESS handshake (wrong id — both servers just drop the
   connection) surfaces as a `ProxyProtocolException` on the first `Read`, not from
   `ConnectAsync`. That is inherent to the protocol, not a regression; the server
   sends nothing at connect time either way.

3. **The VMess option byte is `0x01`** (ChunkStream only), not `0x1D`.
   `VmessStream` implements baseline framing. Announcing ChunkMasking /
   GlobalPadding / AuthenticatedLength makes the server mask chunk lengths with
   SHAKE128 and the stream desynchronizes immediately.

4. **The address-type codes differ per protocol.** VLESS and VMess use
   `01`=IPv4, `02`=domain, `03`=IPv6. Trojan and SOCKS5 use `01`=IPv4,
   `03`=domain, `04`=IPv6. Field order differs too: VLESS and VMess write the
   **port before the address**, Trojan writes it after.

5. **UUIDs must use `Guid.TryWriteBytes(..., bigEndian: true)`.**
   `Guid.ToByteArray()` emits the first three fields little-endian on every
   platform, which is the wrong order for these wire formats. This is the
   classic trap; `UuidCodec` exists to make it impossible to hit.

6. **A clean VMess EOF is only an authenticated empty chunk** (`00 10` followed
   by the tag). A truncated stream or a bad tag is a hard error and must never
   be reported as EOF — otherwise a truncation attack looks like a normal close.

7. **SIMD is already done where it can be.** AES-GCM, ChaCha20-Poly1305 and
   SHA-256 in the BCL are hardware-accelerated. The SSE4.2 `crc32` instruction
   computes CRC-32C (Castagnoli); VMess needs CRC-32/IEEE, a different
   polynomial, which that instruction cannot produce. FNV-1a is inherently
   sequential. This was measured — do not spend time on it again.

8. **`vmess://` links generally cannot be `System.Uri` values.** The base64 JSON
   payload exceeds `Uri`'s host-length limit and contains `=` padding. Use
   `ProxyClientFactory.Create(string)`, `VmessClient.FromShareLink(string)` or
   `VmessShareLink.Parse(string)` — all of which operate on the raw string.

9. **Non-UUID user ids are real and must be derived, not rejected.** Xray's
   `common/uuid.ParseString` maps any id of length 1..30 to
   `UUIDv5(nil-namespace, utf8(id))` — i.e. `SHA1(16 zero bytes || id)[0..16]`
   with the version nibble set to 5 and the RFC 4122 variant bits set. Length 0
   or 31 is an error; 32..36 is parsed as canonical hex. `UuidCodec` mirrors
   this exactly. About 0.3% of real-world VLESS links depend on it.

10. **VMess `type` is header obfuscation, and only means anything for `net=tcp`.**
    For `ws`/`httpupgrade`/`grpc` every real client ignores it, so rejecting a
    junk `type` on those transports rejects otherwise-valid links.

11. **`vmess://` has two grammars in the wild**: base64-JSON (v2rayN), optionally
    with a `#remark` fragment appended *after* the base64; and the standard URI
    form `vmess://uuid@host:port?encryption=..&type=..&security=..#remark`.
    `VmessShareLink` handles both. Roughly 55% of real links use one of the two
    shapes that pure base64-JSON parsing would reject.

12. **HTML-escaped links silently downgrade REALITY to plaintext.** Some producers
    publish links with `&amp;` as the parameter separator. Splitting on `&` then
    yields keys named `amp;security`, `amp;flow`, `amp;pbk`. Discarding them as
    "unknown keys" leaves `security` at its default `None` and `flow` empty, so a
    REALITY node passes `EnsureSupported()` and the client connects **in the
    clear, sending the UUID unencrypted**. `ShareLinkQuery.StripHtmlAmpPrefix`
    strips the prefix in all three query scanners. Stripping is unconditionally
    safe: a literal `&` inside a value must be `%26`, so a bare `&` is always a
    separator. 68 vless and 10 trojan corpus links arrive this way, 51 REALITY.

    Note how this was found: **not** by the parse-rate number, which cannot see it
    — those links always "parsed successfully", just wrongly. It took connecting to
    live nodes. A percentage is not a proof; treat a metric that cannot fail as a
    metric that is not measuring.

13. **`httpupgrade` must not send `Sec-WebSocket-Key`.** Both `ws` and `httpupgrade`
    advertise `Upgrade: websocket` — that camouflage is the whole point of
    `httpupgrade` — but sing-box routes any request carrying `Sec-WebSocket-Key` to
    its WebSocket handler, which an httpupgrade inbound does not have, and answers
    **404**. Xray accepts either form. Sending the key on both looked like free
    camouflage and broke sing-box outright; only running both servers caught it.
    Measured directly: the key alone triggers the 404, while `Sec-WebSocket-Version`
    on its own still upgrades.

14. **The WebSocket framing is the BCL's, on purpose.** `WebSocketStream` wraps
    `WebSocket.CreateFromStream` rather than framing by hand. Masking, fragment
    reassembly and interleaved control frames are a large surface of subtle,
    security-relevant bugs, and that implementation is hardened and allocation-tuned.
    Two things the adapter must keep doing: a zero-length binary frame is **not** EOF
    (returning its `0` would silently truncate the tunnel — a `Read` must keep going
    until real bytes or a close frame arrive), and message boundaries are deliberately
    not preserved, because a proxy tunnel is a byte stream.

15. **`vmess://` `security=` means two different things in the wild.** The URI
    grammar defines it as the transport security (JSON `tls`), but 611 corpus links —
    27% of every vmess link — put the *body cipher* there (JSON `scy`). The value sets
    are disjoint apart from `none`, so the reading is recovered from the value, not
    guessed: `auto`/`aes-128-gcm`/`chacha20-poly1305` are a body cipher,
    `tls`/`reality`/`none` are transport security. `none` keeps its documented meaning
    — both readings agree there is no TLS, so nothing is downgraded. This is safe in a
    way the VLESS case was not: VMessAEAD seals the request header under a key derived
    from the id, so a wrong guess costs a failed handshake, never a cleartext id.

## Development Rules

- Keep hot protocol paths allocation-conscious: prefer `Span<T>`,
  `Memory<T>`, `ArrayPool<byte>`, `stackalloc`, and `ValueTask`.
- Return rented buffers in `finally`, and clear them when they held credentials.
- Use `BinaryPrimitives` for network byte order.
- Avoid LINQ in protocol hot paths.
- Keep protocol helpers `internal` unless a public API is intentionally needed.
- Public API additions must have XML documentation.
- Add new proxy types through `ProxyType`, client implementation, factory
  registration, protocol helper, error codes, and tests.
- Preserve multi-target compatibility for `net8.0`, `net9.0`, and `net10.0`.
- **Never silently downgrade.** An unrecognized `security=`, a non-zero
  `alterId`, or a transport we cannot speak must fail with a message naming what
  was found and what is accepted. Defaulting an unknown TLS mode to plaintext
  would send the user's UUID in the clear; that bug was caught in review once
  already.

## Testing

Run the test project directly:

```bash
dotnet test QuickProxyNet.Tests/QuickProxyNet.Tests.csproj
```

The crypto is pinned by byte-exact vectors produced by an independent
implementation: `VmessCryptoTest`, `VmessRequestTest`, `VmessBodyTest`,
`Sha224Test`. A failure there means the code is wrong, not the test. Never relax
those vectors.

Integration tests live in `QuickProxyNet.Tests/Integration/`:

- `DockerProtocolTests` runs real Xray and sing-box servers from
  `tests/docker/docker-compose.yml`. Enable with `QPN_DOCKER_TESTS=1`.
- `ConnectTest` uses external proxies via `HTTP_PROXY_URI` / `SOCKS5_PROXY_URI`.

Both gate on environment variables through the attributes in
`QuickProxyNet.Tests/SkipGates.cs` (`[EnvFact]`, `[AnyEnvFact]`, `[DockerFact]`,
`[DockerTheory]`), so an unconfigured test reports as **skipped**, never as
passed. Do not replace that with an early `return` — it turns "did not run" into
"green", which is how a test suite starts lying about what it proves.

**There is no runtime `Assert.Skip` on xunit 2.9.3.** This was checked, not
assumed. `Assert.Skip` / `Assert.SkipWhen` / `Assert.SkipUnless` are not in the
shipped xunit.assert 2.9.3 assembly at all — they sit behind the `XUNIT_SKIP`
compilation define that only xunit.v3 sets. `Xunit.Sdk.SkipException.ForSkip` *is*
public there, so `throw SkipException.ForSkip(...)` compiles — but the
`$XunitDynamicSkip$` token it encodes appears in **no** v2 assembly (verified
against xunit.core 2.9.3, xunit.execution.dotnet 2.9.3 and
xunit.runner.visualstudio 3.0.0), so v2 reports the throw as a plain **failure**
with the raw token in the message. Discovery-time `FactAttribute.Skip` is the
mechanism that actually works, and environment variables do not change mid-run,
so evaluating the gate in the attribute constructor is exact.

If a docker run is interrupted, clean up with:

```bash
docker compose -p quickproxynet-test -f tests/docker/docker-compose.yml down -v
```

## Diagnostics

`tools/CorpusCheck` runs the share-link parsers over ~17k real-world links
(PypsCFG `merged_all.txt`) and groups failures by reason:

```bash
dotnet run --project tools/CorpusCheck                 # parse the corpus
dotnet run --project tools/CorpusCheck -- --live 30    # connect to sampled live nodes
```

Rules: the corpus is downloaded to a temp directory and **never committed** — it
contains real IPs, UUIDs and passwords belonging to other people. Every example
in the report is redacted to a shape. Test fixtures stay synthetic. `--live` is
manual-only and must never run in CI.

## Build

NUKE build scripts are available from the repository root:

```bash
./build.cmd <target>   # Windows
./build.sh <target>    # Linux/macOS
```

Useful targets include restore, compile, tests, pack, and push. Versioning is
derived from git tags through MinVer.

## Working Process That Actually Worked

- Do protocol work in **sequential** sub-agents. Parallel agents share the test
  project and break each other's build.
- Verify every agent's claims yourself: `dotnet build -c Release` (0 warnings on
  all three TFMs) and `dotnet test`. Do not trust a report.
- Ground truth for crypto is an **independent implementation** (a throwaway
  Python one worked well) that first reproduces the already-committed vectors,
  and only then is used to generate new ones.
- Follow implementation with an adversarial review round.

That process is what caught the silent plaintext downgrade on an unknown
`security=`, the VMess response-header deadlock, the bracketed-IPv6 host bug,
and credential buffers that were returned to the pool unzeroed.

## VPN-Style Protocol Research

Notes for VLESS, VMess and Trojan live in `docs/` alongside the implementation.
`docs/quic-protocols-analysis.md` covers Hysteria2 and TUIC: those are **not
implemented**, and that document explains the architectural problem (one QUIC
connection multiplexes many streams, which does not fit "one `ConnectAsync`, one
socket") that has to be solved before they can be.

## What Is Worth Implementing Next

Measured with `tools/CorpusCheck` over 21 403 real links (2026-08-14), counting what
can actually **connect**, not what parses. See `docs/implementation-plan.md` §7 for
the full table.

| Blocker | Links | % of corpus |
| --- | ---: | ---: |
| REALITY (needs uTLS — `SslStream` cannot do it) | 10 653 | 49.8% |
| gRPC | 991 | 4.6% |
| xhttp (Xray-only) | 789 | 3.7% |
| Hysteria2 / TUIC (QUIC) | 472 | 2.2% |

The point of that table: **QUIC is the worst remaining investment**, not the next
phase. It is the heaviest architectural work in the roadmap — it breaks the "one
`ConnectAsync`, one socket" model — and buys 2.2%. The old roadmap listed it as
phase 4 purely because it was next in the document, which is not a reason. REALITY
is half the corpus and is gated on a uTLS ClientHello, so it is a separate project
rather than a feature.
