# Docker integration servers

Real Xray-core and sing-box servers for `QuickProxyNet.Tests/Integration/DockerProtocolTests.cs`.

Byte-exact vectors prove our crypto matches an independent implementation. They cannot prove a
server *accepts* the handshake — framing, field order, the VMess option byte, the address-type
codes, the non-UUID id derivation and the Shadowsocks lazy salt read all have to be right
simultaneously for that. This stack is the only thing in the repo that proves it.

Two implementations are here on purpose: they disagree about what they tolerate, so one alone
would silently bless a bug the other rejects.

## Running

The tests bring the stack up and tear it down themselves. Enable them with:

```bash
QPN_DOCKER_TESTS=1 dotnet test QuickProxyNet.Tests/QuickProxyNet.Tests.csproj
```

Without `QPN_DOCKER_TESTS=1` every case reports as **skipped** — never as passed.

Manually, always with the fixed project name:

```bash
docker compose -p quickproxynet-test -f tests/docker/docker-compose.yml up -d --wait
docker compose -p quickproxynet-test -f tests/docker/docker-compose.yml down -v
```

If a run is interrupted, the `down -v` above is the cleanup. After a completed run `docker ps`
must be empty.

The stack is a **machine-global singleton** — one fixed project name, one fixed set of host
ports — so only one test process can own it at a time. Since the test project multi-targets,
`dotnet test` runs the TFMs concurrently, and `DockerComposeFixture` serializes them on a lock
file (`%TEMP%/quickproxynet-docker-compose.lock`): each run brings the stack up, uses it and
tears it down before the next starts. If a process is killed hard and a later run reports the
lock as held for over ten minutes, delete that file.

## Images

All three are expected to be present locally; nothing here builds an image.

| Image | Role |
| --- | --- |
| `ghcr.io/xtls/xray-core:latest` | Xray inbounds (verified against 26.3.27; `freedom.finalRules: allow` is required from 26.x, which otherwise blackholes the private `echo` target) |
| `ghcr.io/sagernet/sing-box:latest` | sing-box inbounds (verified against 1.13.14) |
| `alpine:3.20` | HTTP echo target |

## Host port map

Container ports are `10001..10010` for the first batch and `10011..10014` for Shadowsocks; the
host ports differ per server so both can run at once. The Shadowsocks ports break the
`+24800`/`+24810` pattern on purpose — past `10010` it cannot hold for both servers — and take a
fresh decade each: xray `2482x`, sing-box `2483x`.

| Host port | Server | Inbound | Credential |
| --- | --- | --- | --- |
| 24801 | xray | vless, `security=none` | `11111111-1111-4111-8111-111111111111` |
| 24802 | xray | vless, `security=tls` | `22222222-2222-4222-8222-222222222222` |
| 24803 | xray | trojan (always TLS) | `qpn-test-trojan-password` |
| 24804 | xray | vmess, driven with `aes-128-gcm` | `33333333-3333-4333-8333-333333333333` |
| 24805 | xray | vmess, driven with `chacha20-poly1305` | `44444444-4444-4444-8444-444444444444` |
| 24806 | xray | vless, `security=none`, **non-UUID id** | `not-a-uuid` |
| 24807 | xray | vless over `ws`, path `/qpn-ws` | `55555555-5555-4555-8555-555555555555` |
| 24808 | xray | vmess over `ws`, path `/qpn-vmess-ws` | `66666666-6666-4666-8666-666666666666` |
| 24809 | xray | trojan over `ws` + TLS, path `/qpn-trojan-ws` | `qpn-test-trojan-password` |
| 24810 | xray | vless over `httpupgrade`, path `/qpn-hu` | `77777777-7777-4777-8777-777777777777` |
| 24811 | sing-box | vless, `security=none` | `11111111-1111-4111-8111-111111111111` |
| 24812 | sing-box | vless, `security=tls` | `22222222-2222-4222-8222-222222222222` |
| 24813 | sing-box | trojan (always TLS) | `qpn-test-trojan-password` |
| 24814 | sing-box | vmess, driven with `aes-128-gcm` | `33333333-3333-4333-8333-333333333333` |
| 24815 | sing-box | vmess, driven with `chacha20-poly1305` | `44444444-4444-4444-8444-444444444444` |
| 24817 | sing-box | vless over `ws`, path `/qpn-ws` | `55555555-5555-4555-8555-555555555555` |
| 24818 | sing-box | vmess over `ws`, path `/qpn-vmess-ws` | `66666666-6666-4666-8666-666666666666` |
| 24819 | sing-box | trojan over `ws` + TLS, path `/qpn-trojan-ws` | `qpn-test-trojan-password` |
| 24820 | sing-box | vless over `httpupgrade`, path `/qpn-hu` | `77777777-7777-4777-8777-777777777777` |
| 24821 | xray | shadowsocks `aes-256-gcm` | `qpn-test-ss-password` |
| 24822 | xray | shadowsocks `chacha20-ietf-poly1305` | `qpn-test-ss-password` |
| 24823 | xray | shadowsocks `aes-128-gcm` | `qpn-test-ss-password` |
| 24831 | sing-box | shadowsocks `aes-256-gcm` | `qpn-test-ss-password` |
| 24832 | sing-box | shadowsocks `chacha20-ietf-poly1305` | `qpn-test-ss-password` |
| 24833 | sing-box | shadowsocks `aes-128-gcm` | `qpn-test-ss-password` |
| 24834 | sing-box | shadowsocks `aes-192-gcm` — **sing-box only** | `qpn-test-ss-password` |

Every credential above is synthetic test data committed on purpose — repdigit UUIDs and literal
passwords. None of it is, or ever was, a real credential. The C# side mirrors this table in
`QuickProxyNet.Tests/Integration/DockerEndpoints.cs`; keep the two in sync.

### The two VMess ports

VMess picks its body cipher **client-side**: the cipher is the security nibble of the request
header, and neither Xray nor sing-box lets a `vmess` inbound restrict it. So ports 24804/24814 and
24805/24815 are server-side identical; what differs is the `VmessSecurityKind` the test drives
them with. They are kept separate so a failure names the cipher directly.

### The non-UUID port

Port 24806 is configured with the literal id `not-a-uuid`. Xray's `common/uuid.ParseString` maps
any id of length 1..30 to `UUIDv5(nil-namespace, utf8(id))`, and `UuidCodec` mirrors that. The
VLESS id is compared byte for byte on the server, so `Vless_NonUuidId_DerivesSameIdAsXray`
round-tripping means our derivation matches Xray's exactly — a unit vector could only ever pin
that against ourselves. sing-box has no equivalent, so this inbound is Xray-only.

### The Shadowsocks ports

Unlike VMess, a Shadowsocks inbound is bound to one cipher, so each cipher needs its own port.
`aes-192-gcm` is not in the SIP004 table: sing-box and shadowsocks-libev speak it, Xray's
`cipherFromString` has no case for it, so port 24834 has no Xray twin and
`Shadowsocks_Aes192Gcm_RoundTrip_SingBoxOnly` is a single-server test by necessity. Its 24-byte
salt is also the one size no permissive implementation could have vectored for us.

Xray prints a deprecation warning for the `shadowsocks` inbound at startup. It is harmless and
not a failure.

A Shadowsocks server sends its salt only after the target has replied, and sends **nothing** to a
client whose first chunk it cannot open — Xray additionally drains a pseudo-random number of bytes
before closing (`NewBehaviorSeedLimitedDrainer(seed, 16+38, 3266, 64)` in
`proxy/shadowsocks/protocol.go`: under 3400 bytes in total, 54 + 3266 + 64 at the very most).
`Shadowsocks_WrongPassword_ConnectSucceeds_ReadFails` writes an HTTP request plus 4096 filler
bytes so the drainer always runs out, and then expects the failure on the first read as a closed
connection (a FIN, or a RST because the surplus was left unread) — never a timeout, never at
connect time. A client whose first read simply hangs fails this test.

## The echo target

`alpine:3.20` running `nc -lk -p 8080 -e /bin/sh /echo/serve.sh`. Alpine's busybox has no `httpd`
applet (it lives in `busybox-extras`), but `nc -lk … -e PROG` is a persistent accept loop that
execs `PROG` per connection — a real server, with no gap between connections and no extra image
pull. `serve.sh` drains the request and answers:

```
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 11
Connection: close

QPN-ECHO-OK
```

It is reachable only from inside the compose network, as `echo:8080`. Tests target it by that DNS
name, which also exercises each protocol's **domain** address type rather than the IPv4 one.

`serve.sh` reads the request before replying: replying first lets `nc` close the socket while the
client is still sending, which surfaces on Windows as an RST that discards the queued response.

## TLS certificate

`certs/server.crt` + `certs/server.key` are a self-signed keypair used by the `vless security=tls`
and `trojan` inbounds. **Committing them is correct and intended** — they are our test data, not a
third-party secret, and the private key protects nothing.

Regenerate with:

```bash
cd tests/docker/certs
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 36500 \
  -keyout server.key -out server.crt \
  -subj "/CN=QuickProxyNet Test" \
  -addext "subjectAltName=DNS:localhost,DNS:xray,DNS:singbox,DNS:qpn.test,IP:127.0.0.1"
```

Tests connect to `127.0.0.1` with SNI `qpn.test` and accept the certificate through
`ServerCertificateValidationCallback`, which checks the subject CN is `QuickProxyNet Test`.
That is deliberately *not* accept-anything: the TLS cases are supposed to prove a real TLS
session with our server took place. `AllowInsecure` is left `false` for the same reason.

## Line endings

`.gitattributes` pins `tests/docker/**` to `eol=lf`. A CRLF checkout breaks `serve.sh` inside the
container.
