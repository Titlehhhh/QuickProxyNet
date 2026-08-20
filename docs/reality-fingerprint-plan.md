# Making the managed REALITY ClientHello look like Chrome

`QuickProxyNet.Reality/Managed/TlsClientHello.cs` currently emits a valid TLS 1.3 hello that a
real REALITY server accepts. It is not a browser fingerprint, and until it is, the managed client
is a protocol implementation rather than a censorship-resistance tool — a hello that merely
*works* puts its user in a smaller and stranger bucket than one that fails.

This is what closing that gap requires. Everything below was read out of the reference sources
rather than inferred; where a claim could not be verified it says so.

## The target is uTLS, not Chrome

Xray maps `fp=chrome` to `utls.HelloChrome_Auto` (`Xray-core/transport/internet/tls/tls.go`),
and uTLS defines `HelloChrome_Auto = HelloChrome_133` (`u_common.go`). So the population a
REALITY user blends into is *uTLS's model of Chrome*, not a live browser. Reproduce uTLS; when
Chrome drifts, follow uTLS rather than getting ahead of it.

## What Chrome 133 sends

**Header.** `legacy_version 0x0303`, 32-byte random, **32-byte** `legacy_session_id` — which is
exactly what REALITY needs, so the sealed blob and the fingerprint do not conflict — and
`legacy_compression_methods = 01 00`.

**Cipher suites,** 16 entries, order fixed and never permuted:

```
GREASE, 1301, 1302, 1303, c02b, c02f, c02c, c030,
cca9,   cca8, c013, c014, 009c, 009d, 002f, 0035
```

The TLS 1.2 suites are not optional set dressing: a three-suite list is a tell on its own.

**Extensions,** 18 slots (16 real plus two GREASE), canonical order before permutation:

| # | id | extension | body |
| --- | --- | --- | --- |
| 1 | GREASE₁ | filler | empty — always first |
| 2 | `0000` | server_name | `00 <listlen> 00 <namelen> <name>` |
| 3 | `0017` | extended_master_secret | empty |
| 4 | `ff01` | renegotiation_info | `00` |
| 5 | `000a` | supported_groups | `GREASE, 11ec, 001d, 0017, 0018` |
| 6 | `000b` | ec_point_formats | `01 00` |
| 7 | `0023` | session_ticket | empty |
| 8 | `0010` | ALPN | `02 "h2" 08 "http/1.1"` |
| 9 | `0005` | status_request | `01 0000 0000` |
| 10 | `000d` | signature_algorithms | `0403,0804,0401,0503,0805,0501,0806,0601` |
| 11 | `0012` | signed_certificate_timestamp | empty |
| 12 | `0033` | key_share | see below |
| 13 | `002d` | psk_key_exchange_modes | `01 01` |
| 14 | `002b` | supported_versions | `GREASE, 0304, 0303` |
| 15 | `001b` | compress_certificate | `02 0002` (brotli) |
| 16 | `44cd` | application_settings | `0003 02 "h2"` — note 133 uses `44cd`, ≤131 used `4469` |
| 17 | `fe0d` | encrypted_client_hello | GREASE ECH, below |
| 18 | GREASE₂ | filler | `00` — always last |

**No padding extension.** BoringSSL dropped the pad-to-512 rule, and a hello carrying an ML-KEM
key share is ~1.7 KB anyway — far outside the window that rule ever applied to.

**`signature_algorithms` contains no ed25519.** Verified here by experiment, not just by reading:
removing `0x0807` leaves the real-server handshake and tunnel tests green. An earlier comment in
this repo claimed it was required because a REALITY server answers with an Ed25519 certificate —
it is not, because the server generates that certificate only after authenticating the client and
never consults the extension. The list above is already what the code sends.

## GREASE

Values are `0x0a0a, 0x1a1a, … 0xfafa` — one byte of randomness per slot, `(b & 0xf0) | 0x0a`
doubled into both bytes. Six independent draws per connection, with two rules that matter:

- The two extension-slot values **must differ**; BoringSSL fixes a collision with `^= 0x1010`.
- The group value in `supported_groups[0]` and the one in `key_share[0]` are **the same draw**.
  Drawing them independently is directly detectable.

`key_share`'s GREASE entry is `<grease_group> 0001 00`.

## GREASE ECH (`fe0d`)

Pure randomness, no crypto dependency, and about 250 of the missing bytes:

```
1B   0x00                       outer ClientHello
2B   kdf_id  = 0x0001           HKDF-SHA256
2B   aead_id = 0x0001           AES-128-GCM (uTLS always; Chrome picks 0x0003 without AES-NI)
1B   config_id                  random
2B   0x0020
32B  enc                        public half of a fresh, discarded X25519 keypair
2B   payload length
NB   payload                    random; length is exactly one of 144, 176, 208, 240
```

REALITY servers have no ECH keys configured, so the extension is ignored — verified in
`handshake_server_tls13.go`, where `retry_configs` are only built when ECH keys exist.

## Extension permutation, and why JA3 is the wrong metric

BoringSSL builds a Fisher–Yates permutation of every extension index once per handshake. GREASE₁
is emitted before the loop and GREASE₂ after it, so those two stay pinned; **everything else
moves, including `server_name`, `key_share` and `supported_versions`**. There is no "SNI first"
convention any more.

So JA3 — which hashes the extension list in order — changes almost every connection and is
useless as an acceptance criterion. JA4 strips GREASE and sorts the cipher and extension lists
before hashing; signature algorithms are appended **unsorted**, and `0000`/`0010` are removed from
the sorted list because they are already encoded elsewhere in the fingerprint. JA4 is the metric
to test against.

## X25519MLKEM768 — the hard part

Group `0x11EC`. The client's key share is **1216 bytes, ML-KEM first**:

```
1184B  ML-KEM-768 encapsulation key
  32B  X25519 public key
```

The server replies with 1120 bytes (`ML-KEM ciphertext 1088 || X25519 public 32`), and the shared
secret fed to the key schedule is **64 bytes, ML-KEM part first**:
`MLKEM768.Decap(ct) || X25519(sk, pk)`.

It cannot be faked. REALITY's server sorts post-quantum groups first among those the client
advertises, so offering `0x11ec` guarantees it is selected and a real decapsulation is required.

**Availability is the problem.** `System.Security.Cryptography.MLKem` arrives in .NET 10 but is
OS-gated — it needs Windows 11 with the PQC CNG updates or OpenSSL 3.5+, and throws
`PlatformNotSupportedException` otherwise. A client that produces a Chrome fingerprint on a
patched Windows 11 and a different one on Debian 12 is **worse** than one that is consistently
wrong, because the fingerprint then leaks the host OS. The same gating applies to `Shake128`/
`Shake256`, which ML-KEM needs.

That argues for one managed ML-KEM-768 used on every target framework, validated against the NIST
ACVP vectors — in character for a repo that already hand-rolls X25519 and the TLS 1.3 key
schedule. `MLKem` may be used where supported only after asserting byte-identical output against
the managed path for the same seed.

**Until ML-KEM exists, omit `0x11ec` from both `supported_groups` and `key_share`.** JA4 is
unchanged by that (it hashes extension ids, not group lists), and the hello simply drops to
~500 bytes — which is itself a tell, since no current Chrome sends a hello that small, so it must
be documented as degraded. The tempting alternative — offering the hybrid key share while leaving
the group out of `supported_groups` to force a fallback — violates RFC 8446 §4.2.8 and is a
one-line check for any DPI box. It is worse, not better.

## What this means for REALITY's sealing

REALITY's server looks for a standalone X25519 share **first**, and only falls back to the X25519
tail of a hybrid entry when there is none (`XTLS/REALITY/tls.go`). Chrome sends both. So:

- `RealityAuth.DeriveAuthKey` keeps using the private key of the standalone `001d` share. No
  change needed there.
- The two X25519 keypairs must be **independent**. Chrome's are, and reusing one would be a
  trivial byte-equality check for an observer.
- The TLS handshake itself then runs on X25519MLKEM768 while `authKey` comes from the other
  keypair. Keeping those two separate is the obvious place to introduce a bug.
- `SessionIdOffset = 39` and the AAD remain correct — the header layout does not change.

Two client-side changes come with the hybrid group: `ParseServerHello` currently accepts only
`0x001D` with a 32-byte share and must also accept `0x11EC` with 1120; and the
HelloRetryRequest error text stops being accurate once three groups are offered.

## Order of work

Build the instrument first. Without a JA4 implementation, "does our hello match" is an opinion.

1. **`Ja4.Compute` as a test helper**, emitting `JA4_r` as well — the raw string is what names the
   list that diverged when a test fails.
2. **A reference corpus.** The strongest oracle is uTLS itself: ~20 lines of Go calling
   `utls.UClient(..., HelloChrome_133)` and dumping `HandshakeState.Hello.Raw`, a few hundred
   times, checked in as hex so CI needs no Go toolchain. A live Chrome capture on a loopback
   listener is the second oracle, and tells you whether Chrome has drifted past 133.
3. **Restructure the builder** around a GREASE seed and an ordered list of extension writers, then
   permute indices `1 .. n-2`.
4. **The cheap extensions** — rows 2–11 and 13–16, exact bodies. Key share still bare X25519.
5. **GREASE ECH.** ~30 lines, no crypto dependency.
6. **Permutation.** After this the JA4 is already correct; only the wire length and the group list
   are still wrong.
7. **ML-KEM-768.** Keygen and decapsulation, ACVP vectors, then the hybrid key share, the 64-byte
   secret, and the `ParseServerHello` change.

Steps 3–6 are roughly 400 lines and need no new dependency.

## The honest acceptance criterion

> The hello is *structurally indistinguishable* from uTLS `HelloChrome_133`: identical JA4 and
> JA4_r, identical extension set and cipher list, byte-identical extension bodies outside an
> enumerated set of per-connection random fields, and a matching length distribution.

Three things it does not claim, and which belong in the type's documentation:

- **Not byte-identical.** Chrome randomises its hello by design; byte-identity is not meaningful.
- **Not "matches Chrome today".** It matches uTLS's model of Chrome 133, which is the right target
  precisely because that is what the rest of the ecosystem sends.
- **Not indistinguishable end-to-end.** The hello is one layer. What follows is VLESS, not a
  browser: no Chrome-shaped HTTP/2 SETTINGS, no browser request timing, and an ALPN of `h2`
  describing nothing the tunnel actually does. Fixing the hello removes the cheapest
  discriminator. It does not make the flow look like a browser.

## Sources

- uTLS `u_parrots.go`, `u_common.go`, `u_tls_extensions.go`, `u_ech.go`, `common.go`
- BoringSSL `ssl/extensions.cc`, `ssl/handshake.cc`, `ssl/ssl_key_share.cc`,
  `ssl/encrypted_client_hello.cc`
- XTLS/REALITY `tls.go`, `handshake_server_tls13.go`
- Xray-core `transport/internet/tls/tls.go` (the `fp` name table)
- FoxIO JA4 specification, `technical_details/JA4.md`
- RFC 8701 (GREASE), RFC 8446 §4.2.8, draft-kwiatkowski-tls-ecdhe-mlkem-02 §3.1.2–3.1.3
