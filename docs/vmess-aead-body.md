# VMessAEAD (alterId=0) — Body Framing & Server Response — Byte-Exact Spec

Scope: the **encrypted body stream** and the **AEAD server response header** for a
VMessAEAD client, `alterId = 0`, body security `aes-128-gcm` or
`chacha20-poly1305`. This document does **not** cover the request header AEAD
envelope (auth-id / `VMess Header AEAD *` KDF) — only what happens *after* the
request header has been sent: how request body chunks are sealed, how the server
response header is opened, and how response body chunks are opened.

All multi-byte integers are **big-endian** unless stated otherwise. All AEAD tags
are **16 bytes**. All values in tables are **synthetic** illustrations.

**Baseline profile** used throughout = request option `S` (`RequestOptionChunkStream`)
set, and options `M` (`RequestOptionChunkMasking`), `P` (`RequestOptionGlobalPadding`),
and `A` (`RequestOptionAuthenticatedLength`) **cleared**. This is the simplest
interoperable VMessAEAD body. The masking (SHAKE128) and padding paths are
described but marked out-of-scope-for-baseline.

Sources verified against `v2fly/v2ray-core` @ `master` (cross-checked vs
`XTLS/Xray-core` @ `main`):
- `proxy/vmess/encoding/client.go` — `NewClientSession`, `EncodeRequestBody`,
  `DecodeResponseHeader`, `DecodeResponseBody`, `GenerateChunkNonce`.
- `proxy/vmess/encoding/auth.go` — `GenerateChacha20Poly1305Key`, `ShakeSizeParser`.
- `common/crypto/auth.go` — `AuthenticationReader` / `AuthenticationWriter`.
- `common/crypto/chunk.go` — `PlainChunkSizeParser`, `AEADChunkSizeParser`.
- `proxy/vmess/aead/kdf.go` + `consts.go` — `KDF`, `KDF16`, label constants.
- `common/buf/buffer.go` — buffer `Size` constant.

---

## 1. Body encryption keys, IVs, and per-chunk nonce

### 1.1 Session key material

`NewClientSession` draws 33 random bytes and splits them (verbatim logic):

| Field | Source | Size |
| --- | --- | ---: |
| `requestBodyKey` | `randomBytes[0:16]` | 16 |
| `requestBodyIV`  | `randomBytes[16:32]` | 16 |
| `responseHeader` (a.k.a. `respV`) | `randomBytes[32]` | 1 |

For AEAD (`alterId = 0`, `isAEAD == true`):

```
responseBodyKey = SHA256(requestBodyKey)[0:16]      // 16 bytes
responseBodyIV  = SHA256(requestBodyIV) [0:16]      // 16 bytes
```

(The non-AEAD/legacy path uses `MD5` instead; not used here.)

### 1.2 aes-128-gcm

- AEAD key = `requestBodyKey` (16 bytes) directly. `cipher.NewGCM(aes.NewCipher(requestBodyKey))`.
- `NonceSize()` = 12, tag = 16.

### 1.3 chacha20-poly1305 — the MD5 key expansion

The 16-byte `requestBodyKey` is expanded to a 32-byte ChaCha20 key by
`GenerateChacha20Poly1305Key` (verbatim behavior confirmed):

```
key = new byte[32]
key[0:16]  = MD5(requestBodyKey)      // MD5 of the 16-byte body key
key[16:32] = MD5(key[0:16])           // MD5 of the first half
return key
```

- `chacha20poly1305.New(key)`; `NonceSize()` = 12, tag = 16.

### 1.4 Per-chunk nonce — `GenerateChunkNonce` (VERIFIED VERBATIM)

```go
func GenerateChunkNonce(nonce []byte, size uint32) crypto.BytesGenerator {
	c := append([]byte(nil), nonce...)   // copy of the 16-byte body IV
	count := uint16(0)
	return func() []byte {
		binary.BigEndian.PutUint16(c, count) // overwrite c[0..2) with the counter
		count++
		return c[:size]                      // size == AEAD NonceSize() == 12
	}
}
```

Therefore, for **every chunk** the 12-byte AEAD nonce is:

```
nonce[0:2]  = uint16 BE chunk counter (0,1,2,...)
nonce[2:12] = requestBodyIV[2:12]     // 10 bytes of the body IV, unchanged
```

Byte layout (12 bytes total):

| Offset | Bytes | Content |
| ---: | ---: | --- |
| 0 | 2 | `count` (uint16, big-endian) |
| 2 | 10 | `requestBodyIV[2..12]` (constant for the whole stream) |

- Counter **starts at 0** and increments by 1 after each `Seal`/`Open`.
- The counter is a **`uint16`**: it wraps `0xFFFF -> 0x0000` (Go `uint16` overflow;
  `PutUint16` rewrites only bytes `[0..2)`, leaving `[2..12)` intact). No nonce
  bytes beyond the first two ever change.
- The **request body** stream uses `GenerateChunkNonce(requestBodyIV, 12)`; the
  **response body** stream uses `GenerateChunkNonce(responseBodyIV, 12)`. Each
  direction has its own independent counter starting at 0.

> Note: the same `count`/`iv[2:]` nonce scheme is used for both AES-GCM and
> ChaCha20-Poly1305; only the key/cipher differs.

---

## 2. Chunk framing (`AuthenticationReader` / `AuthenticationWriter`, option `S`)

### 2.1 On-the-wire chunk

Each chunk (baseline, `PlainChunkSizeParser`, no padding):

```
+----------------+-------------------------------+
| length (2, BE) | AEAD sealed payload (N+16)    |
+----------------+-------------------------------+
```

- `length` is a **plain unmasked uint16, big-endian** (`PlainChunkSizeParser`,
  `SizeBytes() == 2`).
- `length` = size of the **sealed** payload that follows = `plaintextLen + 16`
  (plaintext length **plus the 16-byte AEAD tag**), NOT the plaintext length.

  Confirmed from `AuthenticationWriter.seal`:
  `encryptedSize = len(plaintext) + auth.Overhead()` (Overhead = 16), and the
  size field encoded is `uint16(encryptedSize + paddingSize)`. With baseline
  `paddingSize == 0`, wire `length == plaintextLen + 16`.

- The AEAD nonce for this chunk is the current `GenerateChunkNonce()` value
  (§1.4). AAD is **empty/none** (`AdditionalDataGenerator = GenerateEmptyBytes()`).

Worked example (aes-128-gcm, first data chunk, synthetic):

```
plaintext      = "hello" (5 bytes)
counter        = 0  -> nonce = 00 00 | requestBodyIV[2..12]
sealed         = AES-128-GCM.Seal(plaintext) = 5 + 16 = 21 bytes
length         = 21 = 0x0015
wire bytes     = 00 15  <21 bytes of ciphertext||tag>
```

### 2.2 Maximum chunk size

- The `length` field is `uint16`, so the **wire-format hard cap** on a sealed
  chunk is `65535` bytes → **max plaintext per chunk = 65535 − 16 = 65519**.
- v2ray-core / Xray-core do **not** emit chunks that large. The writer bounds each
  aggregated stream chunk by:
  `payloadSize = buf.Size − Overhead(16) − SizeBytes(2) − maxPadding`.
  - `v2ray-core`: `buf.Size = 2048` → max plaintext per emitted chunk ≈ **2030**.
  - `Xray-core`:   `buf.Size = 8192` → max plaintext per emitted chunk ≈ **8174**.
- **The commonly cited "2^14 = 16384" is NOT a v2ray/Xray constant** — see the
  uncertainty list. A correct reader must accept any sealed chunk up to the
  `uint16` cap (65535); do not hard-code 16384 as a receive limit.

### 2.3 EOF / termination

End-of-stream is an **empty final chunk**: a sealed payload of zero-length
plaintext (i.e. just the 16-byte tag), framed with the length field.

Reader EOF condition (verbatim logic from `AuthenticationReader`):

```go
if size + r.sizeOffset == uint16(r.auth.Overhead()) + padding {
    r.done = true
    return io.EOF
}
```

For baseline (`PlainChunkSizeParser` → `sizeOffset = 0`, `padding = 0`,
`Overhead = 16`): EOF is signaled when the decoded `length == 16`.

Exact bytes on the wire for the terminating chunk (aes-128-gcm or chacha20):

```
00 10  <16-byte AEAD tag of an empty plaintext, under the current chunk nonce>
```

i.e. `length = 0x0010 = 16`, followed by exactly 16 bytes (the tag). The reader
must still **verify** that tag with `Open` before treating the stream as cleanly
closed (the empty chunk is authenticated). The writer produces it by calling
`WriteMultiBuffer` with an empty buffer → `seal([]byte{})`.

### 2.4 Length masking (`ShakeSizeParser`) — out of scope for baseline

Active only when option `M` (`RequestOptionChunkMasking`) is set; then
`sizeParser = NewShakeSizeParser(bodyIV)` replaces `PlainChunkSizeParser`.
Verified behavior:

- Fields: `shake sha3.ShakeHash`, `buffer [2]byte`. `SizeBytes() == 2`.
- Seed: `sha3.NewShake128()`, then `shake.Write(bodyIV)` (request uses
  `requestBodyIV`, response uses `responseBodyIV`).
- `next()`: read 2 bytes from the SHAKE128 stream, interpret big-endian → `mask` (uint16).
- `Decode(b)`: `size = mask ^ binary.BigEndian.Uint16(b)`.
- `Encode(size, b)`: `binary.BigEndian.PutUint16(b, mask ^ size)`.

So with masking the 2-byte length is XOR-masked by a per-chunk SHAKE128 keystream
word (a fresh `mask` per chunk, in lock-step between the two peers). For the
baseline (`M` off) the length is a plain uint16 — **implement `PlainChunkSizeParser`
first; `ShakeSizeParser` is future work.** .NET has `System.Security.Cryptography.Shake128`
(§5) for when masking is added.

### 2.5 Global padding (`P`) — out of scope for baseline

Active only when option `P` (`RequestOptionGlobalPadding`) is set, and it requires
`M` (the size parser must implement `PaddingLengthGenerator`, which only
`ShakeSizeParser` does). Each chunk then carries `NextPaddingLen()` random padding
bytes appended **after** the sealed payload, where:

```
NextPaddingLen() = ShakeSizeParser.next() % 64     // 0..63 bytes, from the same SHAKE128 stream
```

and the wire `length` field counts `sealedSize + paddingLen`. Baseline: `P` off,
`paddingLen == 0` always. Confirmed.

---

## 3. Server response header (AEAD, alterId=0)

The response header is **always AES-128-GCM**, independent of the body cipher.

### 3.1 KDF (`proxy/vmess/aead/kdf.go`, VERIFIED VERBATIM)

```go
func KDF(key []byte, path ...string) []byte {
	hmacCreator := &hMacCreator{value: []byte("VMess AEAD KDF")}
	for _, v := range path {
		hmacCreator = &hMacCreator{value: []byte(v), parent: hmacCreator}
	}
	hmacf := hmacCreator.Create()
	hmacf.Write(key)
	return hmacf.Sum(nil)          // 32 bytes
}
func KDF16(key, path...) []byte { return KDF(key, path...)[:16] }

func (h *hMacCreator) Create() hash.Hash {
	if h.parent == nil { return hmac.New(sha256.New, h.value) }
	return hmac.New(h.parent.Create, h.value)   // nested HMAC: parent HMAC used as the "hash" ctor
}
```

This is a **recursive/nested HMAC-SHA256**. For a single-label path
`KDF(key, LABEL)` it evaluates to:

```
inner  = HMAC-SHA256 keyed by "VMess AEAD KDF"    (used as the block/hash function)
outer  = HMAC keyed by LABEL, whose underlying hash constructor is `inner`
result = outer.Update(key).Final()                (32 bytes)
```

A plain `HMACSHA256` call is **not** sufficient — a nested-HMAC wrapper is required
(see §5 note). `KDF16` truncates to `[0:16]`; IVs below truncate to `[0:12]`.

### 3.2 The four response-header KDF labels (VERIFIED VERBATIM strings)

| Purpose | Constant | Exact string | Derivation |
| --- | --- | --- | --- |
| Length key   | `KDFSaltConstAEADRespHeaderLenKey`     | `AEAD Resp Header Len Key` | `KDF16(responseBodyKey, "AEAD Resp Header Len Key")` (16B) |
| Length IV    | `KDFSaltConstAEADRespHeaderLenIV`      | `AEAD Resp Header Len IV`  | `KDF(responseBodyIV,  "AEAD Resp Header Len IV")[0:12]` (12B) |
| Payload key  | `KDFSaltConstAEADRespHeaderPayloadKey` | `AEAD Resp Header Key`     | `KDF16(responseBodyKey, "AEAD Resp Header Key")` (16B) |
| Payload IV   | `KDFSaltConstAEADRespHeaderPayloadIV`  | `AEAD Resp Header IV`      | `KDF(responseBodyIV,  "AEAD Resp Header IV")[0:12]` (12B) |

Note the length labels contain `Len` and the payload labels do **not** — copy
exactly, including single spaces. Keys derive from **`responseBodyKey`**, IVs from
**`responseBodyIV`** (§1.1).

### 3.3 Response header envelope on the wire

```
+------------------------------------------+------------------------------------------------+
| encrypted length: 2 + 16 tag  (18 bytes) | encrypted header: L + 16 tag  (L+16 bytes)     |
+------------------------------------------+------------------------------------------------+
```

Step 1 — read exactly **18 bytes**, decrypt to get `L`:

```
L_plain(2 bytes) = AES128GCM(key=lenKey, nonce=lenIV, aad=EMPTY).Open(cipher18)
L = uint16_BE(L_plain)          // length of the header plaintext, tag-excluded
```

Step 2 — read exactly **`L + 16` bytes**, decrypt to get the header plaintext:

```
headerPlain(L bytes) = AES128GCM(key=payloadKey, nonce=payloadIV, aad=EMPTY).Open(cipherL16)
```

- **AAD is empty/none** for both opens (`Open(nil, iv, data, nil)`). Confirmed.
- Each of the two AEAD operations uses its own fixed 12-byte nonce (from the KDF),
  used exactly once — there is no counter here.

### 3.4 Response header plaintext layout

The client reads the **first 4 bytes**, then optional command data:

| Offset | Size | Field | Meaning / check |
| ---: | ---: | --- | --- |
| 0 | 1 | `responseHeader` (respV) | **MUST equal** the `session.responseHeader` byte the client generated (§1.1). Mismatch → reject the connection. |
| 1 | 1 | `option` | response option bitmask (e.g. dynamic-port / reuse hints). |
| 2 | 1 | `command` | command id; `0` = no command. |
| 3 | 1 | `commandLength` | length `M` of command data (only meaningful if `command != 0`). |
| 4 | M | `commandData` | present only if `command != 0`; parsed by `UnmarshalCommand(command, data)`. |

Verbatim client check: `if buffer.Byte(0) != c.responseHeader { reject }`. If
`buffer.Byte(2) != 0`, it reads `dataLen = buffer.Byte(3)` more bytes and calls
`UnmarshalCommand`. Known commands are **dynamic-port / switch-account** style
directives (`commandData` carries host/port/id/alterId/valid-time). A minimal
client **may parse-and-ignore** them (skip `commandLength` bytes) — decrypt/verify
correctness does not depend on acting on them.

### 3.5 Response body

Immediately after the response header, the response body follows as chunks using
**exactly the framing of §2**, but keyed with `responseBodyKey` / `responseBodyIV`:

- aes-128-gcm: `NewAesGcm(responseBodyKey)`, nonce `GenerateChunkNonce(responseBodyIV,12)`.
- chacha20:    `chacha20poly1305.New(GenerateChacha20Poly1305Key(responseBodyKey))`,
  nonce `GenerateChunkNonce(responseBodyIV,12)`.
- Same `PlainChunkSizeParser` length semantics, same empty-chunk EOF, same
  masking/padding gating on options `M`/`P` (baseline: neither).

---

## 4. Half-close / cancellation semantics for a `Stream` wrapper

- **Writer signals EOF** by emitting the empty terminating chunk (§2.3): seal an
  empty plaintext under the next chunk nonce and frame it (`00 10` + 16-byte tag).
  In a .NET `Stream`, do this on graceful close / `FlushFinalBlock`-equivalent —
  once, then write no further body bytes. (TCP FIN alone is not the in-band EOF;
  the authenticated empty chunk is.)
- **Reader detects EOF** when it decodes a chunk whose `length == Overhead (16)`
  (baseline) — i.e. an authenticated empty chunk → surface as normal end-of-stream
  (`Read` returns 0). The tag on that empty chunk must still verify.
- **Half-close**: request-body and response-body streams are independent
  (separate keys, IVs, and counters). One direction may send its EOF chunk while
  the other keeps flowing. Model as two half-duplex encrypted streams over one
  transport.
- **Unexpected mid-chunk close**: if the underlying connection closes while a chunk
  is partially received (fewer than `length` sealed bytes available, or the length
  prefix itself is truncated), this is a **truncation error**, NOT clean EOF —
  surface it as an `IOException`/`EndOfStreamException`. Clean EOF is *only* the
  authenticated empty chunk. A failed `Open` (bad tag) is likewise a hard error
  (tampering / desync), never treated as EOF.

---

## 5. .NET BCL notes (net8 / net9 / net10)

- **AES-GCM** — `System.Security.Cryptography.AesGcm`. In .NET 8+ the tag-length
  is mandatory: construct as `new AesGcm(key, tagSizeInBytes: 16)` (the
  length-less ctor is obsolete/removed in net8). `AesGcm.IsSupported` exists.
  Nonce 12 bytes, tag 16 bytes — matches VMess.
- **ChaCha20-Poly1305** — `System.Security.Cryptography.ChaCha20Poly1305`. Nonce
  12, tag 16 (fixed) — matches. **`ChaCha20Poly1305.IsSupported` may be `false`**
  on some platforms (it wraps OS primitives: OpenSSL on Linux/macOS, CNG on
  Windows — unsupported on older Windows builds). **Always gate usage on
  `ChaCha20Poly1305.IsSupported`**; if false, fall back (e.g. BouncyCastle
  `ChaCha20Poly1305` or restrict `security` to `aes-128-gcm`). Do not assume it
  is present.
- **MD5** — `MD5.HashData(...)` (one-shot). Needed for the ChaCha key expansion
  (§1.3) and legacy paths. (Cryptographically weak, but the protocol mandates it
  here.)
- **SHA-256** — `SHA256.HashData(...)` for `responseBodyKey/IV` derivation (§1.1).
- **HMAC-SHA256** — `HMACSHA256` / `HMACSHA256.HashData(...)`. **Caveat:** the VMess
  `KDF` is a *nested* HMAC (§3.1) where an inner HMAC is used as the outer HMAC's
  hash function. `HMACSHA256` alone cannot express that; implement a small
  recursive-HMAC helper (a custom `HashAlgorithm` that wraps an `HMACSHA256`, or a
  hand-rolled HMAC over an HMAC PRF). Verify it against a known VMess test vector.
- **SHAKE128** — `System.Security.Cryptography.Shake128` exists in **.NET 8+**
  (`Shake128.IsSupported`). Needed only for the future `ShakeSizeParser` masking /
  global-padding support (§2.4–2.5); not required for the baseline.

---

## 6. Per-chunk pseudocode (baseline, synthetic)

### 6.1 Send request body

```
counter = 0
key   = (security==AESGCM) ? requestBodyKey
                           : Chacha20KeyExpand(requestBodyKey)   // §1.3
foreach plaintext block (<= ~2030 or up to 65519 bytes):
    nonce = putUint16BE(counter) || requestBodyIV[2:12]
    sealed = AEAD_Seal(key, nonce, plaintext, aad=EMPTY)         // len = |plaintext| + 16
    write( uint16BE(|sealed|) )                                  // = |plaintext| + 16
    write( sealed )
    counter = (counter + 1) mod 65536
// EOF:
nonce = putUint16BE(counter) || requestBodyIV[2:12]
sealed = AEAD_Seal(key, nonce, EMPTY, aad=EMPTY)                 // 16-byte tag
write( uint16BE(16) ); write( sealed )                           // 00 10 <tag>
```

### 6.2 Read server response header

```
respKey = SHA256(requestBodyKey)[0:16]
respIV  = SHA256(requestBodyIV)[0:16]
lenKey  = KDF16(respKey, "AEAD Resp Header Len Key")
lenIV   = KDF  (respIV,  "AEAD Resp Header Len IV")[0:12]
hdrKey  = KDF16(respKey, "AEAD Resp Header Key")
hdrIV   = KDF  (respIV,  "AEAD Resp Header IV")[0:12]

read 18 bytes -> encLen
Lbytes = AES128GCM_Open(lenKey, lenIV, encLen, aad=EMPTY)        // 2 bytes
L = uint16BE(Lbytes)

read (L+16) bytes -> encHdr
hdr = AES128GCM_Open(hdrKey, hdrIV, encHdr, aad=EMPTY)           // L bytes
assert hdr[0] == session.responseHeader                          // MUST verify
option = hdr[1]; command = hdr[2]; cmdLen = hdr[3]
if command != 0: cmdData = next cmdLen bytes of hdr              // parse or skip
```

### 6.3 Read response body

```
counter = 0
key   = (security==AESGCM) ? respKey : Chacha20KeyExpand(respKey)
loop:
    read 2 bytes -> length (uint16 BE)          // truncated read here => error, not EOF
    if length == 16:                            // empty chunk => clean EOF
        tag = read 16 bytes
        nonce = putUint16BE(counter) || respIV[2:12]
        AEAD_Open(key, nonce, tag, aad=EMPTY)   // must verify; then stream is closed
        break
    sealed = read (length) bytes                // short read => error
    nonce  = putUint16BE(counter) || respIV[2:12]
    plaintext = AEAD_Open(key, nonce, sealed, aad=EMPTY)   // bad tag => hard error
    deliver(plaintext)
    counter = (counter + 1) mod 65536
```

---

## 7. Reference test vectors

No official byte-level VMessAEAD **body**/response test vectors are published in
the v2ray-core / Xray-core repos (the encoding tests use randomized round-trips,
not fixed vectors). Recommended approach: generate vectors by running the Go
reference (`proxy/vmess/encoding`) with a fixed RNG seed and capturing wire bytes,
then assert the C# implementation reproduces them. Nested-HMAC `KDF` in particular
should be pinned to a captured `(key, label) -> 16/12 bytes` vector. **Flagged as
not-independently-verified** — see below.
