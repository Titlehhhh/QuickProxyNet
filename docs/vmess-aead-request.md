# VMessAEAD Client Request Header — Byte-Exact Specification

Target: a C#/.NET reimplementation of the **VMessAEAD** (alterId = 0) client
request header and its authentication envelope.

Scope: this document covers **only** the client-side request header generation
(what the client writes onto the wire immediately after TCP connect). It does not
cover the body/data chunk framing, the response header, or legacy (non-AEAD,
alterId > 0) VMess.

Sources cross-verified (raw Go source, not blog summaries):

- `v2fly/v2ray-core` @ `master`
  - `proxy/vmess/aead/kdf.go`, `.../aead/authid.go`, `.../aead/encrypt.go`, `.../aead/consts.go`
  - `common/protocol/id.go` (cmdKey), `common/protocol/headers.go`, `common/protocol/headers.pb.go`, `common/protocol/address.go`
  - `proxy/vmess/encoding/client.go`, `proxy/vmess/encoding/encoding.go`
- `XTLS/Xray-core` @ `main` — `proxy/vmess/aead/consts.go` (identical constant values; used as a cross-check)
- V2Fly developer docs: <https://www.v2fly.org/en_US/developer/protocols/vmess.html>

All multi-byte integers on the VMess wire are **big-endian (network order)** unless
stated otherwise. All AEAD key labels below are copied **verbatim** from the Go
`const` values in `aead/consts.go`.

> Convention in this doc: `‖` = concatenation. `KDF16(k, L, a, b)` = first 16
> bytes of `KDF(k, L, a, b)`. Byte offsets are 0-based.

---

## 0. Constant reference (verbatim label strings)

From `proxy/vmess/aead/consts.go` (v2fly and Xray agree byte-for-byte):

| Go const name | Verbatim string value | Used for |
|---|---|---|
| `KDFSaltConstVMessAEADKDF` | `VMess AEAD KDF` | KDF seed / innermost HMAC key |
| `KDFSaltConstAuthIDEncryptionKey` | `AES Auth ID Encryption` | AuthID AES-128-ECB key |
| `KDFSaltConstVMessHeaderPayloadLengthAEADKey` | `VMess Header AEAD Key_Length` | length-AEAD key |
| `KDFSaltConstVMessHeaderPayloadLengthAEADIV` | `VMess Header AEAD Nonce_Length` | length-AEAD nonce |
| `KDFSaltConstVMessHeaderPayloadAEADKey` | `VMess Header AEAD Key` | payload-AEAD key |
| `KDFSaltConstVMessHeaderPayloadAEADIV` | `VMess Header AEAD Nonce` | payload-AEAD nonce |

Response-direction labels (NOT needed for the request, listed for completeness):
`AEAD Resp Header Len Key`, `AEAD Resp Header Len IV`, `AEAD Resp Header Key`,
`AEAD Resp Header IV`.

cmdKey magic string (from `common/protocol/id.go`):
`c48619fe-8f02-49e0-b9e9-edf763e17e21`

> ⚠️ These label strings are the exact bytes hashed. Any deviation (trailing space,
> underscore vs space, capitalization) breaks interop. Note the length labels use an
> **underscore**: `..._Length`. Copy them exactly.

---

## 1. cmdKey derivation (16 bytes)

`cmdKey = MD5( uuid16 ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21" )`

From `common/protocol/id.go`:

```go
md5hash := md5.New()
md5hash.Write(uuid.Bytes())                                    // 16 bytes
md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))  // 36 ASCII bytes
md5hash.Sum(id.cmdKey[:0])                                     // 16-byte digest
```

- `uuid.Bytes()` returns the **raw 16 RFC 4122 (big-endian / network-order) bytes**
  of the UUID — the same order as the canonical text form reads left to right.
  This is exactly what the project's `UuidCodec.WriteBigEndian` produces
  (`Guid.TryWriteBytes(dest, bigEndian: true, ...)`). Do **not** use
  `Guid.ToByteArray()` (that overload is little-endian for the first three fields).
- The magic string is appended as **ASCII bytes** (36 chars: 32 hex digits + 4
  dashes). It is a literal string, NOT parsed as a UUID.
- `cmdKey` is the 16-byte MD5 output; it is the `key` argument to every KDF below.

MD5 total input = 16 + 36 = **52 bytes**.

---

## 2. The VMessAEAD KDF (nested recursive HMAC-SHA256)

From `proxy/vmess/aead/kdf.go`:

```go
func KDF(key []byte, path ...string) []byte {
    hmacCreator := &hMacCreator{value: []byte(KDFSaltConstVMessAEADKDF)}
    for _, v := range path {
        hmacCreator = &hMacCreator{value: []byte(v), parent: hmacCreator}
    }
    hmacf := hmacCreator.Create()
    hmacf.Write(key)
    return hmacf.Sum(nil)
}

func (h *hMacCreator) Create() hash.Hash {
    if h.parent == nil {
        return hmac.New(sha256.New, h.value)     // base: HMAC-SHA256 keyed by the seed
    }
    return hmac.New(h.parent.Create, h.value)    // HMAC keyed by value, hash = parent HMAC
}

func KDF16(key []byte, path ...string) []byte { return KDF(key, path...)[:16] }
```

### What it computes

`KDF` builds a chain of HMAC constructors where **each path label becomes the key of
an HMAC whose underlying hash function is the previous (parent) HMAC**. The innermost
(base) HMAC is keyed by the literal seed `"VMess AEAD KDF"` over plain SHA-256. The
final HMAC is fed the `key` (cmdKey, or cmdKey for all our uses) as its message.

For labels `L1, L2, ... Ln` (in the order passed), the result is:

```
KDF(key, L1, L2, ..., Ln) =
    HMAC_{Ln}(
        h = HMAC_{L(n-1)}(
              h = ... HMAC_{L1}(
                        h = HMAC_{"VMess AEAD KDF"}(h = SHA256)
                    ) ...
            )
    )  applied to message = key
```

- The **last** path label is the key of the **outermost** HMAC.
- The **seed** `"VMess AEAD KDF"` is the key of the **innermost** HMAC (hash = SHA-256).
- The **message** passed to the final HMAC is `key` (the 16-byte cmdKey).
- Output is 32 bytes (SHA-256 block). `KDF16` = first 16 bytes. `KDF12` (nonce) =
  first 12 bytes (the code writes `KDF(...)[:12]` inline; there is no named `KDF12`).

### Reference pseudocode (recursion made explicit)

```
function KDF_bytes(key, labels[]):        # returns 32 bytes
    # Build innermost first
    inner = HMAC_SHA256_init(macKey = "VMess AEAD KDF")   # hash = SHA-256
    current = inner
    for L in labels:                       # in given order, first label wraps the seed
        current = HMAC_init(macKey = L, innerHashFactory = current)
    current.update(key)                    # message = cmdKey
    return current.finalize()              # 32 bytes

KDF16(key, labels) = KDF_bytes(key, labels)[0..16]
KDF12(key, labels) = KDF_bytes(key, labels)[0..12]
```

> Implementation note for .NET: an HMAC "whose hash function is another HMAC" is not
> directly expressible with `HMACSHA256` (which is hard-wired to SHA-256). You must
> implement the generic HMAC construction manually:
> `HMAC_K(m) = H( (K⊕opad) ‖ H( (K⊕ipad) ‖ m ) )` with block size 64, where the inner
> `H` at each level is itself a full HMAC evaluation. Keys longer than 64 bytes are
> hashed first per RFC 2104 (none of our labels exceed 64 bytes, so this branch is not
> hit here — but implement it for correctness). Verify against a captured trace.

---

## 3. AuthID (the 16-byte EAuID)

From `proxy/vmess/aead/authid.go` — `CreateAuthID(cmdKey, time.Now().Unix())`:

### 3a. Plaintext (16 bytes, pre-encryption)

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 8 | Unix timestamp (seconds) | **int64, big-endian** |
| 8 | 4 | Random | 4 bytes from `crypto/rand` |
| 12 | 4 | CRC32-IEEE of bytes `[0..12)` | **uint32, big-endian** |

```go
buf := bytes.NewBuffer(nil)
binary.Write(buf, binary.BigEndian, time)     // int64 seconds
buf.Write(random4)                            // 4 random bytes
zero := crc32.ChecksumIEEE(buf.Bytes())       // CRC32 over the first 12 bytes
binary.Write(buf, binary.BigEndian, zero)     // uint32, big-endian
// buf now holds exactly 16 bytes
```

- CRC is **CRC-32/IEEE** (poly `0xEDB88320` reflected; the standard zlib/PKZIP CRC-32,
  init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`, input & output reflected) — this is
  `crc32.ChecksumIEEE`.
- CRC input = the **first 12 bytes** (timestamp ‖ random), computed **before** the
  CRC field is appended.
- CRC output is serialized **big-endian**.

### 3b. Encryption

```go
key := KDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey)  // "AES Auth ID Encryption"
block, _ := aes.NewCipher(key)                          // AES-128
block.Encrypt(authid[:], buf.Bytes())                   // single 16-byte block
```

- Cipher: **AES-128**, single block, `block.Encrypt` = raw ECB of one block =
  **no padding, no IV, no chaining**. (16-byte plaintext → 16-byte `authid`.)
- Key = `KDF16(cmdKey, "AES Auth ID Encryption")`.
- Result `authid` (16 bytes) is the first field written on the wire.

> In .NET: use `Aes` with `Mode = CipherMode.ECB`, `Padding = PaddingMode.None`, or
> the one-shot `EncryptEcb(plaintext, PaddingMode.None)` (net6+), on a single 16-byte
> block. Do not use `AesGcm` here.

---

## 4. Request header sealing (AEAD envelope)

From `proxy/vmess/aead/encrypt.go` — `SealVMessAEADHeader(cmdKey [16]byte, data []byte)`,
where `data` is the plaintext instruction/command section from §5.

### 4a. Wire order (exact)

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | `authid` (§3, the EAuID) |
| 16 | 2 + 16 | `encryptedLength` = AES-128-GCM(len(data) as uint16 BE) + 16-byte tag = **18 bytes** |
| 34 | 8 | `connectionNonce` (8 random bytes from `crypto/rand`) |
| 42 | L + 16 | `encryptedHeader` = AES-128-GCM(data) + 16-byte tag, where `L = len(data)` |

Total request-header size = `16 + 18 + 8 + (L + 16)` = **58 + L** bytes.

```go
generatedAuthID := CreateAuthID(cmdKey[:], time.Now().Unix())    // 16 bytes (§3)
connectionNonce := random(8)

lenBytes := uint16BE(len(data))                                  // 2 bytes

// --- length AEAD ---
lenKey   := KDF16(cmdKey, "VMess Header AEAD Key_Length",   authid, connectionNonce)
lenNonce := KDF  (cmdKey, "VMess Header AEAD Nonce_Length", authid, connectionNonce)[:12]
encryptedLength = AES128GCM(lenKey).Seal(nonce=lenNonce, plaintext=lenBytes, aad=authid)

// --- payload AEAD ---
payKey   := KDF16(cmdKey, "VMess Header AEAD Key",   authid, connectionNonce)
payNonce := KDF  (cmdKey, "VMess Header AEAD Nonce", authid, connectionNonce)[:12]
encryptedHeader = AES128GCM(payKey).Seal(nonce=payNonce, plaintext=data, aad=authid)

output = authid ‖ encryptedLength ‖ connectionNonce ‖ encryptedHeader
```

### 4b. The four KDF derivations (verbatim labels + args)

Both AEADs are keyed off `cmdKey` and mixed with **both** `authid` and
`connectionNonce` as extra KDF path elements (passed as raw byte strings, in that
order):

| Purpose | Function | Label (verbatim) | Extra KDF args | Output |
|---|---|---|---|---|
| Length key | `KDF16` | `VMess Header AEAD Key_Length` | `authid`, `connectionNonce` | 16 B |
| Length nonce | `KDF`→`[:12]` | `VMess Header AEAD Nonce_Length` | `authid`, `connectionNonce` | 12 B |
| Payload key | `KDF16` | `VMess Header AEAD Key` | `authid`, `connectionNonce` | 16 B |
| Payload nonce | `KDF`→`[:12]` | `VMess Header AEAD Nonce` | `authid`, `connectionNonce` | 12 B |

So each key/nonce is `KDF(cmdKey, LABEL, authid, connectionNonce)` — i.e. a 3-label
KDF path: `[LABEL, authid_bytes, connectionNonce_bytes]`.

### 4c. AEAD parameters

- Algorithm: **AES-128-GCM** (`aes.NewCipher` + `cipher.NewGCM`), 16-byte (128-bit)
  authentication tag, 12-byte nonce (standard GCM).
- **AAD = `authid` (the 16-byte EAuID) for BOTH** the length AEAD and the payload
  AEAD. (Confirmed: `Seal(nil, nonce, plaintext, generatedAuthID[:])` in both blocks.)
- GCM `Seal` output = ciphertext (same length as plaintext) followed by the 16-byte
  tag. So encryptedLength = 2 + 16 = 18 bytes; encryptedHeader = L + 16 bytes.

> In .NET: `AesGcm` (net5+). Construct with the 16-byte key; the constructor now
> requires the tag size (`new AesGcm(key, 16)` on net8+). Call
> `Encrypt(nonce12, plaintext, ciphertext, tag16, associatedData: authid)`.

---

## 5. Plaintext instruction/command section (`data`, what §4 seals)

Built in `proxy/vmess/encoding/client.go` (`EncodeRequestHeader`). This is the
plaintext that becomes `encryptedHeader`.

### 5a. Field layout

| Offset | Size | Field | Value / encoding |
|---|---|---|---|
| 0 | 1 | Version | `0x01` (constant `Version = byte(1)`) |
| 1 | 16 | `requestBodyIV` | random (used later for body cipher) |
| 17 | 16 | `requestBodyKey` | random (used later for body cipher) |
| 33 | 1 | `responseHeader` (respV) | random byte; server echoes it in its response header |
| 34 | 1 | Option (`Opt`) | bitflags, see §5b |
| 35 | 1 | `(paddingLen << 4) \| security` | high nibble = padding length; low nibble = security type (§5c) |
| 36 | 1 | Reserved | `0x00` |
| 37 | 1 | Command | `0x01` TCP, `0x02` UDP, `0x03` Mux |
| 38 | 2 | Port | **big-endian uint16** |
| 40 | 1 | Address type (`T`) | `0x01` IPv4, `0x02` domain, `0x03` IPv6 |
| 41 | var | Address | see §5d |
| … | `paddingLen` | Random padding | `paddingLen` random bytes |
| end−4 | 4 | Checksum `F` | **FNV-1a-32, big-endian**, over all preceding bytes (§5e) |

> ⚠️ Field order for port vs address: the VMess command section writes **port first,
> then address type, then address** (`addrParser` is configured `PortThenAddress`).
> This is the opposite of SOCKS5/Trojan/VLESS ordering. Confirmed via
> `PortThenAddress()` in `encoding.go`.

### 5b. Option byte bitflags (`common/protocol/headers.go`)

| Flag | Value | Meaning |
|---|---|---|
| `RequestOptionChunkStream` (S) | `0x01` | body sent as chunked stream (standard) |
| `RequestOptionConnectionReuse` (R) | `0x02` | connection reuse (deprecated) |
| `RequestOptionChunkMasking` (M) | `0x04` | chunk length obfuscation |
| `RequestOptionGlobalPadding` (P) | `0x08` | global padding |
| `RequestOptionAuthenticatedLength` (A) | `0x10` | authenticated chunk length |

The exact option value is a **client configuration choice** (depends on the negotiated
security and features), not a fixed constant. For a typical modern AEAD client using
AES-128-GCM or ChaCha20-Poly1305, v2ray sets
`ChunkStream | ChunkMasking | GlobalPadding | AuthenticatedLength` (`0x01|0x04|0x08|0x10 = 0x1D`).
These flags govern **body framing**, which is out of this document's scope — but they
must be written correctly here because the server reads them from this header.

### 5c. Security type (low nibble of byte 35)

The low nibble is `byte(header.Security)`, i.e. the numeric `SecurityType`
(`common/protocol/headers.pb.go`). Wire values (confirmed identical in the v2fly doc's
"Sec" table):

| SecurityType | Numeric / nibble value | Meaning |
|---|---|---|
| `UNKNOWN` | `0` (`0x0`) | unknown (not written) |
| `LEGACY` | `1` (`0x1`) | AES-128-CFB (legacy, non-AEAD body) |
| `AUTO` | `2` (`0x2`) | auto — resolved to a concrete cipher before writing |
| `AES128_GCM` | `3` (`0x3`) | AES-128-GCM |
| `CHACHA20_POLY1305` | `4` (`0x4`) | ChaCha20-Poly1305 |
| `NONE` | `5` (`0x5`) | no body encryption |
| `ZERO` | `6` (`0x6`) | "zero" — no encryption and no auth (implies NONE + no chunk stream) |

- For a normal AEAD client you will write `3` (AES-128-GCM) or `4`
  (ChaCha20-Poly1305) in the low nibble.
- `AUTO (2)` and `UNKNOWN (0)` should not appear on the wire: the client resolves
  `AUTO` to `AES128_GCM` (or ChaCha20-Poly1305 on platforms without AES hardware)
  before serializing.
- High nibble = `paddingLen` (0–15, see §6).

### 5d. Address encoding

| Address type | Bytes written |
|---|---|
| IPv4 (`0x01`) | 4 raw bytes |
| Domain (`0x02`) | 1-byte length `n`, then `n` ASCII/IDNA bytes |
| IPv6 (`0x03`) | 16 raw bytes |

(Port — 2 bytes big-endian — is written **before** the address-type byte; see §5a.)

### 5e. Checksum: FNV-1a-32

From `encoding/client.go`: `fnv1a := fnv.New32a(); fnv1a.Write(buffer.Bytes()); fnv1a.Sum(hashBytes[:0])`.

- Algorithm: **FNV-1a, 32-bit**.
  - Offset basis = `2166136261` (`0x811C9DC5`)
  - Prime = `16777619` (`0x01000193`)
  - Per byte: `hash ^= b; hash *= prime` (XOR first, then multiply — the "1a" variant),
    all arithmetic mod 2³².
- Input = **every byte of the command section written so far**, i.e. version through
  random padding **inclusive** (the padding IS covered by the checksum; the checksum
  is appended last).
- Output = 4 bytes **big-endian** (Go `hash.Hash32.Sum` emits the uint32 big-endian).

> The 4-byte checksum is part of `data` (the payload plaintext). The §4 payload AEAD
> then seals the whole thing (including this FNV checksum) and adds its own GCM tag on
> top. So the header has two independent integrity layers: the inner FNV-1a and the
> outer GCM tag.

---

## 6. Time window, jitter, and padding length

### 6a. Timestamp used by the client

- The AuthID timestamp (§3a) is `time.Now().Unix()` — the **current UTC time in
  whole seconds** (Unix epoch), int64 big-endian. For **VMessAEAD the client uses the
  exact current second** (no random jitter is added to the AEAD AuthID timestamp;
  `SealVMessAEADHeader` calls `CreateAuthID(key, time.Now().Unix())` directly).

> ⚠️ Distinction from **legacy VMess**: the old (alterId>0, MD5-auth) format hashed a
> timestamp randomized within **±30 seconds** of now (the "±30s" figure in the v2fly
> developer doc refers to that legacy path, not to AEAD). Do not apply ±30s jitter to
> the AEAD AuthID.

### 6b. Server-side acceptance window (informational — client just uses "now")

From `proxy/vmess/aead/authid.go`, the server's `AuthIDDecoder.Match` rejects any
decrypted AuthID whose timestamp differs from the server's current time by **more than
120 seconds**:

```go
if math.Abs(math.Abs(float64(t)) - float64(time.Now().Unix())) > 120 { continue }
```

The replay filter is likewise sized for a **120-second** window (`cacheDurationSec = 120`
in `validator.go`, giving a ±120 s generation range). **Practical implication for the
client: its clock must be within ~120 s of the server's.** The client itself sends
"now"; it does not choose a window.

### 6c. Random padding length

- `paddingLen := dice.RollWith(16, rand.Reader)` → a random integer in **[0, 16)**,
  i.e. **0–15** inclusive (fits the 4-bit high nibble of byte 35).
- `paddingLen` random bytes (from `crypto/rand`) are appended after the address and
  **before** the FNV-1a checksum, and are covered by that checksum (§5e).

---

## 7. .NET BCL availability notes (net8 / net9 / net10)

Available in `System.Security.Cryptography` — use directly:

| Primitive | .NET API | Notes |
|---|---|---|
| MD5 (cmdKey) | `MD5.HashData(...)` | one-shot, static; fine for the 52-byte input |
| SHA-256 | `SHA256`, `SHA256.HashData` | base hash for the KDF's HMAC |
| HMAC-SHA256 | `HMACSHA256`, `HMACSHA256.HashData(key, data)` | see caveat below |
| AES-128-ECB single block (AuthID) | `Aes` with `Mode=ECB, Padding=None`, or `aes.EncryptEcb(pt, PaddingMode.None)` | one 16-byte block; NOT AesGcm |
| AES-128-GCM (envelope) | `AesGcm` | net8+ constructor requires tag size: `new AesGcm(key, 16)` |

Must be implemented manually:

| Primitive | Why | Guidance |
|---|---|---|
| **VMessAEAD nested KDF** | The KDF nests HMAC-inside-HMAC (the "hash function" of an outer HMAC is itself an HMAC). `HMACSHA256` is hard-wired to SHA-256 and cannot be nested via the BCL. | Implement the RFC 2104 HMAC construction generically (block size 64, ipad `0x36`, opad `0x5C`), so the inner hash at each level can be another HMAC evaluation. Then layer per §2. |
| **FNV-1a-32** | No BCL type. | Trivial: `uint hash = 2166136261; foreach(b) { hash ^= b; hash *= 16777619; }` then write big-endian. |
| **CRC-32/IEEE** (AuthID) | Not in `System.Security.Cryptography`. | `System.IO.Hashing.Crc32` exists but is an **out-of-band NuGet package** (`System.IO.Hashing`), not part of the base runtime — flag this dependency. It computes CRC-32/IEEE and matches `crc32.ChecksumIEEE`; **verify its output byte order** (the type's `GetCurrentHash`/`GetHashAndReset` emits **little-endian** bytes per its docs, whereas VMess needs the value **big-endian** — reverse or re-serialize accordingly). A ~15-line table-based inline implementation avoids the dependency entirely and is easy to get right. |

> ChaCha20-Poly1305 (for `SecurityType 4`) is only needed for the **body** cipher, not
> the request header (the header envelope is always AES-128-GCM). `ChaCha20Poly1305`
> exists in the BCL (net7+) but availability is platform-dependent
> (`ChaCha20Poly1305.IsSupported`). Out of scope here.

---

## 8. Worked layout summary (example values only — no real UUID)

Using synthetic placeholders (do NOT use as test vectors — these are illustrative):

- UUID (example): `b831381d-6324-4d53-ad4f-8cda48b30811` → `uuid16` = its 16 RFC 4122
  big-endian bytes → `cmdKey = MD5(uuid16 ‖ magic)` (16 bytes).
- Suppose the resolved target is IPv4 `93.184.216.34:443`, TCP, AES-128-GCM,
  `paddingLen = 5`.

Plaintext command section (`data`):

```
01                                  version
<16 bytes>                          requestBodyIV
<16 bytes>                          requestBodyKey
<1 byte>                            responseHeader (respV)
1D                                  option (S|M|P|A) — config-dependent
53                                  (paddingLen=5)<<4 | security=3(GCM) = 0x53
00                                  reserved
01                                  command = TCP
01 BB                               port 443, big-endian
01                                  address type = IPv4
5D B8 D8 22                         address 93.184.216.34
<5 random bytes>                    random padding (paddingLen=5)
<4 bytes>                           FNV-1a-32(all bytes above), big-endian
```

Then the wire header = `authid(16) ‖ encLen(18) ‖ connNonce(8) ‖ encHeader(len(data)+16)`.

---

## Verification status

Every constant, label, offset, and endianness above was read from the raw Go source of
`v2fly/v2ray-core@master` and cross-checked against `XTLS/Xray-core@main` for the AEAD
constants (identical). Items a reader should still re-confirm against source or a live
capture before shipping are listed in the accompanying summary.
