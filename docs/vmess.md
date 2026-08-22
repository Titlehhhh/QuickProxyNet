# VMess

VMess - оригинальный зашифрованный протокол V2Ray. В отличие от VLESS, VMess
не является маленьким CONNECT header-ом: он включает аутентификацию,
шифрование header-а и шифрование/маскирование тела. Для QuickProxyNet это
значит, что после handshake нельзя просто вернуть исходный `NetworkStream`:
нужен stream-wrapper, который шифрует `Write` и расшифровывает `Read`.

## Стек

Типичные варианты:

```text
TCP -> VMess encrypted stream
TCP -> TLS -> VMess encrypted stream
TCP -> WebSocket -> VMess
TCP -> HTTP/2/gRPC -> VMess
```

VMess зависит от времени: клиент и сервер должны иметь близкое UTC-время,
потому что timestamp участвует в защите от replay.

## URI

Классическая share-ссылка часто выглядит как base64-encoded JSON:

```text
vmess://base64({
  "v": "2",
  "ps": "name",
  "add": "server.example.com",
  "port": "443",
  "id": "uuid",
  "aid": "0",
  "scy": "auto",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": "tls",
  "sni": "example.com"
})
```

Также встречаются URI-форматы, но JSON-base64 все еще широко распространен.

Поля:

| Поле | Значение |
| --- | --- |
| `add` | сервер |
| `port` | порт |
| `id` | UUID пользователя |
| `aid` / `alterId` | legacy параметр; современный AEAD обычно использует `0` |
| `scy` / `security` | шифрование тела: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` в некоторых клиентах |
| `net` | `tcp`, `ws`, `grpc`, `h2`, etc. |
| `tls` | `tls`, пусто, иногда `reality` в Xray-экосистеме |
| `sni` | SNI для TLS |
| `host`, `path` | transport-specific параметры |

## Header authentication

Официальная V2Fly developer-документация разделяет два режима:

- AEAD authentication - современный вариант, обеспечивает целостность header-а.
- MD5 authentication - legacy вариант через MD5 + AES-128-CFB; deprecated.

Для новой реализации надо ориентироваться на AEAD и не начинать с legacy MD5,
если не нужна совместимость со старыми серверами.

## Request structure на уровне полей

VMess request асимметричен: client request и server response имеют разные
форматы. Wire bytes зависят от режима authentication/encryption, поэтому
ниже структура полей до шифрования/оберток:

Логически запрос состоит из:

```text
Authentication Info
Command Section
Data Section
```

В современном AEAD-формате request выглядит так:

```text
+---------------------+---------+-------+---------+--------------+
| Authentication Info | ALength | Nonce | AHeader | Data Section |
+---------------------+---------+-------+---------+--------------+
| 16                  | 18      | 8     | var     | var          |
+---------------------+---------+-------+---------+--------------+
```

`Authentication Info` на plaintext-уровне строится из timestamp, random bytes
и CRC32, затем шифруется/аутентифицируется. Поэтому VMess чувствителен к
синхронизации времени.

```text
Auth / encrypted header:
  version
  user credential / UUID-derived auth
  timestamp / nonce
  request body key
  request body IV
  response header byte
  options
  padding/security
  command
  destination port
  destination address type + address
  random padding
  checksum / AEAD tag

Encrypted body:
  length/security framing
  encrypted payload chunks
```

Команды близки к другим V2Ray protocol structs:

```text
01 = TCP
02 = UDP
03 = Mux
```

Destination обычно несет port/address для target, но конкретный byte layout
надо брать из выбранной VMess AEAD реализации, потому что header завернут в
AEAD-authenticated envelope.

Command Section до защиты содержит:

| Поле | Размер | Назначение |
| --- | ---: | --- |
| `Version` | 1 | protocol version, обычно `1` |
| `Request Encryption IV` | 16 | IV для payload |
| `Request Encryption Key` | 16 | ключ для payload |
| `Response Auth V` | 1 | байт, который должен вернуться в response |
| `Option` | 1 | bit flags |
| `Margin P` | 4 бита | размер random padding |
| `Encryption Sec` | 4 бита | режим шифрования data section |
| `Reserved` | 1 | должен быть `0` |
| `Command Cmd` | 1 | TCP/UDP |
| `Port` | 2 | target port, big-endian |
| `Address Type` | 1 | IPv4/domain/IPv6 |
| `Address` | variable | target address |
| `Random` | `P` | padding |
| `Checksum` | 4 | FNV1a от command section без checksum |

Command values:

```text
01 = TCP data
02 = UDP data
```

Address type:

```text
01 = IPv4
02 = domain name
03 = IPv6
```

Domain address: `1 byte length + domain bytes`.

Option flags:

| Flag | Смысл |
| --- | --- |
| `S` | standard chunked data stream, обычно включен |
| `R` | reuse TCP connection, deprecated |
| `M` | metadata obfuscation |
| `P` | global padding |
| `A` | authenticated packet length experiment |
| `X` | reserved |

`R`, `M`, `P`, `A` зависят от `S` и поддержки конкретной реализации.

## Security тела

Распространенные варианты:

| Значение | Смысл |
| --- | --- |
| `aes-128-gcm` | AEAD encryption тела |
| `chacha20-poly1305` | AEAD encryption тела |
| `auto` | клиент/реализация выбирает подходящий cipher |
| `none` | встречается в конфиг-экосистемах, но не делает VMess таким же простым как VLESS |
| `zero` | raw stream copy для payload, но header/auth остаются |
| `aes-128-ctr` | legacy compatibility в некоторых реализациях |

Даже если body security отключена/упрощена, VMess header authentication остается
существенно сложнее VLESS.

`alterId` сейчас legacy:

```text
alterId = 0  -> VMessAEAD
alterId = 1+ -> legacy compatibility
```

Для новой реализации разумный baseline: canonical UUID, `alterId = 0`, AEAD,
`aes-128-gcm` или `chacha20-poly1305`.

## Transport/security режимы

| Слой | Для `Stream` |
| --- | --- |
| `net=tcp`, без TLS | Нужен `VmessaeadStream`, который шифрует/дешифрует body |
| `net=tcp`, `tls=tls` | `SslStream` снаружи + VMess stream-wrapper внутри |
| WebSocket | нужен WebSocket stream adapter + VMess wrapper |
| gRPC/H2 | нужен HTTP/2/gRPC transport adapter |
| REALITY | те же проблемы, что у VLESS REALITY, плюс VMess |

В Xray transport/security разделены: transport methods (`raw`, `websocket`,
`grpc`, `httpupgrade`, `xhttp`, etc.) и transport security (`none`, `tls`,
`reality`). В sing-box похожие части вынесены в `tls`, `transport`,
`packet_encoding` и `network`.

## Практическая оценка для QuickProxyNet

VMess сложнее Trojan и VLESS:

- нужен AEAD KDF/authentication;
- нужен body framing;
- нужен replay/time behavior;
- нужен encrypted stream wrapper;
- много legacy-совместимости: alterId, MD5 auth, разные `security` значения.
- `zero` упрощает только payload, но не убирает VMess header/auth state machine.
- UDP нельзя честно выразить одним `Stream`; нужен packet/datagram API.

Если цель - быстро получить TCP `Stream` для Minecraft, VMess не лучший первый
кандидат. Лучше сначала VLESS none/TLS и Trojan. VMess стоит добавлять только
после решения, какую совместимость поддерживать: modern AEAD-only или legacy
тоже.

Для C# рабочая модель выглядит так:

```text
Socket/NetworkStream
optional SslStream
optional transport adapter
VMess protocol adapter
Stream/PipeReader/PipeWriter для payload
```

Самая большая сложность - совместить time-based auth, AEAD/legacy режимы,
chunk framing, half-close/cancellation semantics и совместимость с выбранным
core.

## Источники

- V2Fly VMess developer protocol docs: https://www.v2fly.org/en_US/developer/protocols/vmess.html
- Project X VMess protocol docs: https://xtls.github.io/en/development/protocols/vmess.html
- V2Fly VMess config docs: https://www.v2fly.org/en_US/v5/config/proxy/vmess.html
- Xray VMess inbound docs: https://xtls.github.io/en/config/inbounds/vmess.html
- Xray VMess outbound docs: https://xtls.github.io/en/config/outbounds/vmess.html
- Xray transport docs: https://xtls.github.io/en/config/transport.html
- sing-box VMess outbound: https://sing-box.sagernet.org/configuration/outbound/vmess/
- sing-box V2Ray transport: https://sing-box.sagernet.org/configuration/shared/v2ray-transport/
- V2Fly VMess AEAD source: https://github.com/v2fly/v2ray-core/tree/master/proxy/vmess/aead
