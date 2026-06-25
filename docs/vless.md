# VLESS

VLESS - легкий proxy-протокол семейства Xray/V2Ray. Важная мысль для
QuickProxyNet: сам VLESS - это не транспорт и не шифрование. Это короткий
request/response header, который идет поверх уже установленного канала.

Типичные стеки:

```text
TCP -> VLESS -> target TCP stream
TCP -> TLS -> VLESS -> target TCP stream
TCP -> REALITY -> VLESS -> target TCP stream
TCP -> WebSocket/gRPC/XHTTP -> VLESS -> target stream
```

Для Minecraft интересен режим `network=tcp`/`type=tcp`/`type=raw` и команда
`TCP`. После успешного VLESS handshake можно вернуть обычный `Stream`.

## URI

Распространенная форма:

```text
vless://<uuid>@<server>:<port>?type=tcp&security=none#name
vless://<uuid>@<server>:<port>?type=tcp&security=tls&sni=example.com#name
vless://<uuid>@<server>:<port>?type=tcp&security=reality&pbk=...&sid=...&sni=...&fp=chrome&flow=xtls-rprx-vision#name
```

Частые параметры:

| Параметр | Значение |
| --- | --- |
| `uuid` / userinfo | 16-байтовый идентификатор пользователя |
| `type` / `network` | транспорт: `tcp`/`raw`, `ws`, `grpc`, `xhttp`, `httpupgrade` |
| `security` | `none`, `tls`, `reality` |
| `sni` / `serverName` | имя для TLS/REALITY handshake |
| `flow` | например `xtls-rprx-vision`; влияет на XTLS/REALITY режим |
| `pbk` | REALITY public key |
| `sid` | REALITY short id |
| `fp` | uTLS/browser fingerprint: `chrome`, `firefox`, `safari`, etc. |
| `alpn` | ALPN для TLS/REALITY |
| `path`, `host`, `serviceName` | параметры WebSocket/gRPC/XHTTP транспортов |

## Wire format: базовый TCP CONNECT

Xray `EncodeRequestHeader` пишет:

```text
+---------+----------+-------------+---------+-------------+
| Version | UUID     | Addons      | Command | Destination |
+---------+----------+-------------+---------+-------------+
| 1 byte  | 16 bytes | variable    | 1 byte  | variable    |
+---------+----------+-------------+---------+-------------+
```

`Version` сейчас `0x00`.

`UUID` - 16 байт в RFC/network byte order. В .NET нельзя бездумно брать
`Guid.ToByteArray()` для старых overload-ов, потому что там mixed-endian порядок.
Для .NET 8+ лучше использовать `Guid.TryWriteBytes(..., bigEndian: true, ...)`
или вручную парсить canonical UUID string.

`Addons` для обычного режима без XTLS:

```text
00
```

Это длина protobuf/addons-блока. Для простого TCP она равна нулю.

`Command`:

```text
01 = TCP
02 = UDP
03 = Mux
04 = Reverse / RVS
```

Для Minecraft нужен `0x01`.

`Destination` у VLESS кодируется как `port then address`:

```text
+------+----------+
| Port | Address  |
+------+----------+
| 2 BE | variable |
+------+----------+
```

Address:

```text
01 + 4 bytes IPv4
02 + 1 byte domain length + domain bytes
03 + 16 bytes IPv6
```

Пример для target `mc.example.com:25565` и UUID
`11223344-5566-7788-99aa-bbccddeeff00`:

```text
00                                      version
11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00
00                                      addons length
01                                      command TCP
63 DD                                   port 25565
02                                      domain address type
0E                                      domain length
6D 63 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D
```

После этих байт клиент может писать первый пакет целевого протокола, например
Minecraft handshake/status/login.

## Response header

Сервер отвечает:

```text
+---------+--------+
| Version | Addons |
+---------+--------+
| 1 byte  | var    |
+---------+--------+
```

В простом случае это:

```text
00 00
```

После response header поток прозрачен: следующие байты - это уже ответ target-а.

## Режимы security

### `security=none`

Самый простой вариант:

```text
TCP connect -> VLESS request -> VLESS response -> raw Stream
```

Это хорошо ложится в QuickProxyNet и похоже на SOCKS5 CONNECT. Runtime
dependencies не нужны.

### `security=tls`

Порядок:

```text
TCP connect -> SslStream.AuthenticateAsClientAsync -> VLESS -> Stream
```

Для C# это тоже реалистично. Возвращаемым `Stream` будет `SslStream`.
Нужно поддержать `sni`, ALPN и certificate validation options.

### `security=reality`

REALITY занимает место TLS, но не является обычным `SslStream`:

```text
TCP connect -> REALITY/uTLS handshake -> VLESS -> Stream
```

Нужны public key, short id, SNI/serverName, uTLS fingerprint и проверка
REALITY-specific certificate behavior. Это отдельный transport security слой.
Его нельзя полноценно сделать через стандартный .NET `SslStream`, потому что
`SslStream` не дает точный browser-like ClientHello fingerprint.

### `flow=xtls-rprx-vision`

Flow не меняет базовый VLESS request header как таковой, но меняет поведение
последующего копирования/шифрования в XTLS/REALITY режиме. Для чистой
QuickProxyNet-реализации его лучше считать отдельной большой задачей, а не
частью базового VLESS.

## Stream-модель

| Режим | Можно вернуть `Stream` | Сложность |
| --- | --- | --- |
| TCP + none | Да, `NetworkStream` | Низкая |
| TCP + TLS | Да, `SslStream` | Средняя |
| TCP + REALITY | Да, но нужен custom stream/engine | Высокая |
| WebSocket | Да, но нужен WS stream adapter | Средняя |
| gRPC/XHTTP | Не обычный TCP stream без HTTP/2/3 слоя | Высокая |
| UDP | Не `Stream`; нужен datagram API | Отдельная модель |

## Заметки для реализации

- Начать с `VlessClient : ProxyClient` и `VlessHelper`.
- URI scheme: `vless`.
- Для `security=none` достаточно построить header в stack/pooled buffer.
- Для `security=tls` сначала завернуть socket в `SslStream`.
- UUID byte order покрыть unit-тестом.
- Domain length ограничен одним байтом.
- Response header надо прочитать до возврата stream, иначе пользователь увидит
  `00 00` перед байтами target-а.

## Источники

- Xray VLESS encoding: https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go
- Xray protocol address parser: https://github.com/XTLS/Xray-core/blob/main/common/protocol/address.go
- Xray VLESS outbound docs: https://xtls.github.io/en/config/outbounds/vless.html
- Xray transport docs: https://xtls.github.io/en/config/transport.html
- REALITY notes: https://github.com/XTLS/REALITY/blob/main/README.en.md
