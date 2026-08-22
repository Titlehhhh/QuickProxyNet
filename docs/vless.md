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

Реализовано, в ядре. REALITY занимает место TLS, но не является `SslStream` —
рукопожатие написано своё (`Internal/Reality/`: X25519, HKDF key schedule, record
layer, ClientHello с запечатанным в `session_id` ключом):

```text
TCP connect -> RealityTlsClient.HandshakeAsync -> VLESS -> Stream
```

Из ссылки берутся `pbk` (X25519 public key, base64url), `sid`, `sni`; ALPN по
умолчанию `h2, http/1.1`, как у Xray. Сервер, не узнавший нас, отдаёт настоящий
сертификат decoy-сайта — это приходит как `RealityHandshakeException` с кодом
`AuthFailed`. Чего нет: браузерного отпечатка ClientHello (`fp=chrome` сегодня
декоративен) — см. `reality-fingerprint-plan.md`.

### `flow=xtls-rprx-vision`

Реализовано. Flow добавляет в request header блок addons — protobuf-сообщение с
одним полем: `0x0A`, длина, `xtls-rprx-vision`. Сервер, у которого пользователь
настроен с этим flow, без него просто рвёт соединение.

Дальше меняется и сам поток. Сервер отвечает не чистым VLESS: после двухбайтового
response header идёт UUID пользователя (один раз), а за ним кадры

```
command(1) | contentLen(2 BE) | paddingLen(2 BE) | content | padding
```

пока не придёт команда `0x01` (end) или `0x02` (direct) — после неё соединение
сырое. Команда `0x02` в жизни встречается чаще: её Xray шлёт, решив, что внутри
TLS. Клиент, который её игнорирует, зависает на следующем заголовке.

`VisionStream` снимает эти кадры на приёме и один раз паддит первую отправку.
Вторая половина Vision — splice в прямое копирование при обнаружении TLS-в-TLS —
не реализована: это оптимизация пропускной способности, на формат провода она не
влияет.

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
- Response header читается лениво, на первом `Read` (`VlessResponseStream`): ни
  Xray, ни sing-box не шлют его, пока target не ответил, и чтение до возврата
  stream дедлочит любой client-speaks-first протокол. См. AGENTS.md, правило 2.

## Источники

- Xray VLESS encoding: https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go
- Xray protocol address parser: https://github.com/XTLS/Xray-core/blob/main/common/protocol/address.go
- Xray VLESS outbound docs: https://xtls.github.io/en/config/outbounds/vless.html
- Xray transport docs: https://xtls.github.io/en/config/transport.html
- REALITY notes: https://github.com/XTLS/REALITY/blob/main/README.en.md
