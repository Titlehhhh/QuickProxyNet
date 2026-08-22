# Trojan

Trojan - proxy-протокол, который маскируется под обычный TLS-сервис. Для
QuickProxyNet он очень удобен: после TLS handshake клиент отправляет короткий
Trojan request, читает/не читает дополнительный ответ в зависимости от режима,
и дальше поток становится обычным TCP stream к target.

## Стек

Базовый поток:

```text
TCP connect -> TLS -> Trojan request -> target TCP stream
```

В отличие от VLESS `security=none`, Trojan по спецификации ожидает TLS. Сам
Trojan header идет внутри TLS.

## URI

Распространенная форма:

```text
trojan://<password>@<server>:<port>?sni=example.com#name
trojan://<password>@<server>:<port>?security=tls&type=tcp&sni=example.com#name
```

Параметры:

| Параметр | Значение |
| --- | --- |
| userinfo/password | пароль пользователя |
| `sni` | SNI для TLS |
| `allowInsecure` | клиентская политика проверки сертификата |
| `type` / `network` | `tcp`, `ws`, `grpc` в разных клиентах |
| `alpn` | TLS ALPN |
| `path`, `host`, `serviceName` | transport-specific параметры |

## Wire format

Официальная схема:

```text
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) | CRLF    | Trojan request | CRLF    | payload  |
+-----------------------+---------+----------------+---------+----------+
| 56 bytes              | 2 bytes | variable       | 2 bytes | variable |
+-----------------------+---------+----------------+---------+----------+
```

Первый блок - ASCII hex от SHA-224 пароля:

```text
56 ASCII bytes: [0-9a-f]
0D 0A
```

В .NET важный нюанс: BCL не дает готовый `SHA224`. Для zero-dependency
реализации придется добавить внутренний SHA-224 или принимать заранее
посчитанный 56-символьный hash как advanced option.

## Trojan request

Request похож на SOCKS5 request:

```text
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | variable |    2     |
+-----+------+----------+----------+
```

Команды:

```text
01 = CONNECT (TCP)
03 = UDP ASSOCIATE
```

Address types совпадают с SOCKS5:

```text
01 = IPv4, 4 bytes
03 = domain, 1 byte length + domain bytes
04 = IPv6, 16 bytes
```

Port идет после address, big-endian.

Для Minecraft `mc.example.com:25565`:

```text
<56 ascii hex chars>
0D 0A
01                                      CONNECT
03                                      domain
0E                                      length
6D 63 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D
63 DD                                   port
0D 0A
<Minecraft handshake bytes...>
```

## Response

У Trojan нет HTTP-like `200 OK`. Если authentication или connect fail, сервер
обычно закрывает соединение или ведет fallback/masquerade как обычный TLS
сервер. Поэтому для client API ошибка часто проявится как EOF/reset на первом
read/write после request.

У Xray fallback-механика описана через эвристику первого пакета: fallback может
сработать, если пакет слишком короткий для Trojan auth, если байт после
56-байтового hash не равен `\r`, или если authentication не прошла. Это не
часть минимальной wire-спеки `trojan-gfw`, но важно для совместимости с
реальными серверами.

## Transport modes

| Режим | Оценка для QuickProxyNet |
| --- | --- |
| TCP + TLS | Хороший первый кандидат |
| WebSocket + TLS | Нужен WS stream adapter |
| gRPC/H2 | Нужен HTTP/2/gRPC adapter |
| UDP associate | Не `Stream`; нужна datagram модель |

В Xray/V2Fly/sing-box transport (`raw`, WebSocket, gRPC, HTTP upgrade, XHTTP и
т.п.) является нижним способом доставки байтов до Trojan-слоя. Эти режимы
лучше документировать как implementation-specific расширения поверх базового
`TLS + Trojan request`.

## Stream-модель

Для TCP CONNECT:

```text
NetworkStream -> SslStream -> write Trojan request -> return SslStream
```

После request `SslStream` можно вернуть пользователю как прозрачный TCP stream.
Это ближе к HTTP CONNECT, чем VMess.

## Заметки для реализации

- Добавить `TrojanClient`.
- Требовать TLS по умолчанию.
- Поддержать `sni` и certificate validation callbacks аналогично
  `HttpsProxyClient`.
- Реализовать SHA-224 или отдельный режим `trojan+hash`.
- Для domain address использовать SOCKS5-compatible address writer.
- Ошибки authentication/connect могут быть диагностированы только косвенно,
  если сервер не присылает явный ответ.
- UDP поддержка требует отдельного решения: V2Fly, например, различает
  stream-like `None` и packet-mode `Packet` encoding.

## Источники

- Trojan protocol: https://trojan-gfw.github.io/trojan/protocol.html
- V2Fly Trojan config: https://www.v2fly.org/en_US/v5/config/proxy/trojan.html
- sing-box Trojan outbound: https://sing-box.sagernet.org/configuration/outbound/trojan/
