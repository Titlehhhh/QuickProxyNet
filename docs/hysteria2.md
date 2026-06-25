# Hysteria2

Hysteria2 - TCP/UDP proxy поверх QUIC. Это принципиально другой класс, чем
SOCKS/HTTP/VLESS-over-TCP: транспортом является UDP, а пользовательские TCP
соединения отображаются на QUIC streams.

`hy2://` обычно является share-link алиасом для Hysteria2.

Версионный контекст: upstream Hysteria2 на 2026-06-25 имеет актуальные
публичные документы по v2 protocol и релизы ветки `app/v2.x`.

## Стек

```text
UDP socket -> QUIC + TLS 1.3 -> Hysteria2 protocol -> QUIC stream -> target TCP stream
```

Для QuickProxyNet это значит: вернуть `Stream` можно только как wrapper поверх
одного QUIC bidirectional stream. Это не `NetworkStream`; нужна QUIC-библиотека
и управление QUIC connection lifecycle.

## URI

Распространенная форма:

```text
hysteria2://<password>@<server>:<port>?sni=example.com#name
hy2://<password>@<server>:<port>?sni=example.com#name
```

Частые параметры:

| Параметр | Значение |
| --- | --- |
| password/userinfo | пароль auth |
| `sni` | TLS SNI |
| `insecure` / `allowInsecure` | политика сертификата |
| `obfs` | obfuscation type |
| `obfs-password` | пароль obfuscation |
| `pinSHA256` | pin сертификата |
| `alpn` | ALPN, обычно HTTP/3-like |

## Protocol overview

Официальная спецификация Hysteria2 описывает протокол как TCP & UDP proxy на
базе QUIC. По умолчанию он мимикрирует под HTTP/3 traffic. Для соединения:

1. Клиент открывает QUIC connection к серверу.
2. Выполняется TLS 1.3 handshake внутри QUIC.
3. Клиент проходит Hysteria authentication.
4. Для TCP target открывается QUIC stream.
5. В stream передается request к целевому host/port и затем payload.

Точная структура frames зависит от Hysteria2 specification; это не простой
однократный header поверх TCP socket. Есть отдельная логика для TCP streams,
UDP relay, keepalive и masquerade/obfuscation.

Публично описанные wire-level свойства:

- числа больше 1 байта идут big-endian;
- QUIC varint совместим с RFC 9000;
- TCP-туннель строится как отдельный QUIC bidirectional stream;
- UDP идет через QUIC datagrams с собственной сессией/пакетом/фрагментами;
- Salamander obfuscation описана отдельно на уровне байтов;
- Gecko в upstream-документах помечается как experimental obfuscation mode.

## Шифрование

QUIC всегда включает TLS 1.3 security. Поэтому режима "без шифрования" в
практическом смысле нет:

```text
UDP packets are QUIC-protected
application data goes through QUIC crypto
```

Дополнительная obfuscation может накладываться поверх UDP/QUIC для обхода
блокировок, но это не замена TLS.

На сервере Hysteria обычно требует `tls` или `acme`; одновременно использовать
оба режима нельзя. На клиенте важны `sni`, `insecure`, certificate pinning и
client certificate options. Серверная настройка `sniGuard` может отклонять
handshake, если SNI не соответствует сертификату.

## Auth и masquerade

Официальный сервер поддерживает несколько auth-моделей:

| Режим | Смысл |
| --- | --- |
| `password` | общий секрет |
| `userpass` | alias, фактический secret `username:password` |
| `http` | backend auth через HTTP POST |
| `command` | backend auth через внешний процесс |

sing-box не имеет отдельного alias `userpass`; для совместимости там надо
передавать строку `username:password` как обычный пароль.

Masquerade нужен, чтобы endpoint выглядел как HTTP/3 сайт. Если masquerade не
настроен, сервер обычно отвечает `404 Not Found` на HTTP-запросы. Режимы:
`file`, `proxy`, `string`. Если включить obfs, сервер уже не выглядит как
валидный HTTP/3 endpoint.

## Obfs, bandwidth и realms

Obfs требует одинаковый пароль на клиенте и сервере. Salamander и Gecko - это
отдельные режимы обфускации поверх базового QUIC/TLS поведения.

Hysteria2 умеет использовать bandwidth hints и congestion control. Если
bandwidth задан, может использоваться Brutal congestion control; без него
документация описывает non-Brutal controller, обычно BBR. Эти детали upstream
считает implementation details, поэтому их нельзя фиксировать как вечный
wire-contract.

Hysteria Realms - режим NAT traversal: rendezvous service помогает сторонам
найти друг друга, затем используется UDP hole punching и QUIC соединение
идет напрямую. Realm token не заменяет пароль Hysteria-сервера.

## TCP как Stream

Для одного target TCP соединения можно представить:

```csharp
Stream stream = hysteriaConnection.OpenTcpStream("mc.example.com", 25565);
```

Но под капотом это:

- shared QUIC connection;
- bidirectional QUIC stream;
- Hysteria2 request framing;
- flow control;
- close/reset mapping;
- congestion control.

В .NET есть `System.Net.Quic`, но он требует платформенной поддержки MsQuic и
не является такой же простой зависимостью, как `Socket`/`SslStream`.
`QuicStream` в .NET наследует `Stream`, поэтому TCP path можно естественно
адаптировать под текущую модель QuickProxyNet.

## Производительность

Hysteria2 рассчитан на плохие/lossy сети и активно использует QUIC congestion
control. Для Minecraft это может быть полезно на нестабильных маршрутах, но:

- добавляется UDP/QUIC stack;
- TCP-over-QUIC может вести себя иначе, чем прямой TCP;
- один QUIC connection может мультиплексировать много target streams.

## Оценка для QuickProxyNet

| Задача | Сложность |
| --- | --- |
| Парсить `hy2://`/`hysteria2://` URI | Низкая |
| Открыть QUIC connection | Средняя/высокая |
| Реализовать Hysteria2 auth/framing | Высокая |
| Вернуть один TCP `Stream` | Возможно через wrapper |
| UDP relay | Нужен отдельный datagram API |

Это не стоит смешивать с базовым `ProxyClient` без проектирования lifecycle:
одно QUIC соединение может обслуживать много потоков, поэтому модель
"один ConnectAsync - один socket" не оптимальна.

## Источники

- Hysteria2 protocol specification: https://v2.hysteria.network/docs/developers/Protocol/
- Hysteria2 full client config: https://v2.hysteria.network/docs/advanced/Full-Client-Config/
- Hysteria2 about HTTP/3: https://v2.hysteria.network/docs/misc/About-HTTP3/
- Hysteria repository: https://github.com/apernet/hysteria
- QUIC RFC 9000: https://datatracker.ietf.org/doc/rfc9000/
- .NET QUIC overview: https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview
- `QuicStream`: https://learn.microsoft.com/en-us/dotnet/api/system.net.quic.quicstream
