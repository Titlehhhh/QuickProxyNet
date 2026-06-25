# TUIC

TUIC - proxy-протокол поверх QUIC. Он ближе к Hysteria2 по транспортной модели:
нижний слой UDP+QUIC+TLS 1.3, а пользовательские TCP соединения отображаются
на QUIC streams.

Актуальная upstream-спецификация описывает protocol version `0x05`.

## Стек

```text
UDP socket -> QUIC + TLS 1.3 -> TUIC commands -> QUIC stream -> target TCP stream
```

Для QuickProxyNet это не "написать CONNECT header в TCP socket". Нужен QUIC
client и stream-wrapper.

## URI

Распространенная форма:

```text
tuic://<uuid>:<password>@<server>:<port>?sni=example.com&congestion_control=bbr#name
```

Частые параметры:

| Параметр | Значение |
| --- | --- |
| `uuid` | user UUID |
| `password` | raw password |
| `sni` | TLS SNI |
| `congestion_control` | `cubic`, `new_reno`, `bbr` |
| `udp_relay_mode` | режим UDP relay |
| `alpn` | QUIC/TLS ALPN |
| `allowInsecure` | политика сертификата |
| `disable_sni` | отключение SNI в некоторых клиентах |

## Authentication

TUIC specification описывает команду Authenticate:

```text
+------+-------+
| UUID | TOKEN |
+------+-------+
| 16   | 32    |
+------+-------+
```

`TOKEN` - 256-bit token, полученный через TLS Keying Material Exporter текущей
TLS-сессии. Label - UUID клиента, context - raw password.

Это важное отличие от простых password header-ов: токен связан с текущей QUIC
TLS-сессией.

## Byte-level команды

Все числовые поля в specification идут big-endian, если не сказано иначе.

Общая форма команды:

```text
+-----+------+----------+
| VER | TYPE | OPT      |
+-----+------+----------+
|  1  |  1   | variable |
+-----+------+----------+
```

`VER` для актуальной версии: `0x05`.

Типы команд:

```text
00 = Authenticate
01 = Connect
02 = Packet
03 = Dissociate
04 = Heartbeat
```

`Authenticate`:

```text
+------+-------+
| UUID | TOKEN |
+------+-------+
| 16   | 32    |
+------+-------+
```

`Connect` содержит целевой адрес:

```text
+------+
| ADDR |
+------+
```

`Packet` для UDP relay:

```text
+----------+--------+------------+---------+------+--------+---------+
| ASSOC_ID | PKT_ID | FRAG_TOTAL | FRAG_ID | SIZE | ADDR   | PAYLOAD |
+----------+--------+------------+---------+------+--------+---------+
| 2        | 2      | 1          | 1       | 2    | var    | var     |
+----------+--------+------------+---------+------+--------+---------+
```

`Dissociate`:

```text
+----------+
| ASSOC_ID |
+----------+
| 2        |
+----------+
```

`Heartbeat` не несет полезной нагрузки.

Адрес:

```text
+------+----------+------+
| TYPE | ADDR     | PORT |
+------+----------+------+
| 1    | variable | 2    |
+------+----------+------+
```

Типы адреса:

```text
FF = None
00 = FQDN
01 = IPv4
02 = IPv6
```

`None` используется в UDP packet flow, например не для первого фрагмента.

## Protocol flow

Типовой flow:

1. Клиент устанавливает QUIC connection.
2. Клиент открывает stream/control path и выполняет Authenticate.
3. Для TCP target клиент открывает QUIC bidirectional stream.
4. Клиент отправляет command/request с target address.
5. Дальше байты target TCP идут внутри этого QUIC stream.

TUIC также поддерживает UDP relay и 0-RTT-related оптимизации в реализациях.

Для `Connect` specification не задает отдельный success response: клиент
открывает bidirectional QUIC stream, отправляет command и может сразу писать
payload. Ошибки обычно выражаются закрытием/reset QUIC stream или connection,
а не отдельным стандартизированным response frame.

## Шифрование

TUIC всегда использует QUIC, а QUIC включает TLS 1.3. Практического режима
"без шифрования" нет. Можно менять certificate validation и ALPN/SNI, но не
убирать QUIC crypto.

## Stream-модель

Для TCP:

```text
TUIC connection -> open bidirectional QUIC stream -> send CONNECT command -> return Stream wrapper
```

Возможная C# форма:

```csharp
public sealed class TuicStream : Stream
{
    // wraps QuicStream and handles TUIC close/reset semantics
}
```

Но `ConnectAsync` должен где-то хранить/reuse QUIC connection, иначе каждый
target TCP stream будет платить дорогой QUIC handshake.

## Производительность

TUIC интересен для высокой пропускной способности и потерь сети за счет QUIC
congestion control. Но для QuickProxyNet появляются новые вопросы:

- какая QUIC библиотека;
- как настраивать BBR/CUBIC/new_reno;
- как маппить QUIC reset/close на `Stream`;
- как поддерживать UDP relay без `Stream`;
- как переиспользовать QUIC connection между несколькими `ConnectAsync`.

sing-box документирует `congestion_control`: `cubic`, `new_reno`, `bbr`
(`cubic` по умолчанию). Для UDP relay там же есть режимы `native` и `quic`;
`udp_over_stream` является расширением sing-box, а не базовой TUIC-спеки.

## Оценка реализации

| Часть | Сложность |
| --- | --- |
| URI parser | Низкая |
| QUIC/TLS connection | Средняя/высокая |
| TLS exporter token | Средняя |
| TUIC commands/framing | Средняя |
| TCP `Stream` wrapper | Средняя |
| UDP relay | Отдельный API |

TUIC реалистичнее делать отдельным optional package, чем добавлять прямо в
минимальное BCL-only ядро.

## Источники

- TUIC protocol spec: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md
- TUIC repository: https://github.com/tuic-protocol/tuic
- sing-box TUIC outbound: https://sing-box.sagernet.org/configuration/outbound/tuic/
- sing-box TUIC inbound: https://sing-box.sagernet.org/configuration/inbound/tuic/
- QUIC RFC 9000: https://datatracker.ietf.org/doc/rfc9000/
- QUIC datagrams RFC 9221: https://datatracker.ietf.org/doc/html/rfc9221
