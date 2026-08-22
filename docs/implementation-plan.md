# План реализации VPN-протоколов в QuickProxyNet

Документ разбивает задачу на подзадачи, фиксирует дизайн и перф-приоритеты.
Исследовательские wire-заметки — в соседних файлах (`vless.md`, `trojan.md`, …).
Здесь — как это лечь в код, в каком порядке, и что и как бенчить.

## 0. Цель и принципы

Сохранить главную модель библиотеки: `ConnectAsync(...) -> Stream`. Новый
протокол — это ещё один способ довести байты до target host:port, поверх
уже существующего socket/SslStream. Никакого нового публичного контракта,
кроме дополнительных `ProxyType` и клиентов.

Инварианты из `AGENTS.md`, которые держим на горячем пути:
- `Span<T>`/`Memory<T>`/`stackalloc`/`ArrayPool<byte>`, аренда возвращается в `finally`;
- `BinaryPrimitives` для network byte order;
- без LINQ в hot path;
- helpers `internal`, публичное API — с XML-докой;
- multi-target `net8.0`/`net9.0`/`net10.0`/`net11.0`.

Корпус для проверки корректности — реальные share-ссылки из PypsCFG
(`vless://`, `vmess://`, `trojan://`, `hy2://`, `tuic://`, ~17.7k конфигов).
Используем как fixtures парсинга (не для сетевых тестов в CI).

## 1. Классификация по сложности

| Протокол | Транспорт | Крипто сверх BCL | QUIC | Класс | Порядок |
| --- | --- | --- | --- | --- | --- |
| VLESS `none`/`tls` | TCP / TLS | нет | нет | Низкий | **1** |
| Trojan | TLS (обяз.) | SHA-224 (нет в BCL) | нет | Средний | **2** |
| VMess (AEAD) | TCP / TLS | AEAD KDF + body framing | нет | Высокий | 3 |
| Hysteria2 / hy2 | QUIC/UDP | — (TLS 1.3 в QUIC) | да | Высокий | 4 |
| TUIC | QUIC/UDP | TLS exporter token | да | Высокий | 4 |
| VLESS REALITY / XTLS-vision | TCP | собственный TLS 1.3 (X25519, HKDF, record layer) | нет | Очень высокий | **сделано** (§8) |

Обоснование порядка: VLESS `none`/`tls` не тянет новых зависимостей и
прогоняет всю новую архитектуру (config-парсер, UUID big-endian, address
writer, header build, response read). Trojan переиспользует address writer и
TLS-слой, добавляя только SHA-224. VMess — отдельная state-machine со
stream-wrapper. QUIC-протоколы ломают модель «один ConnectAsync — один socket»
(одно QUIC-соединение мультиплексирует стримы) и выносятся в опциональный
пакет `QuickProxyNet.Quic`.

## 2. Архитектура

### 2.1 Где расходятся текущая модель и VPN-протоколы

Сейчас `ProxyConnector`/`Proxy` диспатчат по `Uri.Scheme` и берут из URI
только `UserInfo` (creds). Для HTTP/SOCKS этого хватает. VPN-протоколам нужен
богатый конфиг: uuid/password, `security`, `sni`, `alpn`, `flow`, `pbk`,
`sid`, `fp`, `type`, `path`, `host`. VMess вообще кодируется как base64(JSON).

Вывод: нужен **слой типизированного конфига** — парсер share-ссылки →
options-объект. Клиент держит options (как `HttpsProxyClient` держит TLS-опции).

### 2.2 Новые типы

```
QuickProxyNet/
  ProxyType.cs                 + Vless, Vmess, Trojan, Hysteria2, Tuic
  Clients/
    VlessClient.cs             : ProxyClient   (none/tls)
    TrojanClient.cs            : ProxyClient    (фаза 2)
  Configs/
    VlessOptions.cs            typed config (uuid, security, sni, alpn, flow, transport…)
    VlessShareLink.cs          static parser: string/Uri -> VlessOptions
    TrojanOptions.cs           (фаза 2)
  Internal/
    ProxyAddress.cs            address writer: atyp+addr / port, IPv4/IPv6/domain
    UuidCodec.cs               canonical UUID string -> 16 bytes big-endian, zero-alloc
    VlessHelper.cs             request header build + response header read
    Sha224.cs                  (фаза 2) внутренний SHA-224 для Trojan
```

Публичная поверхность фазы 1: `ProxyType.Vless`, `VlessClient`,
`VlessOptions`, `VlessShareLink.Parse(...)`, регистрация схемы `vless` в
`ProxyClientFactory`.

### 2.3 Поток VLESS

```
none:  socket -> NetworkStream -> [write VLESS req] -> [read VLESS resp] -> return stream
tls:   socket -> SslStream.AuthAsClient(sni,alpn) -> [write req] -> [read resp] -> return SslStream
```

Response header (`ver(1) + addonsLen(1) + addons`) читаем ДО возврата stream,
иначе пользователь увидит `00 00` перед байтами target. Если сервер прислал
больше (overread — часть ответа target), оборачиваем в `PrefixedStream`
(уже есть в `HttpHelper`; выносим в `Internal/PrefixedStream.cs` для повторного
использования).

### 2.4 Wire-формат request (базовый TCP, addons=0)

```
ver(0x00) | uuid(16 BE) | addonsLen(0x00) | cmd(0x01 TCP) | port(2 BE) | atyp(1) | addr(var)
```

Внимание к порядку: у VLESS **port идёт перед address** (в отличие от SOCKS5).
Address type: `01`+IPv4(4), `02`+len(1)+domain, `03`+IPv6(16).

## 3. Перф-план (что и как бенчим)

«Перф самое главное» → каждый перф-чувствительный юнит получает бенч в
`QuickProxyNet.Benchmarks` (BenchmarkDotNet, `[MemoryDiagnoser]`), сравнение
наивной и оптимизированной реализации, как уже сделано в
`FindEndOfHeadersBenchmark`.

| Юнит | Наивно | Оптимизировано | Метрика |
| --- | --- | --- | --- |
| UUID `string`→16B | `Guid.Parse().ToByteArray()` (mixed-endian **баг** + alloc) | `Guid.TryWriteBytes(span, bigEndian:true)` / ручной hex | ns + B/op |
| Request header build | `List<byte>`/`MemoryStream` | `stackalloc`/pooled + `BinaryPrimitives` | ns + B/op (цель 0 alloc) |
| Share-link parse | `Uri` + `HttpUtility.ParseQueryString` | span-парсер query, без `Dictionary` для hot-полей | ns + B/op на 60k конфигов |
| Address write | — | общий `ProxyAddress` writer | 0 alloc |

Каждый бенч запускаем (`dotnet run -c Release --project QuickProxyNet.Benchmarks`)
и фиксируем числа в PR. Корректность UUID big-endian и address writer —
обязательно юнит-тестами (это самые частые места ошибок).

### 3.1 Замеры фазы 1 (`VlessBenchmark`)

BenchmarkDotNet 0.15.8, .NET 10, Xeon E5-2697 v4, ShortRun/InProcessNoEmit
(конвенция репо). Надёжна колонка аллокаций; ns при ShortRun шумят (маржа до
84%), поэтому по времени делаем только грубые выводы.

| Юнит | Baseline | Оптимизировано | Alloc | Вывод |
| --- | --- | --- | --- | --- |
| Header build | `MemoryStream` 296 B | span/pooled **0 B** | −100% | zero-alloc, время в пределах шума |
| Share-link parse | `Uri`+`Dictionary` 1848 B | span-scan **1088 B** | −41% | пол — сам `new Uri`; словарь/строки значений убраны |
| UUID encode | `Guid.Parse().ToByteArray()` (mixed-endian **баг**) | `Guid.TryParse`+`TryWriteBytes(bigEndian)` | ≈0 | ручной hex не быстрее → оставляем codec на `Guid` |

Итог: header — 0 alloc (цель достигнута). Parse можно ещё ускорить полностью
ручным парсером без `Uri`, но `Uri` даёт робастность на «грязном» корпусе —
пока оставляем, отмечено как возможная оптимизация фазы 2.

## 4. API-эксперименты

Открытые вопросы дизайна публичного API (проверяем на первой фазе):

1. **Конструирование клиента.** `new VlessClient(host, port, VlessOptions)` vs
   `VlessClient.FromShareLink("vless://…")`. Гипотеза: оба — фабрику через
   share-link, ctor через options.
2. **Статический путь.** Расширить ли `Proxy.ConnectAsync(Uri,…)` на `vless`?
   Проблема: текущий путь тянет из URI только creds. Вариант — перегрузка
   `Proxy.ConnectAsync(VlessOptions, host, port)` без диспатча по строке.
3. **TLS-опции.** Переиспользовать паттерн `HttpsProxyClient`
   (`ServerCertificateValidationCallback`, `SslProtocols`, ALPN) — вынести в
   общий `TlsProxyOptions`, чтобы Trojan/VLESS-tls его делили.
4. **Куда парсить `flow`/REALITY.** В options положить поля, но в фазе 1 при
   `security=reality` или непустом `flow` кидать `NotSupportedException` с
   явным сообщением — чтобы контракт был честным.

Решения фиксируем здесь по мере проверки бенчами/тестами.

## 5. Подзадачи (роадмап)

**Фаза 1 — VLESS none/tls (текущая):**
- [ ] `ProxyType` + `Vless` и заглушки остальных
- [ ] `Internal/UuidCodec` + тесты + бенч
- [ ] `Internal/ProxyAddress` writer + тесты
- [ ] `Configs/VlessOptions` + `VlessShareLink.Parse` + тесты на корпусе
- [ ] `Internal/VlessHelper` (build request / read response) + тесты через `FakeProxyStream`
- [ ] `Clients/VlessClient` (none + tls)
- [ ] wiring: `ProxyConnector` (для none), `ProxyClientFactory` (схема `vless`)
- [ ] бенчи: UUID, header build, share-link parse — прогнать, записать числа

**Фаза 2 — Trojan:** `Internal/Sha224` + тесты (вектора NIST) + бенч,
`TrojanOptions`/parser, `TrojanClient` (TLS обяз.), общий `ProxyAddress`.

**Фаза 3 — VMess AEAD:** KDF/auth, body framing, `VmessStream` wrapper,
time-sync, `security` (`aes-128-gcm`/`chacha20-poly1305`), `alterId=0`.

Зафиксированные API-решения фазы 3 (утверждены 2026-07-23):

1. **Share-link / JSON.** `VmessShareLink.Parse` разбирает классический
   `vmess://base64(JSON)`. Декодируем base64 → парсим `System.Text.Json`
   `Utf8JsonReader` (в составе фреймворка на net8/9/10, без внешних
   зависимостей; zero-alloc-ридер по UTF-8). URI-style vmess-ссылки и не-base64
   вход → `FormatException` с явным сообщением (расширим позже).
2. **Body security (`scy`).** Поддерживаем `aes-128-gcm`, `chacha20-poly1305`
   и `auto` (→ `aes-128-gcm` при аппаратном AES, иначе `chacha20-poly1305`,
   как v2ray). `none`/`zero`/`aes-128-cfb`/legacy → `NotSupportedException`.
3. **Детерминизм тестов.** Заголовок VMess вшивает UTC-время + random, поэтому
   вводим **internal seam** для времени (`TimeProvider`, как в базовом
   `ProxyClient`) и для random/nonce. Helper даёт детерминированные wire-байты
   в юнит-тестах и сверяется с независимым эталоном. Публичное API seam не
   расширяет — только internal.
4. **Транспорт/TLS/legacy.** Поддерживаем `net=tcp` c `security` none/tls
   (`SslStream` снаружи + `VmessStream` внутри — паттерн `VlessClient`),
   `alterId=0` (VMessAEAD). `ws`/`grpc`/`h2`/`httpupgrade`/`reality`,
   `alterId>0` (legacy MD5 auth), UDP/Mux → `NotSupportedException` с явным
   сообщением (честный gating до записи байтов).

**Фаза 4 — транспорты ws/httpupgrade (сделано 2026-08-14):** общий транспортный
слой `Internal/Transports/` для всех трёх протоколов. Порядок слоёв:
`socket → optional SslStream → transport → protocol header`. Фрейминг RFC 6455
берём из BCL (`WebSocket.CreateFromStream`), а не пишем руками. Подробности и
грабли — в `AGENTS.md`, пункты 13–14.

**Фаза 5 — QUIC (Hysteria2/TUIC):** отдельный пакет `QuickProxyNet.Quic` на
`System.Net.Quic`, lifecycle одного QUIC-соединения на несколько стримов.
**Депризорити­зировано** — см. §7.

**REALITY / XTLS-vision:** сделано, в ядре, управляемым TLS 1.3 — см. §8. Не сделан
браузерный отпечаток ClientHello; это следующий шаг по REALITY
(`reality-fingerprint-plan.md`).

## 7. Что делать дальше: решение по цифрам (2026-08-14)

Порядок фаз в этом документе был выбран по «сложности реализации», а не по тому,
сколько реальных конфигов он открывает. Прогон `tools/CorpusCheck` по 21 403
реальным ссылкам это исправил. Ключевая метрика — **сколько ссылок реально может
подключиться**, а не сколько распарсилось: парсинг успешен и для REALITY, и для
grpc, которые падают уже на `ConnectAsync`.

Было (только `tcp`/`raw`):

| | коннектится | доля |
| --- | ---: | ---: |
| vless | 663 / 17 367 | 3.8% |
| trojan | 871 / 1 285 | 67.8% |
| vmess | 1 320 / 2 279 | 57.9% |
| **всего** | **2 854 / 21 403** | **13.3%** |

Стало (ws + httpupgrade + разбор `security=` у vmess):

| | коннектится | доля |
| --- | ---: | ---: |
| vless | 6 162 / 17 367 | 35.5% |
| trojan | 1 279 / 1 285 | 99.5% |
| vmess | 2 277 / 2 279 | 99.9% |
| **всего** | **9 718 / 21 403** | **45.4%** |

Что осталось блокировать и чего это стоит:

| Блокер | Ссылок | % корпуса | Цена |
| --- | ---: | ---: | --- |
| REALITY | 10 653 | 49.8% | uTLS ClientHello — `SslStream` не умеет |
| gRPC | 991 | 4.6% | HTTP/2-фрейминг |
| xhttp | 789 | 3.7% | нестандартный, только Xray |
| Hysteria2/TUIC | 472 | 2.2% | QUIC, ломает «один ConnectAsync — один сокет» |

**Вывод: QUIC — худшая из оставшихся инвестиций.** Самая тяжёлая архитектурная
работа в роадмапе ради 2.2% охвата. Он стоял «фазой 4» только потому, что шёл
следующим по документу — это не обоснование. Следующий по отношению
охват/стоимость — gRPC. REALITY — половина корпуса, и на момент этого замера
вывод был: отдельный проект, а не фича. Он и оказался отдельным проектом — см. §8.

Метод, а не только результат: считать надо то, что может провалиться. «Процент
распарсенного» рос до 99.9% ровно тогда, когда 96% ссылок не могли подключиться —
метрика, которая не умеет падать, ничего не измеряет.

## 6. Границы фазы 1 (honest scope)

Историческая справка: границы, с которых начиналась фаза 1.

Поддерживалось: `vless://` с `security=none` и `security=tls`, транспорт
`tcp`/`raw`, команда TCP, адреса IPv4/IPv6/domain, `sni`/`alpn`.
Явно НЕ поддерживалось (кидали `NotSupportedException`): `reality`, непустой
`flow`, транспорты `ws`/`grpc`/`xhttp`/`httpupgrade`, команды UDP/Mux.

С тех пор закрыты `ws` и `httpupgrade` (фаза 4), а `reality` и
`flow=xtls-rprx-vision` — в самом ядре, через `VlessClient` (§8). Остаются `grpc`,
`xhttp` и UDP/Mux.


## 8. REALITY: что вышло (2026-08-20, уточнено 2026-08-22)

Прогноз из §7 — «отдельный проект, а не фича» — подтвердился по объёму работы, но
не по форме результата. А вывод «пока нет способа подделать uTLS-отпечаток, честный
`NotSupportedException` — единственное правильное поведение» оказался верным лишь
наполовину, и разбираться стоило именно с этой половиной.

Верно то, что `SslStream` не может говорить на REALITY: он отдаёт рукопожатие
Schannel или OpenSSL и не даёт написать ClientHello. Неверно то, что из этого
следует отказ как единственный выход: рукопожатие можно написать самим. Так и
сделано — X25519, аутентификация REALITY, клиент TLS 1.3 и record layer на C#, в
`QuickProxyNet/Internal/Reality/`, плюс `VisionStream` для `xtls-rprx-vision`.
Проходит настоящее рукопожатие с Xray-core и проносит VLESS без внешнего
процесса; проверено и на loopback-Xray, и на живых узлах из корпуса.

По дороге существовал второй вариант — пакет `QuickProxyNet.Reality`, который
поднимал дочерний Xray за фасадом `RealityProxy`. Он был удалён, не выходя в NuGet:
когда управляемый путь доказал себя на реальных серверах, вторая реализация ради
`grpc`/`xhttp` и чужого отпечатка перестала стоить своей поддержки.

### Что оказалось дешевле, чем выглядело

Криптография самого REALITY — крошечная: X25519, HKDF-SHA256, AES-256-GCM,
HMAC-SHA512. Всё, кроме X25519, есть в платформе. Сложность целиком в TLS 1.3 с
побайтовым контролем ClientHello, а он — не общий стек: одна форма рукопожатия,
без PSK, без возобновления, без HRR, без клиентских сертификатов. Всё за
пределами этой формы отвергается по имени.

Ключевая деталь, снявшая неопределённость: приватный ключ, которым REALITY
аутентифицируется, — **тот же самый**, что уходит в `key_share`. Сервер достаёт
публичную половину прямо из `clientHello.keyShares`.

### Что оказалось дороже

Отпечаток. Наш ClientHello сейчас около 200 байт, у Chrome 133 — примерно 1 700.
И это не косметика: клиент, который *работает*, но не совпадает ни с одним живым
браузером, попадает в более узкую и заметную корзину, чем если бы REALITY не
поддерживался вовсе. Пока этот разрыв не закрыт, управляемая реализация — это
реализация протокола, а не средство обхода блокировок, и в документации типа так
и написано.

Байтовый разбор и поэтапный план — в [reality-fingerprint-plan.md](reality-fingerprint-plan.md).
Три вещи оттуда меняют подход: JA3 непригоден как критерий (Chrome перемешивает
расширения на каждое соединение), `MLKem` из .NET 10 привязан к ОС и потому
непригоден как основа, а ML-KEM-768 придётся реализовать управляемо на все TFM.

### Публичная форма — решено

Внутрь `VlessClient`: `security=reality` в `VlessOptions`, или просто ссылка в
`ProxyClientFactory.Create(string)` / `Proxy.ConnectAsync(string, …)`. Отдельный
`RealityClient` и третий пакет отвергнуты — у пользователя в руках `vless://`-ссылка,
и она сама говорит, какой режим безопасности нужен. Наружу из `Internal/Reality/`
торчит только `RealityHandshakeException : ProxyProtocolException`.
