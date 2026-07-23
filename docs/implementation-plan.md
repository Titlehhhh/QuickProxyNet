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
- multi-target `net8.0`/`net9.0`/`net10.0`.

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
| VLESS REALITY / XTLS-vision | TCP | uTLS fingerprint | нет | Очень высокий | отдельно |

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

**Фаза 4 — QUIC (Hysteria2/TUIC):** отдельный пакет `QuickProxyNet.Quic` на
`System.Net.Quic`, lifecycle одного QUIC-соединения на несколько стримов.

**Отдельно:** VLESS REALITY / XTLS-vision (uTLS fingerprint — не покрывается
стандартным `SslStream`).

## 6. Границы фазы 1 (honest scope)

Поддерживается: `vless://` с `security=none` и `security=tls`, транспорт
`tcp`/`raw`, команда TCP, адреса IPv4/IPv6/domain, `sni`/`alpn`.
Явно НЕ поддерживается (кидаем `NotSupportedException`): `reality`, непустой
`flow`, транспорты `ws`/`grpc`/`xhttp`/`httpupgrade`, команды UDP/Mux.
