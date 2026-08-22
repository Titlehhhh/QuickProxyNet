# VPN-подобные proxy-протоколы

Эта папка фиксирует исследование протоколов, которые потенциально можно
добавить в QuickProxyNet с сохранением главной модели библиотеки:
`ConnectAsync(...) -> Stream`.

Файлы:

Wire-level заметки по протоколам:

- [VLESS](vless.md) — реализован
- [VMess](vmess.md), [VMessAEAD request](vmess-aead-request.md), [VMessAEAD body](vmess-aead-body.md) — реализован
- [Trojan](trojan.md) — реализован
- [Hysteria2](hysteria2.md), [hy2](hy2.md), [TUIC](tuic.md) — **не реализованы**
- [Анализ QUIC-протоколов](quic-protocols-analysis.md) — почему Hysteria2 и TUIC
  не ложатся на модель «один `ConnectAsync` — один сокет»

Планы и результаты:

- [План реализации](implementation-plan.md) — что сделано, что дальше, и замеры
  покрытия по реальному корпусу ссылок
- [Достоверность отпечатка REALITY](reality-fingerprint-plan.md) — побайтовый
  разбор ClientHello Chrome 133 и план работ; относится к `QuickProxyNet/Internal/Reality/`

Наличие документа не означает, что протокол поддержан: там, где поддержки нет,
это сказано явно.
