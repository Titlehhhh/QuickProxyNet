# hy2

`hy2://` - распространенный короткий scheme для Hysteria2 share links. Это не
отдельный протокол от Hysteria2; в документации QuickProxyNet его стоит считать
алиасом `hysteria2://`.

Подробное описание wire-level поведения, QUIC/TLS стека, auth, obfuscation и
Stream-модели см. в [hysteria2.md](hysteria2.md).

## URI

Пример:

```text
hy2://<password>@server.example.com:443?sni=example.com&obfs=salamander&obfs-password=secret#name
```

Нормализация для будущей реализации:

```text
scheme: hy2 -> protocol: Hysteria2
password: userinfo
server: host
server_port: port
sni/peer: TLS server name
obfs + obfs-password: optional obfuscation
```

## Практический вывод

Если QuickProxyNet когда-либо добавит Hysteria2, поддержка `hy2://` должна быть
частью того же клиента:

```text
ProxyType.Hysteria2
schemes: hysteria2, hy2
```

Для `ConnectAsync(...)->Stream` это все равно QUIC stream wrapper, а не
`NetworkStream`.

## Источники

- Hysteria2 docs: https://v2.hysteria.network/docs/
- Hysteria2 protocol specification: https://v2.hysteria.network/docs/developers/Protocol/
- sing-box Hysteria2 notes: https://sing-box.sagernet.org/manual/proxy-protocol/hysteria2/
