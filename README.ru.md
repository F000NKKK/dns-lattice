# DNS Lattice

**Языки**

🇺🇸 [English](README.md) | 🇷🇺 **Русский**

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

**DNS Lattice** — программируемый встраиваемый DNS resolver/server engine для
Rust. Он предоставляет split DNS, кэширование, Fake IP, динамический выбор
маршрута, структурированную observability и UDP/TCP/DoT/DoH/DoQ-транспорты
через единый типизированный library API.

По смыслу это DNS-аналог встраиваемого HTTP server core: host-приложение
владеет процессом и конфигурацией, а DNS Lattice отвечает за DNS protocol
handling, resolution, serving, routing, cache behavior и transport execution.

> **Статус:** стадии **0.0–0.6 завершены**. Стадия 0.6 определяет
> hardening-линейку `0.6.x`; реализационных задач в ней больше нет. Штатный
> release-скрипт репозитория выполняет механический bump Cargo-версий до
> `0.6.0` и публикацию. Следующий этап разработки — **1.0**: аудит и заморозка
> публичного API перед первым стабильным релизом. До `1.0.0` API остаётся
> pre-1.0 и может меняться.

## Зачем нужен DNS Lattice

Приложениям с нестандартным DNS обычно приходится вручную собирать несколько
разных задач: DNS wire parsing, split-DNS policy, cache semantics, transport
fallback, encrypted DNS, Fake IP state, server listeners и
application-specific routing. DNS Lattice разделяет эти ответственности, но
оставляет их совместимыми внутри одного engine.

Resolver pipeline явный:

```text
DNS query
  → terminal Fake IP handling, если выбрано policy
  → static split-DNS candidate
  → optional RouteHook
  → validate effective upstream group
  → route-scoped cache
  → ordered upstream failover
  → answer
```

Inbound listeners используют тот же resolver pipeline:

```text
Client → Server → Resolver → Cache/Policy/Hook/Fake IP → UpstreamBackend → Resolver → Server → Client
```

## Workspace

DNS Lattice публикуется как три крейта:

| Крейт | Ответственность |
|---|---|
| `dns-lattice` | Public facade + runtime implementation resolver/server |
| `dns-lattice-model` | DNS message model, names, matcher, split-DNS policy |
| `dns-lattice-core` | Общая типизированная граница `Error` / `Result` |

Большинству приложений достаточно зависимости только от `dns-lattice`.

## Установка

Baseline UDP/TCP не требует TLS/HTTP/QUIC features:

```toml
[dependencies]
dns-lattice = "0.6"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Encrypted transports включаются только при необходимости:

```toml
[dependencies]
dns-lattice = { version = "0.6", features = ["dot", "doh", "doq"] }
```

Cargo features независимы и выключены по умолчанию:

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS по HTTP/1.1, HTTP/2 и HTTP/3;
- `doq` — DNS-over-QUIC.

## Быстрый старт: UDP resolver + server

Используйте канонические domain modules; facade намеренно не предоставляет
плоские root aliases.

```rust,no_run
use std::{net::SocketAddr, sync::Arc, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    server::ServerBuilder,
    upstream::{UdpBackend, UdpBackendConfig},
};

# async fn run() -> Result<()> {
let group = UpstreamGroupId::new("default");
let policy = SplitDnsPolicy::builder()
    .default_group(group.clone())
    .build();

let resolver = Arc::new(
    Resolver::builder(policy)
        .backend(
            group,
            UdpBackend::new(UdpBackendConfig {
                server: "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                timeout: Duration::from_secs(5),
                bind_addr: None,
            }),
        )
        .build(),
);

let server = ServerBuilder::new(resolver)
    .udp_addr("127.0.0.1:5353".parse().unwrap())
    .bind()
    .await?;

server.serve().await?;
# Ok(())
# }
```

`Resolver` владеет routing/cache/failover. `Server` владеет inbound listening и
framing. Реализации `UpstreamBackend` владеют outbound transport execution.

## Публичные модули

Канонические public paths:

| Модуль | Назначение |
|---|---|
| `dns_lattice::core` | Общие типизированные errors/results |
| `dns_lattice::model` | DNS messages, records, names, matchers, policies |
| `dns_lattice::engine` | `Resolver` / `ResolverBuilder` |
| `dns_lattice::upstream` | Outbound backend trait и transports |
| `dns_lattice::server` | Inbound listeners и lifecycle |
| `dns_lattice::fakeip` | Fake IP pool, policy, TTL, snapshots |
| `dns_lattice::hooks` | Dynamic route-selection hook |
| `dns_lattice::observability` | Structured resolver events/sink |

## Split DNS и matching

`dns-lattice-model` предоставляет детерминированный exact/suffix/wildcard
matching и `SplitDnsPolicy`. Resolver сначала получает статического кандидата
upstream group из этой policy.

Model/matcher слой не выполняет network I/O и не зависит от ОС. Hardening
стадии 0.6 добавляет детерминированное property-style покрытие matcher
precedence, message parsing и DNS name compression bounds.

## Семантика кэша

Resolver имеет in-memory answer cache с учётом TTL, включая negative caching.
Для обычных запросов cache identity включает **effective upstream group**.
Это критично при route hook: одинаковые DNS questions, отправленные в разные
маршруты, не могут разделить один answer.

Terminal Fake IP ответы обходят обычный answer cache; их lifetime принадлежит
самому Fake IP mapping.

## Dynamic route hooks

`ResolverBuilder::route_hook` устанавливает один caller-owned `RouteHook` для
обычных запросов. Hook получает первый DNS question и tentative static group:

- `Use(group)` выбирает существующую непустую upstream group;
- `Abstain` сохраняет static candidate.

Ошибка hook, неизвестная group или empty group завершают resolution ошибкой без
молчаливого fallback на другой static route. Hook используется только для
selection: DNS Lattice не передаёт ему resolver/backend handles, cache
authority, client transport metadata или OS/network side-effect capability.

Реализация hook сама владеет timeout, retry, cancellation cleanup и внешними
вызовами. Re-entry в тот же resolver из его hook запрещён.

### Пример hook

```rust,no_run
use async_trait::async_trait;
use dns_lattice::{
    hooks::{RouteDecision, RouteHook, RouteHookError, RouteRequest},
    model::UpstreamGroupId,
};

struct PreferFiltered;

#[async_trait]
impl RouteHook for PreferFiltered {
    async fn select(
        &self,
        request: RouteRequest<'_>,
    ) -> std::result::Result<RouteDecision, RouteHookError> {
        let _question = request.question();
        let _static_candidate = request.static_group();
        Ok(RouteDecision::Use(UpstreamGroupId::new("filtered")))
    }
}
```

## Fake IP

`fakeip::FakeIpPool` предоставляет детерминированное concurrent synthetic
IPv4/IPv6 state:

- inclusive IPv4 и/или IPv6 ranges;
- детерминированное domain → address allocation/reuse;
- address → active-domain reverse lookup;
- per-family LRU eviction при заполнении диапазона;
- обязательный whole-second TTL и expiry;
- caller-owned process-local in-memory snapshot/restore.

`ResolverBuilder::fake_ip` явно включает local synthesis через `FakeIpPolicy`:

- matching IN A/AAAA → local synthetic answer;
- выбранное, но отключённое address family → local NODATA;
- canonical in-range IN PTR → active name или NXDOMAIN.

Fake IP answers terminal: они выполняются до static routing, hooks, ordinary
cache и upstream calls. Их DNS TTL никогда не превышает remaining lifetime
mapping.

DNS Lattice намеренно **не** определяет durable Fake IP persistence и формат
сериализации snapshots.

## Observability

`ResolverBuilder::observability_sink` принимает optional
`observability::ObservabilitySink`. Resolver выдаёт immutable bounded events
для ключевых переходов pipeline, включая:

- query receipt;
- terminal Fake IP handling;
- static/effective route и hook outcomes;
- cache hit/miss;
- upstream attempts/outcomes;
- timeout и terminal error paths.

Sink non-authoritative. Он не может менять routing, answers, cache state или
retries; не получает resolver/backend handles; resolver locks освобождаются до
callbacks; panic callback изолирован от корректности resolver. DNS Lattice не
требует конкретный logging/tracing framework и не владеет background telemetry
queue.

## Upstream transports

Resolver пробует backends внутри upstream group в порядке регистрации.
Timeout/transport/TLS failures могут переключить выполнение на следующий
backend. Если все backends завершились ошибкой, возвращается последняя ошибка,
а успешный answer не кэшируется.

| Transport | Feature | Детали реализации |
|---|---|---|
| UDP | default | Fallback на TCP при `TC=1` |
| TCP | default | RFC 1035 length-prefixed framing |
| DoT | `dot` | `rustls` / `tokio-rustls` |
| DoH HTTP/1.1 + HTTP/2 | `doh` | `hyper` / `hyper-rustls` |
| DoH HTTP/3 | `doh` | `h3` / `quinn`, ALPN `h3` |
| DoQ | `doq` | `quinn`, ALPN `doq` |

DoQ и HTTP/3 используют QUIC/TLS 1.3. TCP DoH поддерживает HTTP/1.1 и HTTP/2
поверх TLS 1.2/1.3 согласно переданной конфигурации.

## Inbound server

`Server` / `ServerBuilder` предоставляют встраиваемый inbound DNS server поверх
общего `Arc<Resolver>`:

- UDP/TCP в default build;
- DoT через `ServerBuilder::dot_addr` с `dot`;
- DoH HTTP/1.1/HTTP/2 через `ServerBuilder::doh_addr` с `doh`;
- DoH HTTP/3 через `ServerBuilder::doh3_addr` с `doh`;
- DoQ через `ServerBuilder::doq_addr` с `doq`.

Host-приложение передаёт TLS/QUIC server configuration и certificate material.
DNS Lattice не выпускает сертификаты и не владеет настройкой privileged ports.

## Feature и platform constraints

MSRV: **Rust 1.93**.

Стадия 0.6 валидирует поддерживаемый facade surface на:

- Linux;
- Windows;
- macOS.

CI запускает workspace formatting, linting, checking, tests и docs, плюс strict
per-feature `check`/`test`/rustdoc для:

```text
--no-default-features
dot
doh
doq
--all-features
```

CI также проверяет package contents workspace и запускает hermetic regression
release automation. Эти проверки не публикуют crates.

## Статус возможностей

| Возможность | Статус |
|---|:---:|
| DNS message encode/decode и name decompression | ✅ |
| Exact/suffix/wildcard domain matcher | ✅ |
| Static split-DNS policy | ✅ |
| Resolver + TTL/negative cache | ✅ |
| Route-scoped cache identity | ✅ |
| UDP/TCP upstreams | ✅ |
| DoT/DoH/DoQ upstreams | ✅ |
| Ordered upstream failover | ✅ |
| UDP/TCP inbound server | ✅ |
| DoT/DoH/DoH3/DoQ inbound server | ✅ |
| Fake IP pool + resolver synthesis | ✅ |
| Dynamic `RouteHook` | ✅ |
| Structured `ObservabilitySink` | ✅ |
| Linux/Windows/macOS feature-matrix validation | ✅ |
| Package/release automation hardening | ✅ |
| Stable public API / SemVer guarantee | ⏳ Стадия 1.0 |

## Границы экосистемы Lattice

DNS Lattice — один компонент более широкой сетевой экосистемы Lattice:

```text
net-lattice      OS network configuration and inspection
tunnel-lattice   TUN/TAP data-plane primitives
dns-lattice      DNS resolver/server control plane
flow-lattice     Policy compiler
sdk-lattice      Application-facing composition
```

DNS Lattice не изменяет OS DNS settings, не управляет TUN/TAP-устройствами, не
компилирует язык правил и не поставляет standalone daemon product. Эти
ответственности принадлежат host application или соседним компонентам Lattice.

## Текущий статус и роадмап

Завершены:

1. **0.0** — repository/architecture baseline;
2. **0.1** — базовая DNS model;
3. **0.2** — resolver и static split DNS;
4. **0.3** — upstream transports, failover, inbound server;
5. **0.4** — Fake IP;
6. **0.5** — dynamic route hooks;
7. **0.6** — hardening, cross-platform validation, observability, package и
   release checks.

В стадии 0.6 больше нет реализационных задач. Операция релиза `0.6.0` — это
механический bump версий и публикация штатным release-скриптом.

Следующая стадия:

8. **1.0** — аудит/заморозка публичного API, фиксация stable SemVer contract,
   финальная package/docs.rs validation и первый stable release.

Полные детали см. в [ROADMAP.ru.md](ROADMAP.ru.md) и
[ARCHITECTURE.ru.md](ARCHITECTURE.ru.md).

## Примеры

Исполняемые примеры находятся в
[`crates/dns-lattice/examples`](crates/dns-lattice/examples):

- `split_dns_policy` — matcher и static policy;
- `message_round_trip` — DNS wire encode/decode;
- `resolver` — in-process resolver/cache.

Запуск:

```bash
cargo run -p dns-lattice --example <name>
```

## Contributing и security

Требования к изменениям — в [CONTRIBUTING.md](CONTRIBUTING.md), private
vulnerability reporting — в [SECURITY.md](SECURITY.md), текущая support policy
— в [SUPPORT.md](SUPPORT.md).

## Лицензия

Mozilla Public License 2.0. См. [LICENSE](LICENSE).
