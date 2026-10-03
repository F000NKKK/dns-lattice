<div align="center">

<a id="top"></a>

# 🧭 DNS Lattice

### Программируемый встраиваемый DNS-резолвер и сервер для Rust

[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice?cacheSeconds=86400)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![CI](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

🇺🇸 [English](README.md) | 🇷🇺 **Русский**

[Возможности](#-ключевые-возможности) • [Транспорты](#-поддерживаемые-транспорты-и-платформы) • [Производительность](#-производительность) • [Установка](#-установка) • [Быстрый старт](#-быстрый-старт) • [Сравнение](#-сравнение)

</div>

---

## 📖 Обзор

**DNS Lattice** — программируемый встраиваемый DNS resolver/server engine для
Rust. Он предоставляет split DNS, кэширование, Fake IP, динамический выбор
маршрута, структурированную observability и UDP/TCP/DoT/DoH/DoQ-транспорты
через единый типизированный library API.

По смыслу это DNS-аналог встраиваемого HTTP server core: host-приложение
владеет процессом и конфигурацией, а DNS Lattice отвечает за DNS protocol
handling, resolution, serving, routing, cache behavior и transport execution.

Приложениям с нестандартным DNS обычно приходится вручную собирать несколько
разных задач: DNS wire parsing, split-DNS policy, cache semantics, transport
fallback, encrypted DNS, Fake IP state, server listeners и
application-specific routing. DNS Lattice разделяет эти ответственности, но
оставляет их совместимыми внутри одного engine.

### 🎯 Почему DNS Lattice?

- **🔀 Split DNS — основа, а не надстройка**: каждый запрос сначала
  направляется в именованную upstream group по детерминированным правилам
  exact/suffix/wildcard.
- **🧊 Кэш, учитывающий маршрут**: ключ кэша включает effective upstream
  group, поэтому один и тот же вопрос, отправленный по двум маршрутам, никогда
  не делит ответ.
- **🎭 Встроенный Fake IP**: конкурентный пул синтетических IPv4/IPv6-адресов
  с обратным поиском, LRU-вытеснением, TTL и снапшотами, подключённый к
  резолверу как терминальный путь ответа.
- **🪝 Динамическая маршрутизация без потери контроля**: `RouteHook` выбирает
  upstream group для каждого вопроса, но не получает ни резолвер, ни backend,
  ни кэш, ни доступ к ОС.
- **🔐 Все транспорты в обе стороны**: UDP, TCP, DoT, DoH (HTTP/1.1, HTTP/2,
  HTTP/3) и DoQ — и как upstream-клиенты, *и* как входящие listeners;
  шифрованные включаются отдельными Cargo features.
- **📡 Observability без фреймворка**: ограниченные неизменяемые события
  резолвера приходят в ваш собственный sink; logging- или tracing-крейт не
  нужен.
- **🧾 Стабильный API**: `1.x` следует SemVer; breaking change требует новой
  мажорной версии.

> **Статус:** **стабильные релизы `1.x` опубликованы** на crates.io
> (`dns-lattice`, `dns-lattice-core`, `dns-lattice-model`). Стадии 0.0–1.0
> завершены: публичный API заморожен, воркспейс следует обычной
> SemVer-дисциплине внутри линейки `1.x` — breaking change требует явного
> мажорного бампа. Текущую версию см. в [CHANGELOG.md](CHANGELOG.md).

## 🌟 Ключевые возможности

### Резолвинг
- ✅ **Статический split DNS**: `SplitDnsPolicy` сопоставляет exact-, suffix-
  и wildcard-шаблоны доменов с upstream groups, с необязательной группой по
  умолчанию
- ✅ **TTL и negative cache**: ответы в памяти истекают по своему DNS TTL;
  NXDOMAIN и пустые ответы тоже кэшируются
- ✅ **Ограниченный шардированный кэш**: память ограничена (по умолчанию
  16 MiB, это оценка) и проверяется при каждой вставке; `CacheConfig`
  задаёт предел, число шардов и границы TTL
- ✅ **Упорядоченный failover**: backends одной группы пробуются в порядке
  регистрации; timeout-, transport- и TLS-ошибки переводят на следующий
- ✅ **Синтез Fake IP**: подходящие A/AAAA и PTR из диапазона отвечаются
  локально из `FakeIpPool`

### Транспорты
- ✅ **UDP и TCP** в сборке по умолчанию, с переходом UDP → TCP при `TC=1`
- ✅ **DoT** (`dot`), **DoH** по HTTP/1.1, HTTP/2 и HTTP/3 (`doh`) и **DoQ**
  (`doq`) — каждый отдельной, выключенной по умолчанию Cargo feature
- ✅ **Входящий сервер** на тех же транспортах, с общим `Arc<Resolver>`

### Расширяемость
- 🪝 **`RouteHook`**: асинхронный выбор upstream group для вопроса, только
  выбор
- 📡 **`ObservabilitySink`**: синхронные non-authoritative события резолвера
- 🔌 **`UpstreamBackend`**: реализуйте свой транспорт и зарегистрируйте его
  рядом со встроенными

### Удобство разработки
- 🧭 **Один типизированный `Error`** для ошибок сообщений, policy,
  транспорта, TLS, hook и Fake IP
- 🗂️ **Модули по доменам** (`engine`, `upstream`, `server`, `fakeip`, ...)
  вместо плоского корневого пространства имён
- 🧪 **Транспорты проверены на loopback**: каждый клиент и listener
  прогоняется против локального сервера на Linux, Windows и macOS в CI

## 💻 Поддерживаемые транспорты и платформы

| Транспорт | Feature | Upstream-клиент | Входящий сервер | Linux | Windows | macOS |
|-----------|---------|:---------------:|:---------------:|:-----:|:-------:|:-----:|
| **UDP** | default | ✅ `UdpBackend` | ✅ `udp_addr` | ✅ | ✅ | ✅ |
| **TCP** | default | ✅ `TcpBackend` | ✅ `tcp_addr` | ✅ | ✅ | ✅ |
| **DoT** (RFC 7858) | `dot` | ✅ `DotBackend` | ✅ `dot_addr` | ✅ | ✅ | ✅ |
| **DoH** HTTP/1.1 + HTTP/2 (RFC 8484) | `doh` | ✅ `DohBackend` | ✅ `doh_addr` | ✅ | ✅ | ✅ |
| **DoH** HTTP/3 | `doh` | ✅ `Doh3Backend` | ✅ `doh3_addr` | ✅ | ✅ | ✅ |
| **DoQ** (RFC 9250) | `doq` | ✅ `DoqBackend` | ✅ `doq_addr` | ✅ | ✅ | ✅ |

✅ для платформы означает, что CI на этой ОС запускает `cargo check`,
`cargo test` и rustdoc с запретом предупреждений для этого набора features, а
тесты включают обмен клиента и listener с локальным loopback-сервером
(самоподписанные сертификаты для шифрованных транспортов). CI не обращается к
публичным резолверам.

> Привязка к привилегированному порту, например 53, — задача
> host-приложения; самому DNS Lattice особые привилегии не нужны.

## 🚀 Производительность

### 🏆 Особенности устройства

- **Попадание в кэш не трогает сеть**: попадание — это одна короткая
  блокировка одного шарда хранилища в памяти, копирование ссылки и возврат
  ответа; параллельные попадания в другие шарды друг друга не ждут. Hook при
  этом всё равно выполняется первым, upstreams — нет.
- **Кэш не может расти без предела**: хранилище занимает фиксированное число
  байт (по умолчанию 16 MiB) и вытесняет записи при каждой вставке, сначала
  истёкшие, поэтому поток одноразовых имён не вытесняет имена, которые
  запрашивают снова и снова.
- **Одна задача на запрос, без общего воркера**: сервер запускает задачу
  Tokio на каждую UDP-датаграмму, на каждое TCP/DoT/DoH-соединение и на
  каждый DoQ-поток; все они делят один `Arc<Resolver>`.
- **Без фоновых потоков и очередей**: резолвер не владеет потоками и не
  владеет задачами, пока вы не включите prefetch кэша (тогда удаление
  резолвера прерывает их), а callbacks observability выполняются синхронно
  после освобождения блокировки шарда кэша.
- **Платите только за нужные транспорты**: без `dot`, `doh` и `doq` в сборке
  нет зависимостей TLS, HTTP и QUIC.

Текущие ограничения, прямо:

- каждый upstream-запрос открывает новый сокет или соединение (UDP-сокет,
  TCP- или TLS-соединение, DoH-клиент, QUIC-соединение); пула соединений
  пока нет;
- по умолчанию `UdpBackend` не добавляет свою запись EDNS0/OPT: он
  пересылает запрос без изменений, поэтому на запрос без неё ответы по UDP
  ограничены 512 байтами (более крупные идут через TCP), а запрос с такой
  записью может получить ответ до объявленного в ней размера.
  `UdpBackend::with_edns_udp_payload_size` включает добавление записи OPT к
  запросам без неё (с одним повтором без неё после `FORMERR` или `NOTIMP` и
  удалением её из ответа);
- входящий сервер отвечает UDP-клиентам с EDNS(0) не более чем
  min(размер payload клиента, поднятый до 512, 1232 байта)
  (`ServerBuilder::edns_udp_payload_size`
  меняет 1232), а клиентам без EDNS — не более чем 512 байтами; более
  крупные ответы отправляются пустыми с `TC=1`, и клиент повторяет запрос
  по TCP;
- кэш ответов занимает не более примерно 16 MiB по умолчанию
  (`CacheConfig::max_bytes`; это оценка занятой кучи, а не точное значение
  аллокатора) и не имеет фоновой очистки: истёкшая запись удаляется, когда
  на тот же вопрос приходит новый запрос или когда вставке нужно место.
  Одновременные одинаковые промахи объединяются в один upstream-запрос
  (см. «Семантика кэша»).

### 📊 Бенчмарки

Бенчмарк, сравнивающий DNS Lattice с
[hickory-resolver](https://github.com/hickory-dns/hickory-dns), в работе.
Цифр пока нет; таблица результатов появится здесь.

## 📦 Установка

```toml
[dependencies]
# Только UDP и TCP: без зависимостей TLS, HTTP и QUIC
dns-lattice = "1.1.3"
tokio = { version = "1.53.1", features = ["rt-multi-thread", "macros"] }
```

Шифрованные транспорты добавляйте только при необходимости. Features
независимы и выключены по умолчанию:

```toml
# DNS-over-TLS
dns-lattice = { version = "1.1.3", features = ["dot"] }

# DNS-over-HTTPS по HTTP/1.1, HTTP/2 и HTTP/3
dns-lattice = { version = "1.1.3", features = ["doh"] }

# DNS-over-QUIC, без HTTP-стека
dns-lattice = { version = "1.1.3", features = ["doq"] }

# Всё сразу
dns-lattice = { version = "1.1.3", features = ["dot", "doh", "doq"] }
```

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS по HTTP/1.1, HTTP/2 и HTTP/3;
- `doq` — DNS-over-QUIC.

Для реализации `RouteHook` или `UpstreamBackend` в ваши зависимости также
нужен `async-trait = "0.1"`.

## 🎓 Быстрый старт

### UDP resolver + server

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

async fn run() -> Result<()> {
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
    Ok(())
}
```

`Resolver` владеет routing/cache/failover. `Server` владеет inbound listening и
framing. Реализации `UpstreamBackend` владеют outbound transport execution.

## 📚 Примеры

### Split DNS с failover

```rust,no_run
use std::{net::SocketAddr, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    model::{DomainPattern, SplitDnsPolicy, UpstreamGroupId},
    upstream::{TcpBackend, TcpBackendConfig, UdpBackend, UdpBackendConfig},
};

fn udp(server: &str) -> UdpBackend {
    UdpBackend::new(UdpBackendConfig {
        server: server.parse::<SocketAddr>().unwrap(),
        timeout: Duration::from_secs(2),
        bind_addr: None,
    })
}

fn build() -> Result<Resolver> {
    let corp = UpstreamGroupId::new("corp");
    let public = UpstreamGroupId::new("public");

    let policy = SplitDnsPolicy::builder()
        .rule(DomainPattern::parse("corp.internal")?, corp.clone()) // corp.internal и ниже
        .default_group(public.clone())
        .build();

    Ok(Resolver::builder(policy)
        .backend(
            corp,
            TcpBackend::new(TcpBackendConfig {
                server: "10.0.0.53:53".parse().unwrap(),
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
            }),
        )
        // По порядку: 9.9.9.9 — только после таймаута или transport-ошибки
        // у 1.1.1.1.
        .backend(public.clone(), udp("1.1.1.1:53"))
        .backend(public, udp("9.9.9.9:53"))
        .build())
}
```

### Upstream DNS-over-TLS (`dot`)

```rust,no_run
use std::time::Duration;

use dns_lattice::{
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    upstream::{DotBackend, DotBackendConfig},
};

fn build() -> Resolver {
    let group = UpstreamGroupId::new("encrypted");
    let dot = DotBackend::new(DotBackendConfig::with_webpki_roots(
        "1.1.1.1:853".parse().unwrap(),
        "cloudflare-dns.com".try_into().unwrap(), // SNI и имя в сертификате
        Duration::from_secs(3),                   // TCP connect
        Duration::from_secs(5),                   // TLS handshake и каждое чтение/запись
    ));

    Resolver::builder(SplitDnsPolicy::builder().default_group(group.clone()).build())
        .backend(group, dot)
        .build()
}
```

`DoqBackendConfig::with_webpki_roots` работает так же для DoQ; DoH принимает
`DohBackendConfig` / `Doh3BackendConfig` с URI эндпоинта и клиентской
конфигурацией `rustls`.

### Fake IP

```rust,no_run
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    fakeip::{FakeIpPolicy, FakeIpPool},
    model::{DomainPattern, SplitDnsPolicy},
};

fn build() -> Result<Resolver> {
    let pool = Arc::new(
        FakeIpPool::builder()
            .ipv4_range(Ipv4Addr::new(198, 18, 0, 0), Ipv4Addr::new(198, 19, 255, 255))
            .ttl(Duration::from_secs(300))
            .build()?,
    );
    let policy = FakeIpPolicy::builder()
        .rule(DomainPattern::parse("example.com")?)
        .build();

    // A-запросы к example.com и его поддоменам получают адреса из пула; AAAA
    // получает локальный NODATA, потому что у пула нет IPv6-диапазона.
    Ok(Resolver::builder(SplitDnsPolicy::builder().build())
        .fake_ip(pool, policy)
        .build())
}
```

### Динамический route hook

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

Устанавливается через `ResolverBuilder::route_hook(PreferFiltered)`.

### Observability sink

```rust,no_run
use std::sync::Arc;

use dns_lattice::{
    engine::Resolver,
    model::SplitDnsPolicy,
    observability::{ObservabilitySink, ObserveEvent},
};

struct PrintSink;

impl ObservabilitySink for PrintSink {
    fn record(&self, event: &ObserveEvent) {
        println!("{event:?}");
    }
}

fn build() -> Resolver {
    Resolver::builder(SplitDnsPolicy::builder().build())
        .observability_sink(Arc::new(PrintSink))
        .build()
}
```

### Корректная остановка

```rust,no_run
use std::sync::Arc;

use dns_lattice::{core::Result, engine::Resolver, server::ServerBuilder};

// Для `ctrl_c` нужна feature `signal` у tokio.
async fn run(resolver: Arc<Resolver>) -> Result<()> {
    let server = ServerBuilder::new(resolver)
        .udp_addr("127.0.0.1:5353".parse().unwrap())
        .tcp_addr("127.0.0.1:5353".parse().unwrap())
        .bind()
        .await?;

    server
        .serve_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
```

### Исполняемые примеры

Исполняемые примеры находятся в
[`crates/dns-lattice/examples`](crates/dns-lattice/examples):

- `split_dns_policy` — matcher и static policy;
- `message_round_trip` — DNS wire encode/decode;
- `resolver` — in-process resolver/cache.

Запуск:

```bash
cargo run -p dns-lattice --example <name>
```

## 🔄 Resolver pipeline

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

## 🔀 Split DNS и matching

`dns-lattice-model` предоставляет детерминированный exact/suffix/wildcard
matching и `SplitDnsPolicy`. Resolver сначала получает статического кандидата
upstream group из этой policy.

Model/matcher слой не выполняет network I/O и не зависит от ОС. Hardening
стадии 0.6 добавил детерминированное property-style покрытие matcher
precedence, message parsing и DNS name compression bounds.

## 🧊 Семантика кэша

Resolver имеет in-memory answer cache с учётом TTL, включая negative caching.
Для обычных запросов cache identity включает **effective upstream group**.
Это критично при route hook: одинаковые DNS questions, отправленные в разные
маршруты, не могут разделить один answer. Биты RD и EDNS DO (RFC 3225)
запроса тоже входят в identity.

- **Что кэшируется**: ответы `NOERROR` с записями, `NXDOMAIN` и `NODATA`,
  только с opcode QUERY, `TC=0` и расширенным RCODE EDNS, равным 0.
  `SERVFAIL`, `REFUSED`, другие коды ошибок, усечённые ответы и ответы с
  TTL 0 возвращаются, но не сохраняются. Запросы, в которых не ровно один
  question, другой opcode, опция EDNS Client Subnet или любая опция EDNS,
  кроме NSID, COOKIE, TCP keepalive и Padding, идут мимо кэша и
  объединения.
- **Объединение запросов (coalescing)**: параллельные промахи с одной cache
  identity делят один upstream-запрос (`CacheConfig::coalesce(false)`
  отключает это). Первый запрос ведущий: он сохраняет ответ и передаёт его
  остальным, которые отвечают со своими id, question и битом RD либо
  получают его ошибку. Ожидающий запрос не выдаёт upstream-событий; sink
  получает `CacheEvent::Coalesced` через `ObservabilitySink::record_cache`.
  Если future ведущего `resolve` отброшен, ожидающий запрос берёт ведение на
  себя; ничего не порождается (spawn), поэтому это работает на любом
  executor.
- **Prefetch (opt-in)**: `CacheConfig::prefetch(Some(Prefetch::new()))`
  обновляет популярные записи незадолго до истечения. Свежее попадание
  запускает фоновое обновление, когда у записи осталось не более 10 % срока
  жизни (`Prefetch::threshold_percent`, от 1 до 50) и она обслужила не менее
  2 попаданий (`Prefetch::min_hits`). Само попадание отвечает из кэша как
  обычно; обновление опрашивает ту же upstream-группу (route hook повторно не
  вызывается), входит в тот же реестр запросов в полёте, что и обычный
  промах, поэтому не дублирует идущий upstream-вызов, а пришедший в это время
  запрос делит его результат, и заменяет запись, если ответ можно
  кэшировать. Каждая сохранённая запись обновляется не более одного раза,
  одновременно идёт не более 256 обновлений, а попадание вне среды Tokio
  обновление не запускает. Обновления выполняются в этой среде и
  прерываются при удалении `Resolver`. Они выдают `CacheEvent::RefreshStarted`
  и `CacheEvent::RefreshCompleted` (с полем `refreshed`), но не
  `ObserveEvent`. По умолчанию выключено: без него резолвер ничего не
  порождает.
- **Время жизни**: по умолчанию сохранённые TTL ограничены 86 400 с
  (positive) и 3 600 с (negative); `CacheConfig::positive_ttl` и
  `CacheConfig::negative_ttl` задают другие границы. Positive-запись живёт по
  наименьшему TTL записей во всех секциях, negative — min(TTL SOA, `MINIMUM`
  SOA) (RFC 2308) или 60 с без SOA (`CacheConfig::negative_ttl_without_soa`
  меняет это значение; `None` не сохраняет такие ответы).
- **Предел памяти**: хранилище разделено на шарды, у каждого своя блокировка
  и равная доля `CacheConfig::max_bytes` (по умолчанию 16 MiB). Каждая
  вставка вытесняет записи, пока шард не уложится в свою долю: сначала
  истёкшие, затем те, к которым не обращались повторно (S3-FIFO), поэтому
  поток уникальных имён, например случайных поддоменов с NXDOMAIN, не
  вытесняет популярные имена. Кэш никогда не сбрасывается целиком ради
  места. Ответ больше одной восьмой доли шарда возвращается, но не
  сохраняется. `CacheConfig::disabled()` (или `max_bytes(0)`) не хранит
  ничего.
- **Попадания**: TTL уменьшаются на целое число секунд, прошедших с
  сохранения ответа. Попадание несёт id, question и бит RD текущего
  запроса, ставит AA=0 и сохраняет исходный порядок всех записей.
- **Сброс**: `Resolver::clear_cache` удаляет всё, `Resolver::purge(name,
  rtype)` удаляет одно имя (для всех групп, классов и форм запроса; один тип
  записи или все при `None`), а `Resolver::purge_subtree(zone)` удаляет зону
  и всё под ней, сопоставляя только целые метки (`ample.com` не совпадает с
  `example.com`). Каждый метод возвращает число удалённых записей. Сброс
  также не даёт запросам, уже ждущим upstream-ответ, сохранить свой ответ;
  они всё равно получают ответ. Используйте его после смены сети или VPN.
- **Статистика**: `Resolver::cache_stats()` возвращает снимок `CacheStats` с
  полями `entries`, `bytes` (оценка), `capacity_bytes`, `hits`, `misses`,
  `coalesced`, `inserts`, `evictions`, `expirations`, `oversized_rejected` и
  `refreshes`. Счётчики монотонны и переживают сброс. `hits` считает запросы,
  отвеченные из хранилища при первом поиске: ведущий, который промахнулся, а
  затем нашёл ответ, только что сохранённый другим запросом, считается
  промахом, поэтому при конкуренции `hits` может быть немного меньше числа
  запросов, обслуженных хранилищем.
- **EDNS(0)**: запись OPT удаляется перед сохранением ответа, поэтому
  попадание никогда не повторяет запись OPT другого клиента. Попадание для
  запроса с записью OPT получает новую (1232 байта, версия 0, бит DO
  запроса, без опций); попадание для запроса без неё не получает OPT.

Terminal Fake IP ответы обходят обычный answer cache; их lifetime принадлежит
самому Fake IP mapping.

## 🪝 Dynamic route hooks

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

## 🎭 Fake IP

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

## 📡 Observability

`ResolverBuilder::observability_sink` принимает optional
`observability::ObservabilitySink`. Resolver выдаёт immutable bounded events
для ключевых переходов pipeline, включая:

- query receipt;
- terminal Fake IP handling;
- static/effective route и hook outcomes;
- cache hit/miss;
- upstream attempts/outcomes;
- timeout и terminal error paths.

Сигналы кэша вне этого упорядоченного потока, например присоединение запроса
к чужому in-flight upstream-вызову, приходят как `observability::CacheEvent`
через метод `ObservabilitySink::record_cache` с реализацией по умолчанию;
sink, который его не переопределяет, их игнорирует.

Sink non-authoritative. Он не может менять routing, answers, cache state или
retries; не получает resolver/backend handles; resolver locks освобождаются до
callbacks; panic callback изолирован от корректности resolver. DNS Lattice не
требует конкретный logging/tracing framework и не владеет background telemetry
queue.

## 🔐 Upstream transports

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

## 🖥️ Inbound server

`Server` / `ServerBuilder` предоставляют встраиваемый inbound DNS server поверх
общего `Arc<Resolver>`:

- UDP/TCP в default build;
- DoT через `ServerBuilder::dot_addr` с `dot`;
- DoH HTTP/1.1/HTTP/2 через `ServerBuilder::doh_addr` с `doh`;
- DoH HTTP/3 через `ServerBuilder::doh3_addr` с `doh`;
- DoQ через `ServerBuilder::doq_addr` с `doq`.

Host-приложение передаёт TLS/QUIC server configuration и certificate material.
DNS Lattice не выпускает сертификаты и не владеет настройкой privileged ports.

## ✅ Feature и platform constraints

MSRV: **Rust 1.93**.

CI валидирует поддерживаемый facade surface на:

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

## 📋 Статус возможностей

| Возможность | Статус |
|---|:---:|
| DNS message encode/decode и name decompression | ✅ |
| Exact/suffix/wildcard domain matcher | ✅ |
| Static split-DNS policy | ✅ |
| Resolver + TTL/negative cache | ✅ |
| Byte-bounded sharded cache, configurable TTL limits | ✅ |
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
| Stable public API / SemVer guarantee | ✅ |

## 🤝 Сравнение

[hickory-resolver](https://docs.rs/hickory-resolver) — устоявшийся
универсальный DNS-резолвер для Rust. У них разные задачи: hickory резолвит
имена так, как это сделала бы ОС, а DNS Lattice маршрутизирует и обслуживает
DNS внутри приложения. Утверждения о hickory ниже взяты с его страницы на
docs.rs (версия 0.26.3).

| Возможность | DNS Lattice | hickory-resolver |
|-------------|-------------|------------------|
| **Назначение** | Движок резолвера и входящий сервер в одном крейте | Stub-резолвер (сервер — отдельный крейт `hickory-server`) |
| **UDP / TCP** | ✅ В сборке по умолчанию | ✅ В сборке по умолчанию |
| **Upstreams DoT / DoH / DoH3 / DoQ** | ✅ Features `dot`, `doh`, `doq` | ✅ Features `tls-*`, `https-*`, `h3-*`, `quic-*` |
| **TLS crypto provider** | `aws-lc-rs` | `aws-lc-rs` или `ring` |
| **Входящий listener DoT / DoH / DoQ** | ✅ Встроен | ➖ Не входит в крейт резолвера |
| **Split DNS по доменам в upstream groups** | ✅ `SplitDnsPolicy` | ➖ Не описан в его документации |
| **Fake IP** | ✅ Встроен | ➖ Не описан в его документации |
| **Hook маршрутизации на запрос** | ✅ `RouteHook` | ➖ Не описан в его документации |
| **Валидация DNSSEC** | ❌ | ✅ Features `dnssec-*` |
| **Системная конфигурация** (`/etc/resolv.conf`, Windows) | ❌ Намеренно; всё настраивает host | ✅ `system-config` (по умолчанию) |
| **Переиспользование upstream-соединений** | ❌ Новое соединение на запрос | ✅ Пул name-серверов |
| **EDNS0 по UDP** | ➖ Входящий сервер отвечает EDNS-клиентам до 1232 байт (настраивается), `FORMERR`/`BADVERS` обрабатываются локально; `UdpBackend` пересылает запись OPT клиента и, пока `with_edns_udp_payload_size` не включён, свою не добавляет | Не сравнивалось |
| **Пропускная способность и задержка** | Ещё не измерены | Ещё не измерены |

## 🛠️ Обзор API

### Публичные модули

Канонические public paths:

| Модуль | Назначение |
|---|---|
| `dns_lattice::core` | Общие типизированные errors/results |
| `dns_lattice::model` | DNS messages, records, names, matchers, policies |
| `dns_lattice::engine` | `Resolver` / `ResolverBuilder` |
| `dns_lattice::cache` | `CacheConfig`: предел памяти кэша, шарды, границы TTL |
| `dns_lattice::upstream` | Outbound backend trait и transports |
| `dns_lattice::server` | Inbound listeners и lifecycle |
| `dns_lattice::fakeip` | Fake IP pool, policy, TTL, snapshots |
| `dns_lattice::hooks` | Dynamic route-selection hook |
| `dns_lattice::observability` | Structured resolver events/sink |

### Основные элементы

| Элемент | Назначение |
|---------|------------|
| `Resolver::builder(SplitDnsPolicy)` | Начать резолвер со split-DNS policy |
| `ResolverBuilder::backend(group, backend)` | Зарегистрировать backend в группе; порядок задаёт порядок failover |
| `ResolverBuilder::fake_ip(pool, policy)` | Включить локальные Fake IP ответы |
| `ResolverBuilder::route_hook` / `observability_sink` | Установить необязательные hook и sink событий |
| `Resolver::resolve(&Message)` | Разрешить один декодированный запрос |
| `ServerBuilder::new(Arc<Resolver>)` | Начать входящий сервер; добавить `udp_addr`, `tcp_addr`, `dot_addr`, `doh_addr`, `doh3_addr`, `doq_addr` |
| `ServerBuilder::bind` → `Server::serve` / `serve_until` | Привязать все listeners и обслуживать до drop или до завершения future остановки |
| `UpstreamBackend` | Async-трейт, который реализует каждый исходящий транспорт |
| `Message::decode` / `encode` | DNS wire format |

### Крейты воркспейса

DNS Lattice публикуется как три крейта:

| Крейт | Ответственность |
|---|---|
| [`dns-lattice`](crates/dns-lattice/README.md) | Public facade + runtime implementation resolver/server |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | DNS message model, names, matcher, split-DNS policy |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Общая типизированная граница `Error` / `Result` |

Большинству приложений достаточно зависимости только от `dns-lattice`.

## 📖 Документация

- **Справочник API**: [docs.rs/dns-lattice](https://docs.rs/dns-lattice)
- **Архитектура**: [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md)
- **Роадмап**: [ROADMAP.ru.md](ROADMAP.ru.md)
- **Изменения**: [CHANGELOG.md](CHANGELOG.md)
- **Поддержка и безопасность**: [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md)

## 🐛 Решение проблем

<details>
<summary><b><code>Error::NoRoute</code> из <code>resolve</code></b></summary>

Ни одно правило split DNS не подошло к имени и у policy нет группы по
умолчанию, в запросе не было вопроса, или в выбранной группе (статически или
через hook) не зарегистрирован ни один backend. Добавьте `default_group` или
зарегистрируйте backend для каждой группы, которую могут вернуть правила и
hook.
</details>

<details>
<summary><b><code>bind</code> завершается с <code>Error::Transport</code></b></summary>

Адрес уже занят, некорректен или требует привилегий (например, порт 53 на
Unix). DNS Lattice не обрабатывает привилегированные порты особо; используйте
непривилегированный порт, например 5353, или дайте процессу право на этот
порт.
</details>

<details>
<summary><b>Большие ответы приходят пустыми с битом <code>TC</code></b></summary>

Входящий UDP listener отвечает клиенту без записи EDNS0 OPT не более чем 512
байтами, а EDNS0-клиенту — не более чем меньшим из объявленного им размера
payload и максимума сервера (по умолчанию 1232 байта,
`ServerBuilder::edns_udp_payload_size`). Для более крупного ответа он
отправляет пустой усечённый ответ (сохраняя запись OPT для EDNS0-клиента), и
клиент должен повторить запрос по TCP; слушайте и TCP (`tcp_addr`) на том же
адресе.
`UdpBackend` делает такой повтор по TCP сам; чтобы он требовался реже,
вызовите `UdpBackend::with_edns_udp_payload_size`: запросы без записи OPT
будут объявлять upstream больший размер UDP payload.
</details>

<details>
<summary><b>DoQ или DoH по HTTP/3 не проходит handshake</b></summary>

QUIC требует TLS 1.3 и правильный ALPN. `DoqBackendConfig::with_webpki_roots`
выставляет `doq` сам; собранный вручную клиентский `tls_config` должен
включать `doq` самостоятельно. На стороне сервера `quinn::ServerConfig` для
`doq_addr` должен объявлять `doq`, а для `doh3_addr` — `h3`. Для `doh_addr`
настройте ALPN `h2` и `http/1.1`.
</details>

<details>
<summary><b>Panic об отсутствующем рантайме Tokio</b></summary>

Каждый встроенный backend и listener выполняет сокетный I/O через Tokio,
поэтому вызывайте `Resolver::resolve`, `ServerBuilder::bind` и
`Server::serve` внутри рантайма Tokio (например, под `#[tokio::main]`).
</details>

## 🌐 Экосистема Lattice

| Крейт | Назначение |
| --- | --- |
| [net-lattice](https://github.com/F000NKKK/net-lattice) | Инспекция и настройка сетевого стека ОС (маршруты, DNS, интерфейсы) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP туннельные интерфейсы |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Программируемый DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Компилятор политик: правила в платформенно-нейтральные сетевые планы |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Прикладной SDK, объединяющий крейты выше |

DNS Lattice не изменяет OS DNS settings, не управляет TUN/TAP-устройствами, не
компилирует язык правил и не поставляет standalone daemon product. Эти
ответственности принадлежат host application или соседним компонентам Lattice.

## 🗺️ Текущий статус и роадмап

Завершены:

1. **0.0** — repository/architecture baseline;
2. **0.1** — базовая DNS model;
3. **0.2** — resolver и static split DNS;
4. **0.3** — upstream transports, failover, inbound server;
5. **0.4** — Fake IP;
6. **0.5** — dynamic route hooks;
7. **0.6** — hardening, cross-platform validation, observability, package и
   release checks;
8. **1.0** — аудит/заморозка публичного API, фиксация stable SemVer contract
   и первый stable release (`dns-lattice`, `dns-lattice-core`,
   `dns-lattice-model` `1.0.0` на crates.io).

Публичный API теперь заморожен: внутри линейки `1.x` аддитивные изменения
идут минорными релизами, фиксы — патчами; breaking change требует явного
мажорного бампа.

Полные детали см. в [ROADMAP.ru.md](ROADMAP.ru.md) и
[ARCHITECTURE.ru.md](ARCHITECTURE.ru.md).

## 🙏 Участие в разработке

Требования к изменениям — в [CONTRIBUTING.md](CONTRIBUTING.md), private
vulnerability reporting — в [SECURITY.md](SECURITY.md), текущая support policy
— в [SUPPORT.md](SUPPORT.md).

```bash
git clone https://github.com/F000NKKK/dns-lattice.git
cd dns-lattice
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p dns-lattice --no-default-features --features doq   # одна feature отдельно
```

Ни одному тесту не нужны привилегии или сеть дальше loopback.

## 📄 Лицензия

Распространяется под [Mozilla Public License 2.0](LICENSE).

## 🌟 Благодарности

- [`rustls`](https://github.com/rustls/rustls), [`quinn`](https://github.com/quinn-rs/quinn),
  [`hyper`](https://github.com/hyperium/hyper) и [`h3`](https://github.com/hyperium/h3),
  на которых работают шифрованные транспорты
- [Tokio](https://tokio.rs), на котором работает каждый сокет
- [hickory-dns](https://github.com/hickory-dns/hickory-dns) — ориентир для
  DNS в Rust

---

<div align="center">

**[⬆ Наверх](#top)**

Часть сетевого стека Lattice

</div>
