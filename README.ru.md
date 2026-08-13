# DNS Lattice

**Языки**

🇺🇸 [English](README.md) | 🇷🇺 **Русский**

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

**DNS Lattice** — программируемый DNS control plane на Rust для сетевого стека Lattice: DNS-аналог того, чем Kestrel является для HTTP в ASP.NET Core — полноценный встраиваемый движок DNS-сервера, который любое приложение размещает у себя, чтобы получить split DNS, Fake IP, кэширование, шифрованный апстрим-транспорт и программируемую маршрутизацию, не строя резолвер с нуля.

> **Статус:** Опубликован `0.3.0`. Он реализует модель DNS-сообщений, доменный/
> зональный матчер, типы политик split-DNS, резолвер/кэш, апстрим-транспорты
> UDP/TCP/DoT/DoH/DoQ, failover и соответствующие входящие серверные
> слушатели в трёх крейтах — `dns-lattice-core`, `dns-lattice-model` и
> фасад `dns-lattice`. Разработка `0.4` добавляет самостоятельный пул Fake
> IP. API остаётся pre-1.0; см. раздел «Текущий статус» ниже.

## Обзор

Логика DNS-резолвинга в Rust-приложениях обычно либо пишется вручную и бессистемно, либо подключается через тяжеловесную, полностью асинхронную, привязанную к транспорту библиотеку резолвера. DNS Lattice стремится отделить протокольно-политический уровень (разбор сообщений, зональное сопоставление, split-DNS маршрутизация, Fake IP) от транспортных вопросов, чтобы приложения могли встраивать именно то поведение DNS-сервера или резолвера, которое им нужно, за одним строго типизированным API.

## Быстрый старт

Обычный путь входящего запроса:

```text
DNS-клиент → Server → Resolver → SplitDnsPolicy → UpstreamBackend → UDP/TCP/DoT/DoH/DoQ
```

В новом коде используйте domain-scoped imports. Плоские aliases в корне
остаются совместимыми.

```rust,no_run
use std::{net::SocketAddr, sync::Arc, time::Duration};

use dns_lattice::{
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    server::ServerBuilder,
    upstream::{UdpBackend, UdpBackendConfig},
};

# async fn run() -> dns_lattice::Result<()> {
let group = UpstreamGroupId::new("default");
let policy = SplitDnsPolicy::builder().default_group(group.clone()).build();
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

`Resolver` оркестрирует декодированные запросы, статическую маршрутизацию,
кэш и failover апстримов. `Server` владеет входящими слушателями и
фреймингом, а реализации `UpstreamBackend` — исходящим транспортом.

## Крейты workspace

Workspace разделён на сфокусированные крейты, по аналогии со структурой
[net-lattice](https://github.com/F000NKKK/net-lattice). У каждого крейта
есть собственный README со своей областью ответственности и примером
использования:

| Крейт | Назначение |
|---|---|
| [`dns-lattice`](crates/dns-lattice/README.md) | Публичный фасад: реэкспортирует крейты ниже как стабильную поверхность |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | Модель DNS-сообщений, доменный/зональный матчер и политики split-DNS |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Общие типы `Error`/`Result` |

## Экосистема Lattice

DNS Lattice — один из крейтов более широкого семейства Lattice:
композируемых кроссплатформенных библиотек для Rust-сетевого стека.

| Крейт | Назначение |
|---|---|
| [net-lattice](https://github.com/F000NKKK/net-lattice) | Инспекция и настройка сетевого стека ОС (маршруты, DNS, интерфейсы) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP туннельные интерфейсы |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Программируемый DNS control plane (этот репозиторий) |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Компилятор политик: правила -> платформенно-нейтральные сетевые планы |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Прикладной SDK, объединяющий крейты выше |

Направление межрепозиторных зависимостей и границы API фиксируются в
[ARCHITECTURE.md](ARCHITECTURE.md) по мере проработки дизайна; `dns-lattice`
не имеет compile-time зависимости ни от одного соседнего крейта.

## Философия

- **Строгая типизация вместо сырых байтов.** Пользователи работают с типизированными сообщениями, именами и записями — без ручной арифметики по байтовым смещениям.
- **Протокол/политика отделены от транспорта.** Модель сообщений, зональный матчер и типы политик не выполняют сетевой ввод-вывод; транспорт добавляется поверх на следующей стадии за явным трейтом бэкенда.
- **Детерминизм по дизайну.** Приоритет зонального/доменного сопоставления — задокументированный, протестированный контракт (см. [ARCHITECTURE.md](ARCHITECTURE.md)), а не случайный порядок итерации.
- **Типизированные ошибки, никаких паник.** Каждая fallible-операция возвращает `Result<T, Error>`; некорректный wire-ввод отклоняется, а не приводит к неопределённому поведению.
- **Постепенный, продуманный рост.** Каждая стадия роадмапа поставляет ограниченный, полностью протестированный слой, а не большую, слабо протестированную поверхность.

## Возможности

Реализовано (`0.3.0` и текущий слой разработки `0.4`):

- Написанная вручную модель DNS-сообщений: кодирование/декодирование заголовка, вопроса и ресурсных записей, включая (де)компрессию имён при декодировании
- Типы записей: A, AAAA, CNAME, PTR, NS, TXT, MX, SOA, плюс типизированный fallback для любого другого типа записи
- Доменный/зональный матчер с детерминированным приоритетом exact/suffix/wildcard
- Типы статической политики split-DNS (`SplitDnsPolicy`), построенные на матчере
- In-process асинхронный `Resolver`: создание из `SplitDnsPolicy`, маршрутизация одного запроса к группе апстримов и резолвинг с failover по зарегистрированным бэкендам группы в порядке регистрации, с кэшем ответов в памяти с учётом TTL и негативным кэшированием по RFC 2308
- Публичный асинхронный модуль `upstream` (трейт `UpstreamBackend`, `UdpBackend`, `TcpBackend`): базовые апстрим-транспорты UDP и TCP поверх `tokio`, пока без EDNS0/OPT (UDP переключается на TCP при усечённом ответе)
- Апстрим-бэкенды DoT (`DotBackend`, RFC 7858) и DoH (`DohBackend`, RFC 8484), каждый за собственной отключённой по умолчанию Cargo-фичей `dot`/`doh`, поверх `rustls`/`tokio-rustls`/`hyper`/`hyper-rustls`
- Апстрим-бэкенд DoQ (`DoqBackend`, RFC 9250) за собственной отключённой по умолчанию Cargo-фичей `doq`, поверх `quinn` (транспорт QUIC, TLS 1.3 встроен через `rustls`); на этой стадии — новое QUIC-соединение на каждый запрос, без пулинга/переиспользования соединений
- Публичный асинхронный модуль `server` (`Server`, `ServerBuilder`): встраиваемый входящий слушатель DNS UDP/TCP поверх `Arc<Resolver>` — жизненный цикл construct/bind/serve/shutdown, одна задача на каждую UDP-датаграмму и одна задача на каждое TCP-соединение (с циклом чтения нескольких запросов с префиксом длины по RFC 1035 §4.2.2), усечение слишком больших UDP-ответов с установкой `TC=1` и синтез `Rcode::ServFail`, если резолвер вернул ошибку
- Входящий слушатель DNS-over-TLS (DoT, RFC 7858) за Cargo-фичей `dot`: `ServerBuilder::dot_addr` принимает TLS-сессию на каждом соединении через `tokio_rustls::TlsAcceptor` и переиспользует тот же цикл чтения/записи с префиксом длины, что и слушатель TCP
- Входящий слушатель DNS-over-QUIC (DoQ, RFC 9250) за Cargo-фичей `doq`: `ServerBuilder::doq_addr` принимает QUIC-эндпойнт `quinn` (ALPN `doq`) и отвечает на каждый запрос через отдельный двунаправленный поток, переиспользуя те же хелперы фрейминга, что и апстрим `DoqBackend`
- Входящий слушатель DNS-over-HTTPS (DoH, RFC 8484) за Cargo-фичей `doh`: TCP `ServerBuilder::doh_addr` принимает TLS-сессию на каждом соединении через `tokio_rustls::TlsAcceptor`, затем обслуживает согласованные через ALPN HTTP/1.1 или HTTP/2 сервер-билдером `hyper_util` поверх TLS 1.2 или 1.3. Для двух протоколов конфигурация содержит ALPN-идентификаторы `h2` и `http/1.1`; GET (`?dns=` в base64url) и POST (тело `application/dns-message`) работают в обоих протоколах.
- DoH HTTP/3 дополняет, а не заменяет legacy TCP: `Doh3Backend` и QUIC `ServerBuilder::doh3_addr` используют QUIC/UDP с ALPN `h3` и TLS 1.3. Для HTTP/1.1/HTTP/2-клиентов на TLS 1.2 или 1.3 остаются TCP `DohBackend`/`doh_addr`.
- Вызываемый приложением `fakeip::FakeIpPool`: детерминированное конкурентное выделение IPv4 и/или IPv6 и обратный поиск в включающих диапазонах с LRU-вытеснением для каждого семейства. Это только хранилище данных: оно не переписывает DNS-ответы, не синтезирует PTR, не применяет TTL/истечение, не сохраняет отображения и не интегрируется неявно с `Resolver` или `Server`.

Запланировано (см. [ROADMAP.ru.md](ROADMAP.ru.md)):

- Динамические хуки маршрутизации для политики со стороны вызывающего кода (стадия 0.5)
- Кроссплатформенная CI-матрица, fuzz/property-тесты, sink наблюдаемости (стадия 0.6)

## Транспортные фичи

UDP и TCP доступны в сборке по умолчанию. Зашифрованные транспорты
подключаются независимо и явно: `dot` для DoT, `doh` для DoH (включая
HTTP/3) и `doq` для DoQ. По умолчанию они отключены, поэтому приложениям,
которым нужны только UDP/TCP, не добавляются зависимости TLS, HTTP и QUIC.

## Не-цели

- DNS Lattice не владеет изменением DNS-конфигурации на уровне ОС — это ответственность [net-lattice](https://github.com/F000NKKK/net-lattice).
- DNS Lattice не компилирует синтаксис правил — это ответственность [flow-lattice](https://github.com/F000NKKK/flow-lattice).
- DNS Lattice не управляет устройствами TUN/TAP и пересылкой пакетов; эти задачи data plane находятся вне области данного крейта.
- DNS Lattice не поставляется как самостоятельный серверный продукт (CLI, формат конфигурации, супервизия процесса) — в область входит только встраиваемый *движок* обслуживания; упаковка его в устанавливаемый демон — задача приложения поверх, обычно через [sdk-lattice](https://github.com/F000NKKK/sdk-lattice).

## Текущий статус

Реализация стадий 0.1-0.2 и объёма реализации стадии 0.3 (Track A/Track B/Track
C/Track D/Track E) из [архитектуры](ARCHITECTURE.ru.md) покрыта
детерминированными unit/doc-тестами, `clippy -D warnings` и проверенными
листингами `cargo package` для всех трёх крейтов:

- пара `Error`/`Result` крейта `dns-lattice-core`, с ручными `Display`/`std::error::Error`
- модули `message` (`Message`, `Header`, `Question`, `ResourceRecord`), `record` (`RecordType`, `Class`, `RData`), `matcher` (`DomainPattern`, `DomainMatcher<T>`) и `policy` (`SplitDnsPolicy`) крейта `dns-lattice-model`
- модуль `engine` фасада `dns-lattice` (`Resolver`, `ResolverBuilder`): создание/резолвинг in-process (асинхронно), статическая split-DNS маршрутизация, failover по зарегистрированным бэкендам группы в порядке регистрации и кэш ответов в памяти с TTL и негативным кэшированием
- модуль `upstream` фасада `dns-lattice` (`UpstreamBackend`, `UdpBackend`, `TcpBackend`): базовые апстрим-транспорты UDP/TCP поверх `tokio`, пока без EDNS0/OPT
- Cargo-фичи `dot`/`doh` модуля `upstream` фасада `dns-lattice` (`DotBackend`, `DohBackend`): транспорты DNS-over-TLS/DNS-over-HTTPS поверх `rustls`/`hyper`, протестированные на loopback-фикстурах TLS/HTTPS с локально сгенерированным самоподписанным сертификатом
- Cargo-фича `doq` модуля `upstream` фасада `dns-lattice` (`DoqBackend`): транспорт DNS-over-QUIC поверх `quinn`/`rustls`, протестированный на loopback-фикстуре QUIC-сервера `quinn` с локально сгенерированным самоподписанным сертификатом
- модуль `server` фасада `dns-lattice` (`Server`, `ServerBuilder`): входящий слушатель UDP/TCP поверх in-process fake-фикстуры `Resolver`, покрывающий резолвинг по обоим транспортам, поведение усечения UDP/`TC=1`, синтез `Rcode::ServFail` при ошибке резолвера и корректное завершение через `serve_until`
- Cargo-фича `dot` модуля `server` фасада `dns-lattice` (`ServerBuilder::dot_addr`): входящий слушатель DNS-over-TLS, протестированный против loopback TLS-клиента с локально сгенерированным самоподписанным сертификатом, покрывающий резолвинг, несколько запросов в одном TLS-соединении и синтез `Rcode::ServFail` при ошибке резолвера
- Cargo-фича `doq` модуля `server` фасада `dns-lattice` (`ServerBuilder::doq_addr`): входящий слушатель DNS-over-QUIC, протестированный против loopback QUIC-клиента `quinn` с локально сгенерированным самоподписанным сертификатом, покрывающий резолвинг, несколько запросов в одном QUIC-соединении (по отдельным потокам) и синтез `Rcode::ServFail` при ошибке резолвера
- Cargo-фича `doh` модуля `server` фасада `dns-lattice`: TCP `ServerBuilder::doh_addr`, сквозным образом протестированный с локально сгенерированным самоподписанным сертификатом для согласованных через ALPN HTTP/1.1 и HTTP/2, и QUIC `ServerBuilder::doh3_addr`, протестированный для HTTP/3 с ALPN `h3`; оба пути покрывают GET и POST, а HTTP/3 также покрывает ответные семантики 400/404 и DNS `SERVFAIL`

Это даёт полностью протестированную модель DNS-сообщений, детерминированный
доменный/зональный матчер, in-process резолвер с реальным
UDP/TCP/DoT/DoH/DoQ апстрим-транспортом и failover по бэкендам группы, а
также встраиваемый входящий слушатель DNS-сервера UDP/TCP/DoT/DoH/DoQ —
всё пригодно для самостоятельного использования уже сегодня. Текущее
состояние разработки также содержит самостоятельный вызываемый пул Fake IP,
описанный выше; он пока не входит в путь запроса резолвера или сервера.

| Возможность | Статус |
|---|:---:|
| Кодирование/декодирование DNS-сообщений | ✅ |
| (Де)компрессия имён при декодировании | ✅ |
| Доменный/зональный матчер (exact/suffix/wildcard) | ✅ |
| Типы статической политики split-DNS | ✅ |
| Движок резолвера / кэш ответов | ✅ |
| Апстрим UDP/TCP | ✅ |
| Апстрим DoT/DoH (Cargo-фичи `dot`/`doh`) | ✅ |
| Апстрим DoQ (Cargo-фича `doq`) | ✅ |
| Failover между апстримами группы | ✅ |
| Входящий слушатель сервера UDP/TCP | ✅ |
| Входящий слушатель сервера DoT (Cargo-фича `dot`) | ✅ |
| Входящий слушатель сервера DoQ (Cargo-фича `doq`) | ✅ |
| Входящий слушатель сервера DoH (Cargo-фича `doh`) | ✅ |
| Пул Fake IP (вызываемый приложением, только данные) | ✅ (разработка 0.4) |
| Динамические хуки маршрутизации | план (0.5) |

## Примеры

Исполняемые исходники в
[`crates/dns-lattice/examples`](crates/dns-lattice/examples) покрывают
доступную сегодня поверхность модели:

| Сценарий | Пример | Покрываемый API |
|---|---|---|
| Разрешение split-DNS политики | [`split_dns_policy`](crates/dns-lattice/examples/split_dns_policy.rs) | `SplitDnsPolicy`, `DomainPattern`, приоритет exact/suffix/wildcard, fallback на группу по умолчанию |
| Wire-round-trip сообщения | [`message_round_trip`](crates/dns-lattice/examples/message_round_trip.rs) | `Message::encode`, `Message::decode`, `Header`, `Question`, `ResourceRecord`, `RData::A` |
| Resolver со split-DNS и кэшем | [`resolver`](crates/dns-lattice/examples/resolver.rs) | `Resolver`, `ResolverBuilder`, in-process fake upstream backends, TTL-кэш ответов, `Error::NoRoute` |

Запустите пример командой `cargo run -p dns-lattice --example <name>`.

## Роадмап

1. **Стадия 0.0: Аудит, роадмап, базовая архитектура** *(завершена)* — аудит репозитория, целевая структура модулей и не-цели.
2. **Стадия 0.1: Базовая модель** *(завершена)* — модель DNS-сообщений, доменный/зональный матчер, типы политики split-DNS, разделение на крейты `dns-lattice-core`/`dns-lattice-model`/`dns-lattice`.
3. **Стадия 0.2: Движок резолвера и статический split DNS** *(завершена)* — точка входа резолвера (создание-резолвинг-остановка), статическая split-DNS маршрутизация, кэш ответов в памяти с негативным кэшированием, фейковый in-process апстрим для детерминированных тестов.
4. **Стадия 0.3: Апстрим-транспорты и слушатель сервера** *(завершена)* — стабилизированный трейт апстрим-бэкенда, базовый UDP/TCP, DoT/DoH/DoQ за Cargo-фичами `dot`/`doh`/`doq`, fallback/failover между апстримами внутри группы и встраиваемый входящий слушатель сервера UDP/TCP/DoT/DoH/DoQ (`Server`/`ServerBuilder`).
5. **Стадия 0.4: Пул Fake IP** *(active)* — вызываемое приложением детерминированное выделение синтетических адресов, обратный поиск и LRU-вытеснение; без неявного переписывания DNS, TTL/истечения или persistence.
6. **Стадия 0.5: Динамические хуки маршрутизации** — стабильный трейт(ы) хука для маршрутизации со стороны вызывающего кода, композиция/приоритет относительно статических правил.
7. **Стадия 0.6: Устойчивость и проверка платформ** — кроссплатформенная CI-матрица, fuzz/property-тесты, sink наблюдаемости, полная синхронизация документации.
8. **Стадия 1.0: Стабильный публичный API и первый релиз** — заморозка публичного API, проверка `cargo package`/docs.rs, первый релиз на crates.io.

Стадии — это границы поставки, а не обещание одного релиза на каждый пункт;
полный список не-целей по стадиям см. в [ROADMAP.ru.md](ROADMAP.ru.md).

## Участие в разработке

Мы рады любому участию. См. [CONTRIBUTING.md](CONTRIBUTING.md) за
руководством, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) за нормами
сообщества и [SECURITY.md](SECURITY.md) за процессом сообщения об
уязвимостях. На этой стадии обратная связь по объёму, дизайну API и
архитектуре — самый ценный вклад.

## Лицензия

Распространяется под [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).
