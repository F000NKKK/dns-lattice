# DNS Lattice

Программируемый DNS control plane на Rust для сетевого стека Lattice: split DNS, Fake IP, пулы адресов и динамические хуки маршрутизации.

## Статус

**Пре-релиз.** Служебная инфраструктура, политики и упаковка перенесены из
[net-lattice](https://github.com/F000NKKK/net-lattice) — первого крейта
экосистемы Lattice. Стадия 0.1 (базовая модель) уже реализовала модель
DNS-сообщений, доменный/зональный матчер и политики split-DNS. Версии
`0.1.0` трёх крейтов ниже опубликованы, чтобы зарезервировать их имена на
crates.io; стабильного публичного API пока нет, версия фасадного крейта
увеличивается по одному разу за каждую завершённую стадию роадмапа.

## Крейты workspace

Workspace разделён на сфокусированные крейты, по аналогии со структурой
`net-lattice`. У каждого крейта есть собственный README со своей областью
ответственности и примером использования:

| Крейт | Назначение |
| --- | --- |
| [`dns-lattice`](crates/dns-lattice/README.md) | Публичный фасад: реэкспортирует крейты ниже как стабильную поверхность |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | Модель DNS-сообщений, доменный/зональный матчер и политики split-DNS |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Общие типы `Error`/`Result` |

Что должна добавить каждая последующая стадия (сервер, резолвер, апстрим-транспорты, Fake IP, динамические хуки маршрутизации) — см. `ROADMAP.ru.md`.

## Экосистема Lattice

| Крейт | Назначение |
| --- | --- |
| [net-lattice](https://github.com/F000NKKK/net-lattice) | Инспекция и настройка сетевого стека ОС (маршруты, DNS, интерфейсы) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP туннельные интерфейсы |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Программируемый DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Компилятор политик: правила -> платформенно-нейтральные сетевые планы |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Прикладной SDK, объединяющий крейты выше |

## Участие в разработке

См. [CONTRIBUTING.md](CONTRIBUTING.md). На этой стадии наиболее ценна обратная
связь по объёму и направлению API.

## Лицензия

Распространяется под [Mozilla Public License 2.0](LICENSE).
