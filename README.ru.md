# DNS Lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## Статус

**Пре-релиз.** Служебная инфраструктура, политики и упаковка перенесены из
[net-lattice](https://github.com/F000NKKK/net-lattice) — первого крейта
экосистемы Lattice. Стадия 0.1 (базовая модель) уже реализовала модель
DNS-сообщений, доменный/зональный матчер и политики split-DNS. Стабильного
публичного API пока нет, релизов не публиковалось.

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
