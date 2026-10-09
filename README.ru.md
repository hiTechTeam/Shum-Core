# Shum Core

[English](README.md) · Русский

Ядро Shum на Rust: криптография, Bluetooth, Nostr и зашифрованное хранилище. Общая реализация протокола для клиентов; интерфейс, аватары и QR рисуют клиенты.

## Состояние

Черновик v1 реализован и сверяется с тестовыми примерами Swift. На macOS с iPhone проверены поиск по Bluetooth, приглашения, сообщения и прочтение. На Linux и Windows есть поиск, но GATT-сервер и приёмка платформ ещё впереди.

Несколько устройств одного профиля, синхронизация истории и релеи профиля входят в будущую v1 stable. Привязки Swift и Kotlin используют UniFFI; переход iOS пока не завершён. План: [Shum Protocol](https://github.com/hiTechTeam/Shum-Protocol).

## Пакеты

У локальных профилей независимые ID, ключи и базы. Отображаемые имена могут совпадать; выбор, открытие и удаление выполняются по ID профиля.

| Пакет | Назначение |
| :--- | :--- |
| `shum-core` | Протокол, криптография и состояние без ввода-вывода |
| `shum-transport-nostr` | Релеи, подписки, доставка и push-запросы |
| `shum-transport-ble` | Поиск, GATT, Noise и Bluetooth-сетка |
| `shum-store` | Зашифрованная SQLite и ключи профилей |

[Shum CLI](https://github.com/hiTechTeam/Shum-CLI) подключает ядро напрямую. Мобильные, десктопные и браузерные клиенты находятся на разных этапах разработки.

## Сборка

Нужен Rust stable; для Bluetooth на macOS также Xcode Command Line Tools.

```sh
git clone --recurse-submodules https://github.com/hiTechTeam/Shum-Core.git
cd Shum-Core
cargo test --workspace --locked --all-features
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Клиент закрепляет одну Git-ревизию для всех четырёх пакетов. Совместимость закреплена через submodule `protocol/`. Разделы 01–09 и их примеры описывают текущий черновик; разделы 10–12 относятся к будущей v1 stable.

Строгая проверка Ed25519 и отклонение повторов Noise согласованы как отличия от Swift. Проверки с настоящей сетью и системной связкой ключей исключены из обычного запуска. CI запускается вручную.

## Документация

[API ядра](docs/core-api.md) · [Хранилище](docs/storage.md) · [Протокол и примеры](https://github.com/hiTechTeam/Shum-Protocol) · [Issues](https://github.com/hiTechTeam/Shum-Core/issues)

## Лицензия

[MIT](LICENSE), copyright 2026 hiTechTeam.
