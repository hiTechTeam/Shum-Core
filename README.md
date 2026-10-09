# Shum Core

Общее ядро Shum на Rust и адаптеры транспорта и хранилища. Контракт
совместимости: iOS 1.0 и Swift-примеры из
[Shum-Protocol](https://github.com/hiTechTeam/Shum-Protocol).

CLI вынесен в отдельный [Shum-CLI](https://github.com/hiTechTeam/Shum-CLI).
Команды, TUI, аватары, системная служба, установка и упаковка находятся там.
Shum-Core не зависит от CLI. Версии и релизы репозиториев независимы.

## Структура

| Пакет | Ответственность |
|---|---|
| `shum-core` | Протокол, криптография и состояние без ввода-вывода |
| `shum-transport-nostr` | Релеи, подписки, доставка Nostr и push-запросы |
| `shum-transport-ble` | Поиск, объявления, GATT, Noise и сетка Bitchat |
| `shum-store` | Совместимая SQLite-база, шифрование и ключи профилей |

Ядро v1 и хранилище реализованы. На macOS BLE проверен с реальным iPhone.
На Linux/Windows пока есть central-адаптер без GATT-сервера; проверка на
настоящих ОС не завершена. Протокол устройств v2 не реализован.

`protocol/` закрепляет конкретный коммит спецификации через git submodule.
Интерфейс UniFFI предусмотрен отдельной feature `uniffi` и типами сборки
`staticlib`/`cdylib`; начальные привязки уже компилируются, API состояния будет дополняться при подключении клиентов.
Ядро получает время и случайные байты от клиента, само их не запрашивает.

Аватары, QR, цвета, форматирование терминала и окна относятся к клиентам.
Генератор пикселей v1 и его Swift-тесты находятся в отдельном
[Shum-CLI](https://github.com/hiTechTeam/Shum-CLI).
Ядро знает только подписываемые поля seed/version/hash/size и проверяет их
протокольный смысл. Декодирование изображений и подготовка фото также
принадлежат клиенту. Это уточнение заменяет первоначальное размещение
генератора аватаров в ядре.

Для ключей выбраны `ed25519-dalek` 2.2, `x25519-dalek` 2.0 и `secp256k1`
0.31 (libsecp256k1: BIP-340 и доступ к исходной ECDH-точке). Dalek даёт
явную строгую проверку, X25519 использует фиксированные ключи от вызывающей
стороны. `Secret32` не реализует Debug/Serialize и очищается через zeroize;
это не обещание очистки всех копий внутри внешних библиотек.
ChaCha20-Poly1305, SHA-256/HMAC/HKDF используют RustCrypto. Версии закреплены
в Cargo.lock, byte-level совместимость проверяется примерами Swift.

Canonical JSON написан отдельно, serde используется для разбора и моделей.
Графемы считает unicode-segmentation, NFC для BLE-профилей выполняет
unicode-normalization. Пример API транзакций: [docs/core-api.md](docs/core-api.md).
Набор Foundation-пробелов зафиксирован в `card.rs`
и проверен Swift-примером всех 26 scalar. Вопрос о строгом отклонении
вырожденных Ed25519-подписей и о replay-ошибке Swift записан в спецификации;
оба исключения совместимости согласованы владельцем 8 октября 2026.

DEFLATE использует flate2 с backend zlib: поток zlib-rs отличается от Apple
Compression и меняет signing bytes. Точные потоки и подписи проверены на
macOS; межплатформенная проверка остаётся частью отключённого CI.

Feature `uniffi` включает настоящий scaffolding и начальные функции для
Swift/Kotlin: проверка карточки, разбор приглашения, canonical packet и
открытие envelope. `cargo check -p shum-core --features uniffi` проходит.
Полный API состояния ещё формируется; xcframework и iOS-приложение не меняются.
[UniFFI](https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html),
[строгая Ed25519-проверка](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html).

Хранилище, миграция, блокировки и команды проверки: [docs/storage.md](docs/storage.md).
Проверки Linux/Windows ещё не выполнены.

## Получение исходников и проверка

Оба репозитория приватные, нужен доступ к Shum-Core и Shum-Protocol.

```sh
git clone --recurse-submodules https://github.com/hiTechTeam/Shum-Core.git
cd Shum-Core
cargo test --workspace --locked --all-features
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Для существующей копии: `git submodule update --init --recursive`.
Проверки сети и системного Keychain исключены из обычного запуска.
Сборка BLE на macOS использует Xcode Command Line Tools (`xcrun swiftc`).

## CI

Автоматический CI отключён по просьбе владельца. Ручной workflow проверяет
форматирование, тесты и Clippy на macOS, Linux и Windows. Read-only ключ для
приватного Shum-Protocol хранится в Actions secret `PROTOCOL_DEPLOY_KEY`.
Workflow получает ровно ту ревизию протокола, которая закреплена в submodule.

## Подключение клиента

Клиент закрепляет одну ревизию этого репозитория для всех четырёх пакетов:

```toml
[dependencies]
shum-core = { git = "https://github.com/hiTechTeam/Shum-Core.git", rev = "<commit>" }
```

Время, случайность, ввод-вывод и исполнение действий предоставляет клиент.
Переход на новую ревизию ядра выполняется отдельно от выпуска клиента.
