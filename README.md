# Shum Core

Ядро мессенджера Shum на Rust: протокол, криптография, транспорты Bluetooth и
Nostr, хранилище на устройстве. Одна реализация протокола для всех клиентов.

Контракт совместимости: спецификация и тестовые примеры из
[Shum-Protocol](https://github.com/hiTechTeam/Shum-Protocol). Ревизия
спецификации закреплена в папке `protocol/` через git submodule. Текущая
ревизия документации: `8e02c9d`; примеры и байты черновика v1 не изменились.
Разделы 10–12 описывают будущую v1 stable, а не уже доступные функции ядра.

## Состояние

- Черновик v1 протокола и хранилище реализованы и сверены со Swift побайтно.
- На macOS Bluetooth проверен с настоящим iPhone: поиск, приглашение,
  сообщения в обе стороны, отметки прочтения.
- На Linux и Windows есть поиск устройств, но компьютер пока не объявляет себя
  рядом (нет GATT-сервера). Проверки на этих системах не завершены.
- Несколько устройств одного профиля, синхронизация и релеи профиля (части
  первой стабильной версии) ещё не реализованы. План:
  [Shum-Protocol, раздел 12](https://github.com/hiTechTeam/Shum-Protocol/blob/main/spec/12-v1-stable.md).
- Начальные привязки для Swift и Kotlin через UniFFI собираются, API состояния
  ещё формируется.

## Пакеты

| Пакет | Что делает |
|---|---|
| `shum-core` | протокол, криптография и состояние, без ввода-вывода |
| `shum-transport-nostr` | релеи, подписки, доставка через Nostr, запросы к push-серверу |
| `shum-transport-ble` | поиск, объявление себя, GATT, Noise и сетка Bitchat |
| `shum-store` | совместимая с iOS база SQLite, шифрование, ключи профилей |

## Клиенты

| Клиент | Как подключает ядро | Состояние |
|---|---|---|
| [Shum-CLI](https://github.com/hiTechTeam/Shum-CLI) | Rust, напрямую | превью для macOS |
| iOS | UniFFI, Swift | планируется переход с текущей реализации на Swift |
| Android | UniFFI, Kotlin | планируется |
| Десктоп macOS, Windows, Linux | Rust, напрямую | планируется |
| Браузер | WebAssembly | планируется |

## Принципы

- **Без ввода-вывода внутри протокола.** Время, случайные байты, сеть, файлы и
  выполнение действий предоставляет клиент. Ядро возвращает действия, клиент
  их исполняет. Пример: [docs/core-api.md](docs/core-api.md).
- **Интерфейс в клиентах.** Аватары, QR, цвета, окна и форматирование терминала
  принадлежат клиентам. Ядро знает только подписываемые поля аватара
  (seed, version, hash, size) и проверяет их смысл.
- **Совместимость доказывается примерами.** Каждое поведение проверяется
  тестовыми примерами, снятыми со Swift. Где Swift ведёт себя неправильно,
  отличие записано в спецификации как решение владельца.

## Криптография и совместимость

- Ключи: `ed25519-dalek` 2.2 (строгая проверка `verify_strict`), `x25519-dalek`
  2.0, `secp256k1` 0.31 (BIP-340 и исходная точка ECDH).
- ChaCha20-Poly1305, SHA-256, HMAC и HKDF из RustCrypto. Версии закреплены в
  `Cargo.lock`.
- `Secret32` не печатается и не сериализуется, очищается через zeroize. Это не
  обещание очистки копий внутри внешних библиотек.
- Канонический JSON написан отдельно и повторяет `JSONEncoder` Apple: порядок
  ключей и экранирование. serde используется только для разбора и моделей.
- Обрезка пробелов в имени повторяет набор Foundation (`card.rs`), проверено
  Swift-примером на всех 26 символах.
- DEFLATE через `flate2` с zlib: поток `zlib-rs` отличается от Apple Compression
  и меняет подписываемые байты.
- Согласованные отличия от Swift (8 октября 2026): вырожденные подписи Ed25519
  отклоняются, окно повторов Noise работает правильно, без ошибки Swift.

## Сборка и проверка

Нужен Rust stable (версия задана в `rust-toolchain.toml`). Сборка Bluetooth на
macOS использует Xcode Command Line Tools.

```sh
git clone --recurse-submodules https://github.com/hiTechTeam/Shum-Core.git
cd Shum-Core
cargo test --workspace --locked --all-features
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Для уже скачанной копии: `git submodule update --init --recursive`.
Проверки с настоящей сетью и системной Связкой ключей исключены из обычного
запуска.

Привязки UniFFI: `cargo check -p shum-core --features uniffi`.

## Подключение в клиенте

Клиент закрепляет одну ревизию этого репозитория для всех пакетов:

```toml
[dependencies]
shum-core = { git = "https://github.com/hiTechTeam/Shum-Core.git", rev = "<commit>" }
shum-transport-nostr = { git = "https://github.com/hiTechTeam/Shum-Core.git", rev = "<commit>" }
shum-transport-ble = { git = "https://github.com/hiTechTeam/Shum-Core.git", rev = "<commit>" }
shum-store = { git = "https://github.com/hiTechTeam/Shum-Core.git", rev = "<commit>" }
```

Переход клиента на новую ревизию ядра выполняется отдельно от выпуска клиента.

## Документация

- [docs/core-api.md](docs/core-api.md): API и пример транзакции.
- [docs/storage.md](docs/storage.md): хранилище, миграция, блокировки.
- [Shum-Protocol](https://github.com/hiTechTeam/Shum-Protocol): спецификация и
  тестовые примеры.

## CI

Автоматический запуск выключен. Ручной workflow проверяет форматирование, тесты
и Clippy на macOS, Linux и Windows, с той ревизией протокола, что закреплена в
submodule.

## Вопросы и предложения

Ошибки и предложения по ядру присылайте через Issues этого репозитория,
вопросы по протоколу в [Shum-Protocol](https://github.com/hiTechTeam/Shum-Protocol/issues).

## Лицензия

[MIT](LICENSE), copyright 2026 hiTechTeam.
