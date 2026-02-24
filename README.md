# RTU102 UDP Receiver (Python + PHP)

Проект содержит две реализации приёмника данных от TELEOFIS RTU102 (NB-IoT, протокол RTU):

- Python: [python_receiver/README.md](/Users/nikolaj/Projects/RTU102_driver/python_receiver/README.md)
- PHP: [php_receiver/README.md](/Users/nikolaj/Projects/RTU102_driver/php_receiver/README.md)

Обе реализации работают в режиме `receive-only`:

- принимают UDP datagram,
- проверяют кадр `0xC0 ... 0xC2`, байт-стаффинг,
- извлекают IMEI,
- расшифровывают XTEA,
- проверяют CRC16,
- пишут логи в JSONL,
- не отправляют ACK/команды устройству.

## Структура

- [RTU102_NBIOT_LLM_GUIDE.md](/Users/nikolaj/Projects/RTU102_driver/RTU102_NBIOT_LLM_GUIDE.md) — подробное описание протокола и практики.
- [python_receiver](/Users/nikolaj/Projects/RTU102_driver/python_receiver) — Python сервер.
- [php_receiver](/Users/nikolaj/Projects/RTU102_driver/php_receiver) — PHP сервер.

## Где указывать IMEI и ключ шифрования

Конфиг (одинаковая структура для Python/PHP):

- Python: [python_receiver/config/receiver.example.json](/Users/nikolaj/Projects/RTU102_driver/python_receiver/config/receiver.example.json)
- PHP: [php_receiver/config/receiver.example.json](/Users/nikolaj/Projects/RTU102_driver/php_receiver/config/receiver.example.json)

Фрагмент:

```json
{
  "keys": {
    "default_hex": null,
    "by_imei": {
      "863703030668235": "4f9c2d0ab3e17c55a8d2f0b19c6e4a73"
    }
  }
}
```

- ключ словаря `by_imei` — это IMEI (строка),
- значение — XTEA ключ в hex,
- длина ключа: `32` hex символа (`16` байт).

Важно: ключ в конфигураторе устройства и ключ на сервере должны совпадать.

## Как генерировать ключ

Используйте криптографически случайный ключ:

```bash
openssl rand -hex 16
```

Не используйте предсказуемые ключи (даты, IMEI, шаблоны вида `1111...`).

Рекомендуется отдельный ключ для каждого IMEI.

## Быстрый старт: Python

Требования: Python `3.12+`.

```bash
cd /Users/nikolaj/Projects/RTU102_driver/python_receiver
python3 -m pip install --user -e .
python3 -m rtu_receiver --config ./config/receiver.example.json
```

Режим одного пакета:

```bash
python3 -m rtu_receiver --config ./config/receiver.example.json --once --log-level debug
```

## Быстрый старт: PHP

Требования: PHP `8.3+`, `ext-sockets`, Composer.

```bash
cd /Users/nikolaj/Projects/RTU102_driver/php_receiver
composer install
php bin/receiver.php --config ./config/receiver.example.json
```

Режим одного пакета:

```bash
php bin/receiver.php --config ./config/receiver.example.json --once --log-level debug
```

## Логи

Обе реализации пишут в `log_dir` три потока:

- `raw-YYYYMMDD.jsonl`
- `decoded-YYYYMMDD.jsonl`
- `errors-YYYYMMDD.jsonl`

## cPanel: что реально работает

- Shared cPanel обычно не подходит для такого сервиса (нет `systemd`, ограничения на постоянные процессы и UDP-сокеты).
- VPS с cPanel и root-доступом подходит.
- Для внешнего приёма от устройства:
  - ставьте `listen_host: "0.0.0.0"`,
  - откройте UDP-порт в firewall/security group.

## systemd

Примеры unit-файлов:

- [python_receiver/systemd/rtu102-python-receiver.service](/Users/nikolaj/Projects/RTU102_driver/python_receiver/systemd/rtu102-python-receiver.service)
- [php_receiver/systemd/rtu102-php-receiver.service](/Users/nikolaj/Projects/RTU102_driver/php_receiver/systemd/rtu102-php-receiver.service)
