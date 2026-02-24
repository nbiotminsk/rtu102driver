# RTU102 UDP Receiver (Python + PHP + Node.js)

Проект содержит три реализации приёмника данных от TELEOFIS RTU102 (NB-IoT, протокол RTU):

- Python: [python_receiver/README.md](/Users/nikolaj/Projects/RTU102_driver/python_receiver/README.md)
- PHP: [php_receiver/README.md](/Users/nikolaj/Projects/RTU102_driver/php_receiver/README.md)
- Node.js: [node_receiver/README.md](/Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver/README.md)

Все реализации работают в режиме `receive-only`:

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
- [node_receiver](/Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver) — Node.js сервер.

## Где указывать IMEI и ключ шифрования

Конфиг (одинаковая структура для Python/PHP/Node.js):

- Python: [python_receiver/config/receiver.example.json](/Users/nikolaj/Projects/RTU102_driver/python_receiver/config/receiver.example.json)
- PHP: [php_receiver/config/receiver.example.json](/Users/nikolaj/Projects/RTU102_driver/php_receiver/config/receiver.example.json)
- Node.js: [node_receiver/config/receiver.example.json](/Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver/config/receiver.example.json)

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

## Что вводить в конфигураторе устройства (поле `Ключ`)

В поле `Ключ` вводится XTEA-ключ:

- ровно `32` hex-символа,
- без пробелов,
- без префикса `0x`.

Пример:

```text
4f9c2d0ab3e17c55a8d2f0b19c6e4a73
```

Порядок:

1. Сгенерировать ключ: `openssl rand -hex 16`.
2. Вставить его в конфигуратор устройства и нажать `Установить`.
3. Этот же ключ указать на сервере в `keys.by_imei["IMEI"]` (или `keys.default_hex`).

Если ключ на устройстве и сервере отличается хотя бы на один символ, расшифровка не пройдет (ошибки CRC/decode).

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

## Быстрый старт: Node.js

Требования: Node.js `22+`.

```bash
cd /Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver
npm install
node ./bin/receiver.js --config ./config/receiver.example.json
```

Режим одного пакета:

```bash
node ./bin/receiver.js --config ./config/receiver.example.json --once --log-level debug
```

## Node.js на сервере (24/7 приём показаний)

1. Проверить Node.js:

```bash
node -v
```

Нужен `v22.x`.

2. Развернуть приложение:

```bash
sudo mkdir -p /opt/rtu102
sudo cp -R /Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver /opt/rtu102/
cd /opt/rtu102/node_receiver
npm install --omit=dev
```

3. Создать боевой конфиг `/opt/rtu102/node_receiver/config/receiver.json`:

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 5000,
  "log_dir": "/var/log/rtu102",
  "decode_enabled": true,
  "keys": {
    "default_hex": null,
    "by_imei": {
      "863703030668235": "ВАШ_32_HEX_КЛЮЧ"
    }
  }
}
```

4. Подготовить пользователя и логи:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rtu || true
sudo mkdir -p /var/log/rtu102
sudo chown -R rtu:rtu /var/log/rtu102 /opt/rtu102/node_receiver
```

5. Установить и запустить сервис:

```bash
sudo cp /opt/rtu102/node_receiver/systemd/rtu102-node-receiver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rtu102-node-receiver
```

6. Открыть UDP-порт:

```bash
sudo ufw allow 5000/udp
```

Также откройте `5000/udp` в cloud firewall/security group.

7. Проверить работу:

```bash
sudo systemctl status rtu102-node-receiver
journalctl -u rtu102-node-receiver -f
```

## Логи

Все реализации пишут в `log_dir` три потока:

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
- [node_receiver/systemd/rtu102-node-receiver.service](/Users/nikolaj/Projects/RTU102_driver/rtu102driver/node_receiver/systemd/rtu102-node-receiver.service)
