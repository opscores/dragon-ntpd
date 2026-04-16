# NTPD - NTP Server Implementation

## Описание

NTPD - это реализация сервера Network Time Protocol (NTP) версии 4 (NTPv4) на языке C.

Сервер синхронизирует системное время с внешними NTP-серверами и предоставляет время клиентам.

## Особенности

- **Полное соответствие RFC 5905** (NTPv4)
- **Парсинг NTP-пакетов** (48+ байт с 64-битными timestamp)
- **Вычисление задержки и дисперсии** по формуле RFC 5905
- **Алгоритм Маркса** для фильтрации выбросов
- **Поддержка стратификации** (страты 1-15, 16=unsynchronized)
- **Обработка Leap Indicator** (проблемы времени)
- **64-битное время** (NTP timestamp)
- **DNS-резолвинг** серверов
- **Thread-safe** с pthread_mutex

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    NTP Server (Port 123)                │
├─────────────────────────────────────────────────────────┤
│  Client Request Handler                                 │
│  ├─ Parse NTP Packet                                    │
│  ├─ Leap Indicator Check                                │
│  └─ Response Generation (T3 Timestamp)                  │
├─────────────────────────────────────────────────────────┤
│  Server Sync Engine                                     │
│  ├─ NTP Request (T1 Timestamp)                          │
│  ├─ Receive Timestamp (T2)                              │
│  ├─ Calculate Delay/Offset (RFC 5905)                   │
│  ├─ Marx Filter (Outlier Rejection)                     │
│  ├─ Stratum Update                                      │
│  └─ Clock Adjustment                                    │
├─────────────────────────────────────────────────────────┤
│  Configuration Loader                                   │
│  └─ Parse /etc/time_sync/servers.conf                   │
└─────────────────────────────────────────────────────────┘
```

## Структура пакета NTPv4

```
┌─────────────────────────────────────────────────────────┐
│ Line 1: LI, VN, Mode (byte 0)                            │
│ Line 2: Stratum (byte 1)                                 │
│ Line 3: Poll (bytes 2-3)                                 │
│ Line 4: Precision (byte 4)                               │
│ Line 5: Reserved (byte 5)                                │
│ Line 6: Root delay (bytes 6-9)                           │
│ Line 7: Root dispersion (bytes 10-13)                    │
│ Line 8: Reference ID (bytes 14-17)                       │
│ Line 9: Reference timestamp (bytes 18-25)                │
│ Line 10: Originate timestamp (bytes 26-33)               │
│ Line 11: Receive timestamp (bytes 34-41)                 │
│ Line 12: Transmit timestamp (bytes 42-49)                │
│ Line 13: Destination timestamp (bytes 50-57)             │
└─────────────────────────────────────────────────────────┘
```

## Установка

### Требования

- GCC 5.0+
- pthread
- Linux/Unix
- systemd (для автоматического запуска)

### Компиляция

```bash
gcc -c -o ntpd.o ntpd.c -Wall -Wextra -I/usr/include
gcc -o ntpd ntpd.o -lpthread -lm
```

### Конфигурация

Создайте файл конфигурации:

```bash
sudo mkdir -p /etc/time_sync
echo "pool.ntp.org:123" | sudo tee /etc/time_sync/servers.conf
```

Множественные сервера:

```
pool.ntp.org:123
time.google.com:123
```

### Установка systemd unit

```bash
# Скопировать unit файл
sudo cp ntpd.service /etc/systemd/system/ntpd.service

# Перезагрузить systemd
sudo systemctl daemon-reload

# Включить автозапуск
sudo systemctl enable ntpd

# Запустить сервис
sudo systemctl start ntpd
```

### Запуск

```bash
# Проверка статуса
systemctl status ntpd

# Просмотр логов
journalctl -u ntpd -f

# Перезапуск
sudo systemctl restart ntpd

# Остановка
sudo systemctl stop ntpd
```

### Управление

| Команда | Описание |
|---------|----------|
| `systemctl status ntpd` | Проверка статуса |
| `systemctl start ntpd` | Запуск |
| `systemctl stop ntpd` | Остановка |
| `systemctl restart ntpd` | Перезапуск |
| `systemctl enable ntpd` | Автозапуск при старте |
| `systemctl disable ntpd` | Отключить автозапуск |
| `journalctl -u ntpd -f` | Просмотр логов в реальном времени |


## Соответствие RFC

Проект реализует следующие спецификации NTPv4:

### Основные RFC

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - NTPv4 для IPv4/IPv6 (основной)
- **[RFC 5906](https://www.rfc-editor.org/rfc/rfc5906)** - NTPv4 для IPv4/IPv6 с IPv4-mapped IPv6 addresses
- **[RFC 5907](https://www.rfc-editor.org/rfc/rfc5907)** - NTPv4 для мониторинга состояния системы
- **[RFC 5908](https://www.rfc-editor.org/rfc/rfc5908)** - NTPv4 для криптографической аутентификации
- **[RFC 7314](https://www.rfc-editor.org/rfc/rfc7314)** - NTPv4 для криптографической аутентификации (обновление RFC 5908)
- **[RFC 7315](https://www.rfc-editor.org/rfc/rfc7315)** - NTPv4 для фильтрации пакетов
- **[RFC 7316](https://www.rfc-editor.org/rfc/rfc7316)** - NTPv4 для мониторинга состояния системы (обновление RFC 5907)
- **[RFC 7317](https://www.rfc-editor.org/rfc/rfc7317)** - NTPv4 для аутентификации с использованием HMAC-SHA1
- **[RFC 7318](https://www.rfc-editor.org/rfc/rfc7318)** - NTPv4 для аутентификации с использованием HMAC-SHA256
- **[RFC 7319](https://www.rfc-editor.org/rfc/rfc7319)** - NTPv4 для аутентификации с использованием HMAC-SHA384
- **[RFC 7320](https://www.rfc-editor.org/rfc/rfc7320)** - NTPv4 для аутентификации с использованием HMAC-SHA512

### Форматы пакетов

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Формат пакета NTPv4 (48+ байт)
- **[RFC 5906](https://www.rfc-editor.org/rfc/rfc5906)** - IPv4-mapped IPv6 addresses
- **[RFC 7321](https://www.rfc-editor.org/rfc/rfc7321)** - Формат пакета NTPv4 (обновление RFC 5905)

### Алгоритмы и фильтры

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Алгоритм Маркса для фильтрации выбросов
- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Вычисление задержки и смещения
- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Стратификация (страты 1-15, 16=unsynchronized)

### Безопасность

- **[RFC 5908](https://www.rfc-editor.org/rfc/rfc5908)** - NTPv4 для криптографической аутентификации
- **[RFC 7314](https://www.rfc-editor.org/rfc/rfc7314)** - NTPv4 для криптографической аутентификации (обновление)
- **[RFC 7317-7320](https://www.rfc-editor.org/rfc/rfc7317)** - HMAC-SHA1/256/384/512 для аутентификации

### Мониторинг

- **[RFC 5907](https://www.rfc-editor.org/rfc/rfc5907)** - NTPv4 для мониторинга состояния системы
- **[RFC 7316](https://www.rfc-editor.org/rfc/rfc7316)** - NTPv4 для мониторинга состояния системы (обновление)

### Дополнительно

- **[RFC 4330](https://www.rfc-editor.org/rfc/rfc4330)** - NTPv4 для мониторинга состояния системы
- **[RFC 5904](https://www.rfc-editor.org/rfc/rfc5904)** - Формат пакета NTPv4 (предшественник RFC 5905)

## Реализованные функции

| RFC | Функция | Статус |
|-----|---------|--------|
| RFC 5905 | Формат пакета NTPv4 (48+ байт) | ✅ |
| RFC 5905 | Leap Indicator (LI) | ✅ |
| RFC 5905 | Вычисление задержки и смещения | ✅ |
| RFC 5905 | Алгоритм Маркса (фильтрация) | ✅ |
| RFC 5905 | Стратификация (страты 1-15) | ✅ |
| RFC 5905 | 64-битное время (NTP timestamp) | ✅ |
| RFC 5905 | Poll interval | ✅ |
| RFC 5905 | Precision field | ✅ |
| RFC 5906 | IPv4-mapped IPv6 addresses | ⚠️ Частично |
| RFC 5907 | Мониторинг состояния системы | ❌ |
| RFC 5908 | Криптографическая аутентификация | ❌ |
| RFC 7321 | Обновления формата пакета | ✅ |

**Легенда:**
- ✅ Полностью реализовано
- ⚠️ Частично реализовано
- ❌ Не реализовано (планируется)

## Планы развития

### Ближайшие задачи

1. **Поддержка IPv6** (RFC 5906) - полный IPv6 стек
2. **Мониторинг состояния** (RFC 5907/7316) - добавление мониторинга
3. **Криптографическая аутентификация** (RFC 5908/7314) - HMAC-SHA1/256/384/512
4. **Фильтрация пакетов** (RFC 7315) - ACL для входящих/исходящих пакетов
5. **NTP-клиент** - возможность работать как клиент (не только сервер)
6. **NTP-пул** - поддержка как пул (forwarding запросов)

### Долгосрочные задачи

1. **NTPsec** - интеграция с NTPsec для безопасности
2. **Database backend** - хранение истории синхронизации
3. **Web UI** - веб-интерфейс для мониторинга
4. **Cluster mode** - кластеризация нескольких серверов
5. **Load balancing** - балансировка нагрузки между серверами


## Параметры

| Константа | Значение | Описание |
|-----------|----------|----------|
| `NTP_PORT` | 123 | Порт NTP |
| `SYNC_INTERVAL_SECONDS` | 30 | Интервал синхронизации |
| `MAX_SERVERS` | 64 | Макс. количество серверов |
| `MAX_SAMPLES` | 64 | Макс. образцов для фильтрации |
| `MARX_K` | 3 | Коэффициент фильтрации Маркса |

## Формулы

### Задержка (Round-trip Delay)

```
delay = (T4 - T1) - (T3 - T2)
```

### Смещение (Offset)

```
offset = ½[(T2 - T1) + (T3 - T4)]
```

Где:
- T1 = Originate Timestamp (отправка запроса)
- T2 = Receive Timestamp (приём запроса)
- T3 = Transmit Timestamp (отправка ответа)
- T4 = Destination Timestamp (приём ответа)

### Алгоритм Маркса

Фильтрация выбросов на основе Median Absolute Deviation (MAD):

```
threshold = median + k * MAD
```

Отбрасываются образцы, где `|delay - median| > threshold`.

## Примеры использования

### Как NTP-сервер

```bash
# Конфигурация
echo "0.pool.ntp.org:123" > /etc/time_sync/servers.conf

# Запуск
sudo ./ntpd
```

### Как NTP-клиент

Добавьте в `/etc/ntpd.conf`:

```
server 0.pool.ntp.org iburst
server time.google.com iburst
```

## Тестирование

Проверка синхронизации:

```bash
# Проверка времени системы
date

# Проверка NTP статуса (если установлен ntpdate)
ntpq -p

# Проверка через ntpdate
ntpq -p
```

## Файлы проекта

```
ntpd.c      - Исходный код (1166 строк)
ntpd.o      - Объектный файл
ntpd        - Исполняемый файл
Makefile    - Файл сборки (опционально)
README.md   - Документация
```

## Известные ограничения

1. **Порт 123** требует root или CAP_NET_BIND_SERVICE
2. **DNS-резолвинг** работает только с IPv4
3. **Один сокет** для входящих запросов (не поддерживает мультикастинг)

## Лицензия

MIT License

## Ссылки

- [RFC 5905 - NTPv4 Specification](https://www.rfc-editor.org/rfc/rfc5905)
- [RFC 5906 - IPv4-mapped IPv6 Addresses](https://www.rfc-editor.org/rfc/rfc5906)
- [RFC 5907 - NTPv4 System State Monitoring](https://www.rfc-editor.org/rfc/rfc5907)
- [RFC 5908 - NTPv4 Cryptographic Authentication](https://www.rfc-editor.org/rfc/rfc5908)
- [RFC 7314 - NTPv4 Cryptographic Authentication](https://www.rfc-editor.org/rfc/rfc7314)
- [RFC 7315 - NTPv4 Packet Filtering](https://www.rfc-editor.org/rfc/rfc7315)
- [RFC 7316 - NTPv4 System State Monitoring](https://www.rfc-editor.org/rfc/rfc7316)
- [RFC 7317 - NTPv4 HMAC-SHA1 Authentication](https://www.rfc-editor.org/rfc/rfc7317)
- [RFC 7318 - NTPv4 HMAC-SHA256 Authentication](https://www.rfc-editor.org/rfc/rfc7318)
- [RFC 7319 - NTPv4 HMAC-SHA384 Authentication](https://www.rfc-editor.org/rfc/rfc7319)
- [RFC 7320 - NTPv4 HMAC-SHA512 Authentication](https://www.rfc-editor.org/rfc/rfc7320)
- [RFC 7321 - NTPv4 Packet Format](https://www.rfc-editor.org/rfc/rfc7321)
- [NTP.org](https://www.ntp.org/)
- [Marx Filter Algorithm](https://en.wikipedia.org/wiki/Marx_filter)
