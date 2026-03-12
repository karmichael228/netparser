# NetParser Pro

Инструмент для анализа PCAP-файлов с веб-интерфейсом, интерактивным графом связей и экспортом простого HTML-отчета.

## Что умеет

- Анализ одного PCAP-файла и сравнение двух файлов.
- Проверка IP по blacklist (Ipsum).
- Дэшборд с метриками, DNS/HTTP/TLS деталями и поиском по `IP / ASN / DNS`.
- Отдельная страница графа `/graph`:
  - клик по узлу -> информация о хосте;
  - клик по ребру -> информация о трафике между хостами;
  - стрелки направления соединений;
  - отдельный цвет для DNS-серверов.
- Экспорт простого HTML-отчета (без анимаций) как дополнения к другим проверкам:
  - через CLI (`--html`);
  - через веб-кнопку `Экспорт HTML`.

## Быстрый старт

### Установка

```bash
pip install -r requirements.txt
```

### Запуск веба

```bash
python app.py
```

Откройте: `http://localhost:5000`

## CLI

### Базовый анализ

```bash
python main.py traffic.pcap
```

### Генерация отчетов (JSON/TXT/HTML)

```bash
python main.py traffic.pcap --json results.json --txt results.txt --html report.html
```

### Сравнение двух PCAP

```bash
python main.py base.pcap --compare compare.pcap --json diff.json --html diff_report.html
```

### Настройка потоков

```bash
python main.py traffic.pcap --threads 8
```

### Важно по аргументам

В текущей версии нет коротких флагов `-o`, `-f`, `-b`, `-c`.  
Используйте позиционный аргумент `pcap_file` и длинные опции:

- `--json`
- `--txt`
- `--html`
- `--compare`
- `--threads`
- `--check-blacklists` / `--no-check-blacklists`

## Веб-интерфейс

### Страницы

- `/` — дэшборд: загрузка PCAP, метрики, анализ IP, DNS/HTTP/TLS.
- `/graph` — интерактивный граф связей.

### Поиск в дэшборде

Поле поиска в списке IP поддерживает:

- IP-адреса;
- ASN;
- DNS-имена/домены.

### Экспорт HTML-отчета в вебе

После анализа в верхней панели доступна кнопка `Экспорт HTML`.  
Экспорт выполняется через `GET /api/export-report` и скачивает файл отчета как вложение.

## HTML-отчеты

Формат отчета — простой и статичный (без анимаций), ориентирован на удобное чтение и архивирование.

Отчет включает:

- сводку по захвату;
- блоки по каждому IP;
- Traffic / Protocols / Connections;
- DNS / HTTP / TLS данные;
- raw JSON-блок для детального разбора.

Типовые файлы в веб-режиме:

- `static/data/analysis_report.html`
- `static/data/comparison_report.html`

## Структура проекта

```text
netparser/
├── app.py
├── main.py
├── netparser.py
├── utils.py
├── requirements.txt
├── static/
│   ├── css/
│   │   ├── dashboard.css
│   │   └── graph.css
│   ├── js/
│   │   ├── dashboard.js
│   │   └── graph.js
│   └── data/
└── templates/
    ├── dashboard.html
    └── graph.html
```

## Технологии

- Backend: `Flask`, `Scapy`
- Frontend: `Bootstrap 5`, `ApexCharts`
- Граф: `Sigma.js + Graphology`

## Лицензия

MIT (см. файл `LICENSE`)
