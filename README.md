# netparser
## Описание
NetParser — это инструмент для анализа сетевого трафика с использованием PCAP-файлов. Он извлекает данные о 
DNS-запросах, SNI-записях, статистике пакетов и автоматически определяет ASN (Autonomous System Number) для 
IP-адресов. Также поддерживается сравнение двух PCAP-файлов для выявления уникального трафика плагинов или изменений 
в сетевых соединениях.

## Установка зависимостей
1. Установите Python 3.6 или выше.
2. python3 -m venv venv
3. pip install -r requirements.txt

## Примеры использования
### Анализ одного pcap-файла: 
python3 main.py your_pcap_file.pcap
### Сравнение двух pcap файлов: 
python3 main.py base_pcap.pcap --compare plugin_pcap.pcap
### Генерация JSON-отчета: 
python3 main.py your_pcap_file.pcap --json report.json
### Генерация HTML-отчета: 
python3 main.py your_pcap_file.pcap --html report.html
### Фильтрация пакетов по типу: 
python3 main.py your_pcap_file.pcap --filter DNS
