#!/usr/bin/env python3
import argparse
import sys
import os
from utils import compare_traffic, generate_report, generate_html_report, print_report, generate_txt_report
from netparser import NetParser


def validate_paths(args):
    """Проверяет существование указанных в аргументах путей."""
    errors = []
    
    if not os.path.exists(args.pcap_file):
        errors.append(f"Файл PCAP не найден: {args.pcap_file}")
    
    if args.compare and not os.path.exists(args.compare):
        errors.append(f"Файл для сравнения не найден: {args.compare}")
    
    return errors


def main() -> None:
    """
    Основная функция, осуществляющая разбор аргументов командной строки и запуск анализа/сравнения PCAP-файлов.
    """
    parser = argparse.ArgumentParser(
        description="Анализатор сетевого трафика для обнаружения подозрительной активности",
        epilog="Пример: %(prog)s capture.pcap --html report.html --check-blacklists"
    )
    parser.add_argument("pcap_file", help="Путь к PCAP файлу для анализа")
    parser.add_argument("--filter", help="Выражение фильтра пакетов (пример: DNS, IP, HTTP и т.д.)")
    parser.add_argument("--html", metavar="HTML_PATH", help="Сгенерировать HTML отчет по указанному пути")
    parser.add_argument("--json", metavar="JSON_PATH", help="Сгенерировать JSON отчет по указанному пути")
    parser.add_argument("--compare", metavar="COMPARE_FILE", help="Путь ко второму PCAP файлу для сравнения")
    parser.add_argument("--txt", metavar="TXT_PATH", help="Сгенерировать TXT отчет по указанному пути")
    parser.add_argument("--check-blacklists", action="store_true", help="Проверять IP адреса по черным спискам")
    parser.add_argument("--no-check-blacklists", action="store_false", dest="check_blacklists", help="Не проверять IP адреса по черным спискам")
    parser.add_argument("--threads", type=int, default=4, help="Количество потоков для обработки (по умолчанию: 4)")
    parser.add_argument("--debug", action="store_true", help="Включить подробный вывод отладочной информации")
    parser.set_defaults(check_blacklists=True)
    
    args = parser.parse_args()
    
    # Проверка существования файлов
    errors = validate_paths(args)
    if errors:
        for err in errors:
            print(f"Ошибка: {err}", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"[*] Начинаем анализ PCAP-файла: {args.pcap_file}")
        
        if args.check_blacklists:
            print("[*] Проверка IP-адресов по черным спискам включена")
        
        if args.compare:
            print(f"[*] Режим сравнения с файлом: {args.compare}")
            unique_traffic = compare_traffic(args.pcap_file, args.compare)
            print_report(unique_traffic)
            if args.json:
                generate_report(args.json, unique_traffic)
            if args.html:
                generate_html_report(args.html, unique_traffic)
            if args.txt:
                generate_txt_report(args.txt, unique_traffic)
        else:
            filters = None
            if args.filter:
                filter_terms = [term.strip() for term in args.filter.upper().split(",")]
                filters = lambda pkt: any(term in str(pkt).upper() for term in filter_terms)
                print(f"[*] Применяется фильтр: {args.filter}")

            net_parser = NetParser(check_blacklists=args.check_blacklists)
            net_parser.analyze(args.pcap_file, filters=filters, num_threads=args.threads)
            report_data = net_parser.get_dict()
            print_report(report_data)

            if args.json:
                generate_report(args.json, report_data)
                print(f"[*] JSON отчет сохранен в: {args.json}")
            if args.html:
                generate_html_report(args.html, report_data)
                print(f"[*] HTML отчет сохранен в: {args.html}")
            if args.txt:
                generate_txt_report(args.txt, report_data)
                print(f"[*] TXT отчет сохранен в: {args.txt}")
            
            print(f"[*] Обработано пакетов: {report_data['Overall Packet Statistics']['total_packets']}")
    except Exception as e:
        sys.exit(f"Ошибка при обработке: {str(e)}. Проверьте error.log для подробностей.")


if __name__ == "__main__":
    main()
