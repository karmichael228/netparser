#!/usr/bin/env python3
import json
import re
from typing import Any, Dict
from jinja2 import Template
from netparser import NetParser


def compare_traffic(pcap_base_file: str, pcap_plugin_file: str) -> Dict[str, Any]:
    """
    Сравнивает трафик между двумя PCAP-файлами и возвращает уникальный трафик из второго (plugin) файла.
    Помимо информации по отдельным IP-адресам, включается сравнение общей статистики пакетов.
    Служебные ключи (например, 'Overall Packet Statistics') обрабатываются отдельно.
    """
    base_parser = NetParser()
    plugin_parser = NetParser()
    base_parser.analyze(pcap_base_file)
    base_traffic = base_parser.get_dict()

    plugin_parser.analyze(pcap_plugin_file)
    plugin_traffic = plugin_parser.get_dict()

    unique_traffic: Dict[str, Any] = {}
    # Фильтруем ключи, не являющиеся IP-адресами (например, служебная статистика)
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    for ip, plugin_data in plugin_traffic.items():
        if ip == "Overall Packet Statistics":
            continue  # служебная статистика будет обработана отдельно
        if not ip_pattern.match(ip):
            continue
        base_data = base_traffic.get(ip)
        if not base_data:
            unique_traffic[ip] = plugin_data
        else:
            unique_dns = set(plugin_data["DNS Associations"]) - set(base_data["DNS Associations"])
            unique_sni = set(plugin_data["SNI Records"]) - set(base_data["SNI Records"])
            unique_http = set(plugin_data.get("HTTP Domains", [])) - set(base_data.get("HTTP Domains", []))
            unique_asn = plugin_data["ASN"] if plugin_data["ASN"] != base_data["ASN"] else None

            unique_packets = {
                key: plugin_data["Packet Statistics"].get(key, 0) - base_data["Packet Statistics"].get(key, 0)
                for key in plugin_data["Packet Statistics"]
            }

            if unique_dns or unique_sni or unique_http or unique_asn or any(count != 0 for count in unique_packets.values()):
                unique_traffic[ip] = {
                    "ASN": unique_asn if unique_asn else base_data["ASN"],
                    "DNS Associations": sorted(unique_dns),
                    "SNI Records": sorted(unique_sni),
                    "HTTP Domains": sorted(unique_http),
                    "Packet Statistics": {key: count for key, count in unique_packets.items() if count != 0}
                }

    # Обрабатываем общую статистику по пакетам
    if "Overall Packet Statistics" in base_traffic and "Overall Packet Statistics" in plugin_traffic:
        overall_base = base_traffic["Overall Packet Statistics"]
        overall_plugin = plugin_traffic["Overall Packet Statistics"]
        overall_diff = {k: overall_plugin.get(k, 0) - overall_base.get(k, 0)
                        for k in set(overall_base) | set(overall_plugin)}
        unique_traffic["Overall Packet Statistics"] = overall_diff
    else:
        unique_traffic["Overall Packet Statistics"] = plugin_traffic.get("Overall Packet Statistics", {})

    return unique_traffic


def generate_report(output_path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Генерирует JSON-отчёт и сохраняет его по указанному пути.
    Отчёт включает информацию по отдельным IP-адресам, а также общую статистику по пакетам.
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"[*] Report saved to '{output_path}'")
    return data


def generate_html_report(output_path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Генерирует HTML-отчёт из переданных данных и сохраняет его по указанному пути.
    Отчёт включает информацию по отдельным IP-адресам и общую статистику по пакетам.
    """
    html_template = """
    <html>
    <head>
        <meta charset="utf-8">
        <title>Network Traffic Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            h1 { text-align: center; }
            .section { border: 1px solid #ccc; margin: 10px; padding: 10px; }
            .section h2 { margin: 0 0 10px 0; }
            .ip-section { border: 1px solid #ddd; margin: 5px; padding: 5px; }
            ul { list-style-type: none; padding-left: 0; }
        </style>
    </head>
    <body>
        <h1>Network Traffic Report</h1>

        {% if data.get("Overall Packet Statistics") %}
        <div class="section">
            <h2>Overall Packet Statistics</h2>
            <ul>
            {% for stat, value in data["Overall Packet Statistics"].items() %}
                <li><strong>{{ stat }}:</strong> {{ value }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}

        {% for ip, report in data.items() if ip != 'Overall Packet Statistics' %}
            <div class="ip-section">
                <h2>IP: {{ ip }}</h2>
                <ul>
                    <li><strong>ASN:</strong> {{ report['ASN'] }}</li>
                    <li><strong>DNS Associations:</strong> {{ report['DNS Associations'] | join(', ') if report['DNS Associations'] else 'None' }}</li>
                    <li><strong>SNI Records:</strong> {{ report['SNI Records'] | join(', ') if report['SNI Records'] else 'None' }}</li>
                    <li><strong>HTTP Domains:</strong> {{ report['HTTP Domains'] | join(', ') if report['HTTP Domains'] else 'None' }}</li>
                    <li><strong>Packet Statistics:</strong>
                        <ul>
                        {% for packet_type, count in report['Packet Statistics'].items() %}
                            <li>{{ packet_type }}: {{ count }}</li>
                        {% endfor %}
                        </ul>
                    </li>
                </ul>
            </div>
        {% endfor %}
    </body>
    </html>
    """
    template = Template(html_template)
    html_content = template.render(data=data)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[*] HTML Report saved to '{output_path}'")
    return data


def print_report(report_data: Dict[str, Any]) -> None:
    """
    Выводит анализ трафика на экран в структурированном виде.
    Отчёт включает информацию по отдельным IP-адресам, а также общую статистику по пакетам.
    :param report_data: Словарь с данными анализа.
    """
    print("\n" + "=" * 60)
    print(f"{'Network Traffic Analysis Report':^60}")
    print("=" * 60)

    # Вывод общей статистики по пакетам
    overall_stats = report_data.get("Overall Packet Statistics")
    if overall_stats:
        print(f"\n{'Overall Packet Statistics':^60}")
        print("-" * 60)
        for stat, value in overall_stats.items():
            print(f"{stat:<20}: {value}")
        print("=" * 60)

    # Вывод информации по IP-адресам
    for ip, report in report_data.items():
        if ip == "Overall Packet Statistics":
            continue
        print(f"\n{'IP Address:':<15}{ip}")
        print(f"{'ASN:':<15}{report.get('ASN', 'Not Available')}")

        dns_info = ', '.join(report.get('DNS Associations', [])) if report.get('DNS Associations') else 'None'
        print(f"{'DNS Associations:':<15}{dns_info}")

        sni_info = ', '.join(report.get('SNI Records', [])) if report.get('SNI Records') else 'None'
        print(f"{'SNI Records:':<15}{sni_info}")

        http_info = ', '.join(report.get('HTTP Domains', [])) if report.get('HTTP Domains') else 'None'
        print(f"{'HTTP Domains:':<15}{http_info}")

        packet_stats = report.get('Packet Statistics', {})
        if packet_stats:
            print(f"\n{'Packet Statistics:':<15}")
            for packet_type, count in packet_stats.items():
                print(f"  {packet_type:<20}{count}")
        else:
            print(f"{'Packet Statistics:':<15}No data available")

        print("=" * 60)
