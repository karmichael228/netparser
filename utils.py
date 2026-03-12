#!/usr/bin/env python3
import json
import re
import os
import html
from typing import Any, Dict, List, Tuple, Optional, Set
from jinja2 import Template
try:
    from netparser import NetParser, IpsumBlacklist
except ImportError:
    from netparser.netparser import NetParser, IpsumBlacklist
from tabulate import tabulate
from termcolor import colored
import datetime

def ip_sort_key(ip: str) -> tuple:
    try:
        return tuple(int(part) for part in ip.split('.'))
    except Exception:
        return (9999,)

def compare_traffic(pcap_base_file: str, pcap_plugin_file: str) -> Dict[str, Any]:
    base_parser = NetParser()
    plugin_parser = NetParser()
    base_parser.analyze(pcap_base_file)
    base_traffic = base_parser.get_dict()
    plugin_parser.analyze(pcap_plugin_file)
    plugin_traffic = plugin_parser.get_dict()

    ip_blacklist = IpsumBlacklist()

    unique_traffic: Dict[str, Any] = {}
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    for ip, plugin_data in plugin_traffic.items():
        if ip == "Overall Packet Statistics":
            continue
        if not ip_pattern.match(ip):
            continue
        base_data = base_traffic.get(ip)
        
        is_blacklisted, threat_score = ip_blacklist.check_ip(ip)
        
        if not base_data:
            # Это новый IP адрес, помечаем его
            plugin_data = dict(plugin_data)  # Создаем копию, чтобы не изменять оригинал
            plugin_data["is_new"] = True  # Специальная метка для новых IP
            
            unique_traffic[ip] = plugin_data
            if "Threat Info" not in plugin_data and is_blacklisted:
                threat_info = {
                    "is_blacklisted": is_blacklisted,
                    "threat_score": threat_score,
                    "threat_level": ip_blacklist.get_threat_level(threat_score)
                }
                plugin_data["Threat Info"] = threat_info
        else:
            unique_dns = set(plugin_data.get("DNS Associations", [])) - set(base_data.get("DNS Associations", []))
            unique_sni = set(plugin_data.get("SNI Records", [])) - set(base_data.get("SNI Records", []))
            unique_http_domains = set(plugin_data.get("HTTP Domains", [])) - set(base_data.get("HTTP Domains", []))
            base_http_reqs: List[Dict[str, str]] = base_data.get("HTTP Requests", [])
            plugin_http_reqs: List[Dict[str, str]] = plugin_data.get("HTTP Requests", [])
            
            # Преобразование HTTP запросов в множества для сравнения
            base_http_req_set = {tuple(sorted((k, v) for k, v in req.items() if v)) for req in base_http_reqs}
            plugin_http_req_set = {tuple(sorted((k, v) for k, v in req.items() if v)) for req in plugin_http_reqs}
            unique_http_req_tuples = plugin_http_req_set - base_http_req_set
            
            # Восстановление оригинальных запросов
            unique_http_reqs = []
            for req_tuple in unique_http_req_tuples:
                for req in plugin_http_reqs:
                    if tuple(sorted((k, v) for k, v in req.items() if v)) == req_tuple:
                        unique_http_reqs.append(req)
                        break
            
            unique_asn = plugin_data["ASN"] if plugin_data["ASN"] != base_data["ASN"] else None
            
            # Правильный расчет уникальных пакетов (только положительные значения)
            unique_protocols = {}
            for key in set(plugin_data.get("Protocols", {})) | set(base_data.get("Protocols", {})):
                plugin_value = plugin_data.get("Protocols", {}).get(key, 0)
                base_value = base_data.get("Protocols", {}).get(key, 0)
                diff = plugin_value - base_value
                if diff > 0:  # Учитываем только положительные значения
                    unique_protocols[key] = diff
            
            # Уникальные DNS запросы
            unique_dns_queries_by_server = {}
            plugin_queries = plugin_data.get("DNS Queries by Server", {})
            base_queries = base_data.get("DNS Queries by Server", {})
            all_servers = set(plugin_queries.keys()) | set(base_queries.keys())
            for server_ip in all_servers:
                plugin_server_queries = set(plugin_queries.get(server_ip, []))
                base_server_queries = set(base_queries.get(server_ip, []))
                unique_queries = plugin_server_queries - base_server_queries
                if unique_queries:
                    unique_dns_queries_by_server[server_ip] = sorted(unique_queries)
            
            # Уникальные соединения
            unique_outgoing = set(plugin_data.get("Connections", {}).get("Outgoing", [])) - set(base_data.get("Connections", {}).get("Outgoing", []))
            unique_incoming = set(plugin_data.get("Connections", {}).get("Incoming", [])) - set(base_data.get("Connections", {}).get("Incoming", []))
            
            # Получение информации о угрозе
            threat_info = None
            if is_blacklisted:
                threat_info = {
                    "is_blacklisted": is_blacklisted,
                    "threat_score": threat_score,
                    "threat_level": ip_blacklist.get_threat_level(threat_score)
                }
            
            # Правильный расчет уникального трафика (только положительные значения)
            unique_traffic_stats = {}
            for key in set(plugin_data.get("Traffic", {})) | set(base_data.get("Traffic", {})):
                plugin_value = plugin_data.get("Traffic", {}).get(key, 0)
                base_value = base_data.get("Traffic", {}).get(key, 0)
                diff = plugin_value - base_value
                if diff > 0:  # Учитываем только положительные значения
                    unique_traffic_stats[key] = diff
            
            # Проверяем, есть ли вообще уникальные данные для этого IP
            has_unique_data = (
                unique_dns or unique_sni or unique_http_domains or unique_http_reqs or
                unique_asn or unique_protocols or unique_dns_queries_by_server or
                unique_outgoing or unique_incoming or unique_traffic_stats
            )
            
            # Добавляем IP только если есть уникальные данные
            if has_unique_data:
                unique_traffic[ip] = {
                    "ASN": unique_asn if unique_asn else base_data["ASN"],
                    "is_new": False,  # Это существующий IP с новыми данными
                    "DNS Associations": sorted(unique_dns),
                    "DNS Queries by Server": unique_dns_queries_by_server if unique_dns_queries_by_server else None,
                    "DNS Responses": plugin_data.get("DNS Responses", []),
                    "DNS Resolution Chains": plugin_data.get("DNS Resolution Chains", []),
                    "SNI Records": sorted(unique_sni),
                    "HTTP Domains": sorted(unique_http_domains),
                    "HTTP Requests": unique_http_reqs,
                    "Traffic": unique_traffic_stats,
                    "Protocols": unique_protocols,
                    "Connections": {
                        "Outgoing": sorted(unique_outgoing, key=ip_sort_key),
                        "Incoming": sorted(unique_incoming, key=ip_sort_key)
                    }
                }
                
                # Добавляем информацию о угрозе, если IP в черном списке
                if threat_info:
                    unique_traffic[ip]["Threat Info"] = threat_info

    if "Overall Packet Statistics" in base_traffic and "Overall Packet Statistics" in plugin_traffic:
        overall_base = base_traffic["Overall Packet Statistics"]
        overall_plugin = plugin_traffic["Overall Packet Statistics"]
        
        # Правильный расчет разницы статистик (только положительные значения)
        overall_diff = {}
        for k in set(overall_base) | set(overall_plugin):
            plugin_value = overall_plugin.get(k, 0)
            base_value = overall_base.get(k, 0)
            diff = plugin_value - base_value
            if diff > 0:  # Учитываем только положительные значения
                overall_diff[k] = diff
        
        unique_traffic["Overall Packet Statistics"] = overall_diff
    else:
        unique_traffic["Overall Packet Statistics"] = plugin_traffic.get("Overall Packet Statistics", {})
    return unique_traffic

def generate_report(output_path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"[*] Report saved to '{output_path}'")
    return data

def generate_html_report(output_path: str, data: Dict[str, Any]) -> None:
    """
    Генерирует HTML-отчет об анализе сетевого трафика.
    
    Args:
        output_path: Путь к файлу отчета
        data: Словарь с данными отчета
    """
    
    ip_keys = [ip for ip in data.keys() if ip != "Overall Packet Statistics"]
    sorted_ips = sorted(ip_keys, key=ip_sort_key)
    
    # Подготовка данных для графа соединений
    graph_nodes = set()
    graph_edges = {}
    
    for ip in sorted_ips:
        graph_nodes.add(ip)
        
        outgoing_connections = data[ip].get("Connections", {}).get("Outgoing", [])
        incoming_connections = data[ip].get("Connections", {}).get("Incoming", [])
        
        # Добавляем все связанные IP в набор узлов
        for conn_ip in outgoing_connections:
            graph_nodes.add(conn_ip)
        
        for conn_ip in incoming_connections:
            graph_nodes.add(conn_ip)
        
        # Сохраняем ребра графа
        if outgoing_connections:
            graph_edges[ip] = outgoing_connections
    
    # Загрузка шаблона из файла
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'report_template.html')
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template_str = f.read()
    
    template = Template(template_str)
    
    context = {
        'data': data,
        'stats': data.get('Overall Packet Statistics', {}),
        'sorted_ips': sorted_ips,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'get_threat_info_for_ip': get_threat_info_for_ip,
        'get_threat_badge_class': get_threat_badge_class,
        'graph_nodes': list(graph_nodes),
        'graph_edges': graph_edges
    }
    
    html_content = template.render(**context)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[*] HTML Report saved to '{output_path}'")


def generate_simple_html_report(output_path: str, data: Dict[str, Any], title: str = "NetParser HTML Report") -> None:
    """Генерирует простой статичный HTML-отчет без анимаций."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats = data.get("Overall Packet Statistics", {})
    ip_keys = [ip for ip in data.keys() if ip != "Overall Packet Statistics"]
    sorted_ips = sorted(ip_keys, key=ip_sort_key)
    blacklisted_count = sum(
        1 for ip in sorted_ips if (data.get(ip, {}).get("Threat Info", {}) or {}).get("is_blacklisted")
    )

    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    def render_kv_table(obj: Dict[str, Any]) -> str:
        if not obj:
            return '<div class="muted">Нет данных</div>'
        rows = []
        for key, value in obj.items():
            rows.append(f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>")
        return f"<table class='kv-table'>{''.join(rows)}</table>"

    def render_list(items: Any) -> str:
        if not items:
            return '<div class="muted">Нет данных</div>'
        if isinstance(items, dict):
            return render_kv_table(items)
        if not isinstance(items, list):
            return f"<div>{esc(items)}</div>"
        return "<ul>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>"

    def render_dns_queries_by_server(queries_map: Dict[str, List[str]]) -> str:
        if not queries_map:
            return '<div class="muted">Нет данных</div>'
        blocks = []
        for server_ip, queries in queries_map.items():
            blocks.append(
                f"<div class='sub-block'><div class='sub-title'>{esc(server_ip)}</div>{render_list(queries)}</div>"
            )
        return "".join(blocks)

    def render_http_requests(requests: List[Dict[str, Any]]) -> str:
        if not requests:
            return '<div class="muted">Нет данных</div>'
        rows = []
        for req in requests:
            rows.append(
                "<tr>"
                f"<td>{esc(req.get('method', '-'))}</td>"
                f"<td>{esc(req.get('host', '-'))}</td>"
                f"<td>{esc(req.get('uri', '-'))}</td>"
                f"<td>{esc(req.get('user_agent', '-'))}</td>"
                "</tr>"
            )
        return (
            "<table class='grid-table'><thead><tr><th>Method</th><th>Host</th><th>URI</th><th>User-Agent</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def render_http_responses(responses: List[Dict[str, Any]]) -> str:
        if not responses:
            return '<div class="muted">Нет данных</div>'
        rows = []
        for resp in responses:
            rows.append(
                "<tr>"
                f"<td>{esc(resp.get('status_code', '-'))}</td>"
                f"<td>{esc(resp.get('status_message', '-'))}</td>"
                f"<td>{esc(resp.get('content_type', '-'))}</td>"
                f"<td>{esc(resp.get('content_length', '-'))}</td>"
                "</tr>"
            )
        return (
            "<table class='grid-table'><thead><tr><th>Status</th><th>Message</th><th>Content-Type</th><th>Length</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    ip_sections = []
    for ip in sorted_ips:
        info = data.get(ip, {})
        threat_info = info.get("Threat Info", {})
        traffic = info.get("Traffic", {})
        protocols = info.get("Protocols", {})
        connections = info.get("Connections", {})
        dns_associations = info.get("DNS Associations", [])
        dns_queries = info.get("DNS Queries by Server", {}) or {}
        dns_responses = info.get("DNS Responses", []) or []
        dns_chains = info.get("DNS Resolution Chains", []) or []
        sni_records = info.get("SNI Records", [])
        http_domains = info.get("HTTP Domains", [])
        http_requests = info.get("HTTP Requests", [])
        http_responses = info.get("HTTP Responses", [])

        threat_label = "Безопасный"
        if threat_info.get("is_blacklisted"):
            threat_label = f"{threat_info.get('threat_level', 'Threat')} ({threat_info.get('threat_score', 0)})"

        ip_sections.append(
            f"""
            <section class="ip-card" id="ip-{esc(ip)}">
                <h2>{esc(ip)}</h2>
                <div class="meta-line">ASN: <b>{esc(info.get("ASN", "Unknown"))}</b> | Threat: <b>{esc(threat_label)}</b></div>
                <div class="grid">
                    <div class="block"><h3>Traffic</h3>{render_kv_table(traffic)}</div>
                    <div class="block"><h3>Protocols</h3>{render_kv_table(protocols)}</div>
                </div>
                <div class="grid">
                    <div class="block"><h3>Connections: Outgoing</h3>{render_list(connections.get("Outgoing", []))}</div>
                    <div class="block"><h3>Connections: Incoming</h3>{render_list(connections.get("Incoming", []))}</div>
                </div>
                <div class="grid">
                    <div class="block"><h3>DNS Associations</h3>{render_list(dns_associations)}</div>
                    <div class="block"><h3>DNS Queries by Server</h3>{render_dns_queries_by_server(dns_queries)}</div>
                </div>
                <div class="grid">
                    <div class="block"><h3>DNS Responses</h3>{render_list(dns_responses)}</div>
                    <div class="block"><h3>DNS Resolution Chains</h3>{render_list(dns_chains)}</div>
                </div>
                <div class="grid">
                    <div class="block"><h3>HTTP Domains</h3>{render_list(http_domains)}</div>
                    <div class="block"><h3>TLS / SNI</h3>{render_list(sni_records)}</div>
                </div>
                <div class="grid">
                    <div class="block"><h3>HTTP Requests</h3>{render_http_requests(http_requests)}</div>
                    <div class="block"><h3>HTTP Responses</h3>{render_http_responses(http_responses)}</div>
                </div>
                <details class="raw-json">
                    <summary>Raw JSON for this IP</summary>
                    <pre>{esc(json.dumps(info, ensure_ascii=False, indent=2))}</pre>
                </details>
            </section>
            """
        )

    html_content = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f7f8fa; color: #1f2937; }}
    .container {{ max-width: 1320px; margin: 0 auto; padding: 24px; }}
    .header {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; }}
    .header h1 {{ margin: 0 0 8px; font-size: 22px; }}
    .muted {{ color: #64748b; font-size: 13px; }}
    .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 12px; }}
    .stat {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; }}
    .stat .label {{ font-size: 12px; color: #64748b; }}
    .stat .value {{ font-size: 18px; font-weight: 600; margin-top: 4px; }}
    .toc {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; }}
    .toc ul {{ margin: 0; padding-left: 18px; column-count: 3; column-gap: 24px; }}
    .toc li {{ break-inside: avoid; margin: 4px 0; }}
    .toc a {{ color: #1d4ed8; text-decoration: none; }}
    .ip-card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; margin-bottom: 14px; }}
    .ip-card h2 {{ margin: 0; font-size: 20px; }}
    .meta-line {{ margin-top: 6px; margin-bottom: 10px; color: #334155; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 10px; }}
    .block {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; min-width: 0; }}
    .block h3 {{ margin: 0 0 8px; font-size: 14px; }}
    .kv-table, .grid-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
    .kv-table th, .kv-table td, .grid-table th, .grid-table td {{ border-bottom: 1px solid #eef2f7; text-align: left; padding: 6px 4px; vertical-align: top; }}
    .kv-table th, .grid-table th {{ width: 32%; color: #475569; font-weight: 600; }}
    ul {{ margin: 0; padding-left: 18px; font-size: 12px; }}
    .sub-block {{ margin-bottom: 8px; }}
    .sub-title {{ font-size: 12px; font-weight: 600; color: #334155; margin-bottom: 3px; }}
    .raw-json summary {{ cursor: pointer; color: #1d4ed8; }}
    .raw-json pre {{ margin: 8px 0 0; background: #0b1020; color: #e5e7eb; padding: 10px; border-radius: 8px; overflow: auto; font-size: 12px; }}
    @media (max-width: 960px) {{
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .grid {{ grid-template-columns: 1fr; }}
      .toc ul {{ column-count: 1; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>{esc(title)}</h1>
      <div class="muted">Сформирован: {esc(timestamp)}</div>
      <div class="stats">
        <div class="stat"><div class="label">Всего IP</div><div class="value">{len(sorted_ips)}</div></div>
        <div class="stat"><div class="label">Подозрительные IP</div><div class="value">{blacklisted_count}</div></div>
        <div class="stat"><div class="label">Всего пакетов</div><div class="value">{esc(stats.get("total_packets", 0))}</div></div>
        <div class="stat"><div class="label">Протокольных метрик</div><div class="value">{len(stats)}</div></div>
      </div>
    </header>
    <section class="toc">
      <div class="muted" style="margin-bottom: 6px;">Навигация по IP</div>
      <ul>
        {"".join(f'<li><a href="#ip-{esc(ip)}">{esc(ip)}</a></li>' for ip in sorted_ips)}
      </ul>
    </section>
    {"".join(ip_sections)}
  </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[*] Simple HTML Report saved to '{output_path}'")

def print_report(report_data: Dict[str, Any]) -> None:
    """
    Выводит отчет об анализе сетевого трафика в консоль.
    
    Args:
        report_data: Словарь с данными отчета
    """
    if "Overall Packet Statistics" in report_data:
        print("\n=== Общая статистика пакетов ===")
        stats_table = [[k, v] for k, v in report_data["Overall Packet Statistics"].items()]
        print(tabulate(stats_table, headers=["Метрика", "Значение"], tablefmt="pretty"))
    
    ip_keys = [ip for ip in report_data.keys() if ip != "Overall Packet Statistics"]
    total_ips = len(ip_keys)
    blacklisted_ips = sum(1 for ip in ip_keys if get_threat_info_for_ip(ip, report_data)[0])
    
    print("\n=== Статистика по IP ===")
    print(f"Всего IP: {total_ips}")
    print(f"IP в черном списке: {blacklisted_ips}")

def get_threat_info_for_ip(ip: str, data: Dict[str, Any]) -> Tuple[bool, str, int]:
    """
    Получает информацию о угрозе для IP-адреса.
    
    Args:
        ip: IP-адрес для проверки
        data: Словарь с данными отчета
        
    Returns:
        Tuple[bool, str, int]: (есть_в_черном_списке, уровень_угрозы, счетчик_угрозы)
    """
    if not ip or not data.get(ip) or not data[ip].get('Threat Info'):
        return False, "", 0
    
    threat_info = data[ip]['Threat Info']
    is_blacklisted = threat_info.get('is_blacklisted', False)
    threat_level = threat_info.get('threat_level', 'Unknown')
    threat_score = threat_info.get('threat_score', 0)
    
    return is_blacklisted, threat_level, threat_score

def get_threat_badge_class(threat_level: str) -> str:
    """
    Возвращает CSS-класс для бейджа угрозы.
    
    Args:
        threat_level: Уровень угрозы (Низкий, Средний, Высокий, Критический)
        
    Returns:
        str: CSS-класс для бейджа
    """
    if threat_level == "Низкий":
        return "threat-low"
    elif threat_level == "Средний":
        return "threat-medium"
    elif threat_level == "Высокий":
        return "threat-high"
    elif threat_level == "Критический":
        return "threat-critical"
    return ""

def format_dns_response(response: str, data: Dict[str, Any]) -> str:
    """
    Форматирует DNS-ответ с учетом наличия IP в черных списках.
    
    Args:
        response: Строка с DNS-ответом
        data: Словарь с данными отчета
        
    Returns:
        str: Отформатированная строка с DNS-ответом
    """
    if not response or not isinstance(response, str):
        return str(response)
    
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    ips = [ip.strip() for ip in response.split(',')]
    
    formatted_parts = []
    for ip in ips:
        if ip_pattern.match(ip):
            is_blacklisted, threat_level, threat_score = get_threat_info_for_ip(ip, data)
            if is_blacklisted:
                formatted_parts.append(f"\033[91m{ip} ({threat_level}: {threat_score})\033[0m")
            else:
                formatted_parts.append(f"\033[92m{ip}\033[0m")
        else:
            formatted_parts.append(ip)
    
    return ", ".join(formatted_parts)

def generate_txt_report(output_path: str, data: Dict[str, Any]) -> None:
    """
    Генерирует текстовый отчет об анализе сетевого трафика.
    
    Args:
        output_path: Путь к файлу отчета
        data: Словарь с данными отчета
    """
    with open(output_path, "w", encoding="utf-8") as f:
        ip_keys = [ip for ip in data.keys() if ip != "Overall Packet Statistics"]
        sorted_ips = sorted(ip_keys, key=ip_sort_key)
        
        for ip in sorted_ips:
            info = data[ip]
            f.write(f"IP: {ip}\n")

            dns_assocs = info.get("DNS Associations", [])
            if dns_assocs:
                f.write("DNS Associations:\n")
                for assoc in dns_assocs:
                    f.write(f"  - {assoc}\n")

            sni_records = info.get("SNI Records", [])
            if sni_records:
                f.write("SNI Records:\n")
                for record in sni_records:
                    f.write(f"  - {record}\n")
            
            f.write("-" * 50 + "\n")
    
    print(f"[*] TXT Report saved to '{output_path}'")
