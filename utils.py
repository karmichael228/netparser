#!/usr/bin/env python3
import json
import re
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
            
            unique_traffic[ip] = {
                "ASN": unique_asn if unique_asn else base_data["ASN"],
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
    
    template_str = r"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Отчет по анализу сетевого трафика</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                color: #333;
                background-color: #f5f5f5;
            }
            @keyframes highlight {
                0% { background-color: rgba(52, 152, 219, 0.4); }
                50% { background-color: rgba(52, 152, 219, 0.7); }
                100% { background-color: transparent; }
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            h1 {
                text-align: center;
                border-bottom: 2px solid #eee;
                padding-bottom: 10px;
                margin-bottom: 20px;
            }
            .stats-container, .ip-container {
                margin-bottom: 20px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
            th, td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .section-title {
                margin-top: 20px;
                padding-bottom: 5px;
                border-bottom: 1px solid #eee;
            }
            .dns-response {
                margin-bottom: 10px;
                padding: 8px;
                background-color: #f2f2f2;
                border-radius: 4px;
            }
            .dns-response-name {
                font-weight: bold;
            }
            .header-info {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            .timestamp {
                color: #777;
                font-size: 0.9em;
            }
            .threat-ip {
                color: #e74c3c;
                font-weight: bold;
            }
            .safe-ip {
                color: #2ecc71;
                font-weight: bold;
            }
            .threat-badge {
                display: inline-block;
                padding: 3px 6px;
                border-radius: 3px;
                font-size: 0.8em;
                font-weight: bold;
                color: white;
                margin-left: 5px;
            }
            .threat-low {
                background-color: #f39c12;
            }
            .threat-medium {
                background-color: #e67e22;
            }
            .threat-high {
                background-color: #d35400;
            }
            .threat-critical {
                background-color: #c0392b;
            }
            .collapsible {
                background-color: #f9f9f9;
                color: #444;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
                border-radius: 5px;
                margin-top: 5px;
                transition: background-color 0.3s;
            }
            .active, .collapsible:hover {
                background-color: #eee;
            }
            .content {
                padding: 0 18px;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
                background-color: white;
                border-radius: 0 0 5px 5px;
            }
            .toggle-icon {
                float: right;
                margin-left: 5px;
            }
            .section-collapsible {
                background-color: #2c3e50;
                color: white;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 18px;
                border-radius: 5px;
                margin: 10px 0;
                transition: background-color 0.3s;
            }
            .section-collapsible:hover {
                background-color: #34495e;
            }
            .ip-collapsible {
                background-color: #2ecc71;
                color: white;
                cursor: pointer;
                padding: 15px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 16px;
                border-radius: 5px;
                margin: 5px 0;
                transition: background-color 0.3s;
            }
            .ip-collapsible.blacklisted {
                background-color: #e74c3c;
            }
            .ip-collapsible:hover {
                background-color: #27ae60;
            }
            .ip-collapsible.blacklisted:hover {
                background-color: #c0392b;
            }
            .ip-content {
                padding: 0 18px;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
                background-color: white;
                border-radius: 0 0 5px 5px;
                border: 1px solid #ddd;
                border-top: none;
            }
            .chart-container {
                position: relative;
                margin: auto;
                height: 300px;
                width: 100%;
            }
            a {
                color: #3498db;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            .uri-link {
                margin-bottom: 5px;
                display: inline-block;
            }
            .copyable {
                cursor: pointer;
                position: relative;
                display: inline-block;
                padding: 2px 5px;
                background-color: rgba(240, 240, 240, 0.5);
                border-radius: 3px;
                margin-right: 5px;
                font-weight: bold;
                color: inherit;
                border: 1px solid #ddd;
            }
            .copyable:hover {
                background-color: #e0e0e0;
            }
            .copyable::after {
                content: 'Скопировано!';
                position: absolute;
                top: -30px;
                left: 50%;
                transform: translateX(-50%);
                background-color: #333;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                opacity: 0;
                transition: opacity 0.3s;
                pointer-events: none;
                white-space: nowrap;
            }
            .copyable.copied::after {
                opacity: 1;
            }
            .connection-link {
                padding: 2px 6px;
                margin: 2px;
                display: inline-block;
                border-radius: 4px;
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                cursor: pointer;
                text-decoration: none !important;
            }
            .connection-link.outgoing {
                background-color: #e8f4f8;
                border-color: #c5e0e8;
            }
            .connection-link.incoming {
                background-color: #f8f4e8;
                border-color: #e8d5c5;
            }
            .connection-link:hover {
                background-color: #e0e0e0;
            }
            .connections-container {
                margin-top: 10px;
                padding: 10px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }
            .http-detail {
                margin-top: 5px;
                font-family: monospace;
                word-break: break-all;
            }
            .usage-tips {
                background-color: #f8f9fa;
                border-left: 4px solid #3498db;
                padding: 10px 15px;
                margin-bottom: 20px;
                border-radius: 4px;
                font-size: 0.9em;
            }
            .usage-tips p {
                margin-top: 0;
                margin-bottom: 5px;
                color: #2c3e50;
            }
            .usage-tips ul {
                margin-top: 5px;
                margin-bottom: 5px;
                padding-left: 25px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-info">
                <h1>Отчет по анализу сетевого трафика</h1>
                <span class="timestamp">Сгенерирован: {{ timestamp }}</span>
            </div>
            
            <div class="usage-tips">
                <p><strong>Подсказки:</strong></p>
                <ul>
                    <li>Нажмите на IP-адрес для перехода к его подробному отчету</li>
                    <li>Щелкните на выделенный фоном IP-адрес, чтобы скопировать его в буфер обмена</li>
                </ul>
            </div>
            
            <!-- Общая статистика по пакетам (раскрывающийся блок) -->
            <button class="section-collapsible" onclick="toggleSection('statsSection')">
                Общая статистика по пакетам <span class="toggle-icon">+</span>
            </button>
            <div id="statsSection" class="content">
                {% if stats %}
                <div class="stats-container">
                    <table>
                        <tr>
                            <th>Метрика</th>
                            <th>Значение</th>
                        </tr>
                        {% for stat, value in stats.items() %}
                        <tr>
                            <td>{{ stat }}</td>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% else %}
                <p>Нет доступной статистики.</p>
                {% endif %}
            </div>
            
            <!-- IP адреса (раскрывающийся блок) -->
            <button class="section-collapsible" onclick="toggleSection('ipSection')">
                IP адреса ({{ sorted_ips|length }}) <span class="toggle-icon">+</span>
            </button>
            <div id="ipSection" class="content">
                {% for ip in sorted_ips %}
                {% set ip_data = data[ip] %}
                {% set is_blacklisted, threat_level, threat_score = get_threat_info_for_ip(ip, data) %}
                
                <button class="ip-collapsible {% if is_blacklisted %}blacklisted{% endif %}" onclick="toggleIP('ip_{{ ip|replace('.', '_') }}')">
                    <span class="copyable" onclick="copyToClipboard(event, '{{ ip }}')">{{ ip }}</span>
                    {% if is_blacklisted %}
                        - В черном списке ({{ threat_level }}: {{ threat_score }})
                    {% else %}
                        - {{ ip_data.get('ASN', 'Не доступно') }}
                    {% endif %}
                    <span class="toggle-icon">+</span>
                </button>
                <div id="ip_{{ ip|replace('.', '_') }}" class="ip-content">
                    <!-- Информация об угрозе -->
                    <div class="section-title">
                        <h3>Информация об угрозе</h3>
                        {% if is_blacklisted %}
                            <p class="threat-ip">Статус: В черном списке - {{ threat_level }} ({{ threat_score }})</p>
                        {% else %}
                            <p class="safe-ip">Статус: Отсуствует в черном списке </p>
                        {% endif %}
                    </div>
                    
                    <!-- ASN -->
                    <div class="section-title">
                        <h3>ASN</h3>
                        <p>{{ ip_data.get('ASN', 'Не доступно') }}</p>
                    </div>
                    
                    <!-- Связи с другими IP -->
                    <div class="section-title">
                        <h3>Связи с другими IP-адресами</h3>
                        <div class="connections-container">
                            <div>
                                <h4>Исходящие соединения:</h4>
                                {% if ip_data.get('Connections', {}).get('Outgoing') %}
                                    {% for connected_ip in ip_data.get('Connections', {}).get('Outgoing', []) %}
                                        {% set ip_blacklisted, ip_threat_level, ip_threat_score = get_threat_info_for_ip(connected_ip, data) %}
                                        <a href="javascript:void(0)" class="connection-link outgoing {% if ip_blacklisted %}threat-ip{% endif %}" 
                                           onclick="scrollToIP('{{ connected_ip }}')">
                                            <span class="copyable" onclick="copyToClipboard(event, '{{ connected_ip }}')">{{ connected_ip }}</span>
                                            {% if ip_blacklisted %}
                                                <span class="threat-badge {{ get_threat_badge_class(ip_threat_level) }}">
                                                    {{ ip_threat_score }}
                                                </span>
                                            {% endif %}
                                        </a>
                                    {% endfor %}
                                {% else %}
                                    <p>Нет исходящих соединений</p>
                                {% endif %}
                            </div>
                            <div>
                                <h4>Входящие соединения:</h4>
                                {% if ip_data.get('Connections', {}).get('Incoming') %}
                                    {% for connected_ip in ip_data.get('Connections', {}).get('Incoming', []) %}
                                        {% set ip_blacklisted, ip_threat_level, ip_threat_score = get_threat_info_for_ip(connected_ip, data) %}
                                        <a href="javascript:void(0)" class="connection-link incoming {% if ip_blacklisted %}threat-ip{% endif %}" 
                                           onclick="scrollToIP('{{ connected_ip }}')">
                                            <span class="copyable" onclick="copyToClipboard(event, '{{ connected_ip }}')">{{ connected_ip }}</span>
                                            {% if ip_blacklisted %}
                                                <span class="threat-badge {{ get_threat_badge_class(ip_threat_level) }}">
                                                    {{ ip_threat_score }}
                                                </span>
                                            {% endif %}
                                        </a>
                                    {% endfor %}
                                {% else %}
                                    <p>Нет входящих соединений</p>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    
                    <!-- DNS ассоциации -->
                    {% if ip_data.get('DNS Associations') %}
                    <div class="section-title">
                        <h3>DNS-разрешения</h3>
                        <ul>
                        {% for assoc in ip_data.get('DNS Associations', []) %}
                            <li>{{ assoc }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    
                    <!-- DNS запросы по серверам -->
                    {% if ip_data.get('DNS Queries by Server') %}
                    <div class="section-title">
                        <h3>DNS-запросы по серверу</h3>
                        {% for server, queries in ip_data.get('DNS Queries by Server', {}).items() %}
                            <button class="collapsible">
                                {% set is_server_blacklisted, server_threat_level, server_threat_score = get_threat_info_for_ip(server, data) %}
                                {% if is_server_blacklisted %}
                                    <span class="threat-ip">Сервер 
                                        <span class="copyable" onclick="copyToClipboard(event, '{{ server }}')">{{ server }}</span>
                                    </span>
                                    <span class="threat-badge {{ get_threat_badge_class(server_threat_level) }}">
                                        {{ server_threat_score }}
                                    </span>
                                {% else %}
                                    <span class="safe-ip">Сервер 
                                        <span class="copyable" onclick="copyToClipboard(event, '{{ server }}')">{{ server }}</span>
                                    </span>
                                {% endif %}
                                <span class="toggle-icon">+</span>
                            </button>
                            <div class="content">
                                <ul>
                                {% for query in queries %}
                                    <li>{{ query }}</li>
                                {% endfor %}
                                </ul>
                            </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    <!-- DNS ответы (раскрывающийся блок) -->
                    {% if ip_data.get('DNS Responses') %}
                    <div class="section-title">
                        <h3>DNS-ответы</h3>
                        <button class="collapsible">Показать/скрыть DNS-ответы ({{ ip_data.get('DNS Responses')|length }}) <span class="toggle-icon">+</span></button>
                        <div class="content">
                            <table>
                                <tr>
                                    <th>Имя</th>
                                    <th>Тип</th>
                                    <th>Разрешение</th>
                                </tr>
                                {% for entry in ip_data.get('DNS Responses', []) %}
                                <tr>
                                    <td>{{ entry.name }}</td>
                                    <td>{{ entry.type }}</td>
                                    <td>
                                        {% if entry.type == "A" %}
                                            {% set ips = entry.resolution.split(',') %}
                                            {% for resolved_ip in ips %}
                                                {% set resolved_ip = resolved_ip.strip() %}
                                                {% set is_ip_blacklisted, ip_threat_level, ip_threat_score = get_threat_info_for_ip(resolved_ip, data) %}
                                                {% if is_ip_blacklisted %}
                                                    <span class="threat-ip">
                                                        <span class="copyable" onclick="copyToClipboard(event, '{{ resolved_ip }}')">{{ resolved_ip }}</span>
                                                    </span>
                                                    <span class="threat-badge {{ get_threat_badge_class(ip_threat_level) }}">
                                                        {{ ip_threat_score }}
                                                    </span>
                                                {% else %}
                                                    <span class="safe-ip">
                                                        <span class="copyable" onclick="copyToClipboard(event, '{{ resolved_ip }}')">{{ resolved_ip }}</span>
                                                    </span>
                                                {% endif %}
                                                {% if not loop.last %}, {% endif %}
                                            {% endfor %}
                                        {% else %}
                                            {{ entry.resolution }}
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </table>
                        </div>
                    </div>
                    {% endif %}
                    
                    <!-- SNI записи -->
                    {% if ip_data.get('SNI Records') %}
                    <div class="section-title">
                        <h3>SNI-записи</h3>
                        <ul>
                        {% for record in ip_data.get('SNI Records', []) %}
                            <li>{{ record }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    
                    <!-- HTTP домены -->
                    {% if ip_data.get('HTTP Domains') %}
                    <div class="section-title">
                        <h3>HTTP-домены</h3>
                        <ul>
                        {% for domain in ip_data.get('HTTP Domains', []) %}
                            <li>{{ domain }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    
                    <!-- Трафик -->
                    {% if ip_data.get('Traffic') %}
                    <div class="section-title">
                        <h3>Трафик</h3>
                        <table>
                            <tr>
                                <th>Тип</th>
                                <th>Размер</th>
                            </tr>
                            {% for traffic_type, size in ip_data.get('Traffic', {}).items() %}
                            <tr>
                                <td>{{ traffic_type.replace('_', ' ').title() }}</td>
                                <td>{{ size }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                    
                    <!-- Протоколы -->
                    {% if ip_data.get('Protocols') %}
                    <div class="section-title">
                        <h3>Протоколы</h3>
                        <table>
                            <tr>
                                <th>Протокол</th>
                                <th>Количество</th>
                            </tr>
                            {% for protocol, count in ip_data.get('Protocols', {}).items() %}
                            <tr>
                                <td>{{ protocol }}</td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                    </div>
                    {% endif %}
                    
                    <!-- HTTP запросы и ссылки -->
                    {% if ip_data.get('HTTP Requests') %}
                    <div class="section-title">
                        <h3>HTTP-запросы</h3>
                        {% for req in ip_data.get('HTTP Requests', []) %}
                        <div class="dns-response">
                            <div><strong>{{ req.get('method', '') }} {{ req.get('uri', '') }} {{ req.get('version', '') }}</strong></div>
                            <div>Host: {{ req.get('host', '') }}</div>
                            {% if req.get('user_agent') %}
                            <div class="http-detail">User-Agent: {{ req.get('user_agent', '') }}</div>
                            {% endif %}
                            {% if req.get('content_type') %}
                            <div class="http-detail">Content-Type: {{ req.get('content_type', '') }}</div>
                            {% endif %}
                            {% if req.get('content_length') %}
                            <div class="http-detail">Content-Length: {{ req.get('content_length', '') }}</div>
                            {% endif %}
                            {% if req.get('referer') %}
                            <div class="http-detail">Referer: {{ req.get('referer', '') }}</div>
                            {% endif %}
                            {% if req.get('authorization') %}
                            <div class="http-detail">Authorization: {{ req.get('authorization', '') }}</div>
                            {% endif %}
                            {% if req.get('origin') %}
                            <div class="http-detail">Origin: {{ req.get('origin', '') }}</div>
                            {% endif %}
                            {% if req.get('cookies') %}
                            <div class="http-detail">Cookies: {{ req.get('cookies', '') }}</div>
                            {% endif %}
                            {% if req.get('body') %}
                            <div class="http-detail">
                                <strong>Body:</strong>
                                <pre>{{ req.get('body', '') }}</pre>
                            </div>
                            {% endif %}
                            {% if req.get('host') and req.get('uri') %}
                            <div class="uri-link">
                                <a href="http://{{ req.get('host') }}{{ req.get('uri') }}" target="_blank">http://{{ req.get('host') }}{{ req.get('uri') }}</a>
                            </div>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        
        <script>
            // Функция для переключения раскрывающихся секций
            function toggleSection(sectionId) {
                var content = document.getElementById(sectionId);
                var button = content.previousElementSibling;
                var icon = button.querySelector(".toggle-icon");
                
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                    icon.textContent = "+";
                } else {
                    content.style.maxHeight = "none";
                    icon.textContent = "-";
                }
            }
            
            // Функция для переключения IP-информации
            function toggleIP(ipId) {
                var content = document.getElementById(ipId);
                var button = content.previousElementSibling;
                var icon = button.querySelector(".toggle-icon");
                
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                    icon.textContent = "+";
                } else {
                    content.style.maxHeight = "none";
                    icon.textContent = "-";
                }
            }
            
            // Обработчик для всех обычных коллапсов
            var coll = document.getElementsByClassName("collapsible");
            for (var i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    var icon = this.querySelector(".toggle-icon");
                    
                    if (content.style.maxHeight) {
                        content.style.maxHeight = null;
                        if (icon) icon.textContent = "+";
                    } else {
                        content.style.maxHeight = content.scrollHeight + "px";
                        if (icon) icon.textContent = "-";
                    }
                });
            }
            
            // Функция копирования в буфер обмена
            function copyToClipboard(event, text) {
                event.stopPropagation();
                
                navigator.clipboard.writeText(text).then(function() {
                    var target = event.currentTarget;
                    target.classList.add('copied');
                    
                    setTimeout(function() {
                        target.classList.remove('copied');
                    }, 1500);
                }).catch(function(err) {
                    console.error('Не удалось скопировать текст: ', err);
                });
                
                // Предотвращаем выполнение других обработчиков
                return false;
            }
            
            // Функция для прокрутки к IP-адресу
            function scrollToIP(ip) {
                var ipElements = document.querySelectorAll('.ip-collapsible');
                for (var i = 0; i < ipElements.length; i++) {
                    if (ipElements[i].textContent.includes(ip)) {
                        // Прокручиваем к элементу
                        ipElements[i].scrollIntoView({ behavior: 'smooth', block: 'center' });
                        
                        // Мигаем фоном для привлечения внимания
                        ipElements[i].style.animation = 'highlight 2s';
                        ipElements[i].style.boxShadow = '0 0 15px #3498db';
                        
                        setTimeout(function(elem) {
                            return function() {
                                elem.style.boxShadow = '';
                                elem.style.animation = '';
                            };
                        }(ipElements[i]), 2000);
                        
                        // Открываем содержимое, если оно закрыто
                        var ipId = 'ip_' + ip.replace(/\./g, '_');
                        var content = document.getElementById(ipId);
                        if (content && !content.style.maxHeight) {
                            toggleIP(ipId);
                        }
                        break;
                    }
                }
            }
            
            // Автоматически открыть первую секцию при загрузке
            document.addEventListener("DOMContentLoaded", function() {
                toggleSection('statsSection');
            });
        </script>
    </body>
    </html>
    """
    
    template = Template(template_str)
    
    context = {
        'data': data,
        'stats': data.get('Overall Packet Statistics', {}),
        'sorted_ips': sorted_ips,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'get_threat_info_for_ip': get_threat_info_for_ip,
        'get_threat_badge_class': get_threat_badge_class
    }
    
    html_content = template.render(**context)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[*] HTML Report saved to '{output_path}'")

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
