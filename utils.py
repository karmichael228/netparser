#!/usr/bin/env python3
import json
import re
from typing import Any, Dict, List
from jinja2 import Template
from netparser import NetParser

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

    unique_traffic: Dict[str, Any] = {}
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    for ip, plugin_data in plugin_traffic.items():
        if ip == "Overall Packet Statistics":
            continue
        if not ip_pattern.match(ip):
            continue
        base_data = base_traffic.get(ip)
        if not base_data:
            unique_traffic[ip] = plugin_data
        else:
            unique_dns = set(plugin_data["DNS Associations"]) - set(base_data["DNS Associations"])
            unique_sni = set(plugin_data["SNI Records"]) - set(base_data["SNI Records"])
            unique_http_domains = set(plugin_data.get("HTTP Domains", [])) - set(base_data.get("HTTP Domains", []))
            base_http_reqs: List[Dict[str, str]] = base_data.get("HTTP Requests", [])
            plugin_http_reqs: List[Dict[str, str]] = plugin_data.get("HTTP Requests", [])
            unique_http_reqs = [req for req in plugin_http_reqs if req not in base_http_reqs]
            unique_asn = plugin_data["ASN"] if plugin_data["ASN"] != base_data["ASN"] else None
            unique_packets = {
                key: plugin_data["Protocols"].get(key, 0) - base_data["Protocols"].get(key, 0)
                for key in plugin_data["Protocols"]
            }
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
            unique_traffic[ip] = {
                "ASN": unique_asn if unique_asn else base_data["ASN"],
                "DNS Associations": sorted(unique_dns),
                "DNS Queries by Server": unique_dns_queries_by_server if unique_dns_queries_by_server else None,
                "DNS Responses": plugin_data.get("DNS Responses", []),
                "DNS Resolution Chains": plugin_data.get("DNS Resolution Chains", []),
                "SNI Records": sorted(unique_sni),
                "HTTP Domains": sorted(unique_http_domains),
                "HTTP Requests": unique_http_reqs,
                "Traffic": {key: plugin_data["Traffic"].get(key, 0) - base_data["Traffic"].get(key, 0)
                            for key in set(plugin_data["Traffic"]) | set(base_data["Traffic"])},
                "Protocols": {key: count for key, count in unique_packets.items() if count != 0}
            }

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
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"[*] Report saved to '{output_path}'")
    return data

def generate_html_report(output_path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    ip_keys = [ip for ip in data.keys() if ip != "Overall Packet Statistics"]
    sorted_ips = sorted(ip_keys, key=ip_sort_key)
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Network Traffic Analysis Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f9; margin: 0; padding: 0; }
            .header { background: linear-gradient(90deg, #4b79a1, #283e51); color: white; padding: 20px; text-align: center; }
            .container { width: 90%; margin: 20px auto; }
            .section { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; padding: 20px; }
            .section h2 { border-bottom: 2px solid #4b79a1; padding-bottom: 10px; margin-bottom: 20px; color: #283e51; }
            .ip-card { border: 1px solid #ddd; border-radius: 6px; margin-bottom: 20px; padding: 15px; background-color: #fafafa; }
            .ip-card h3 { margin-top: 0; color: #4b79a1; }
            .data-list { list-style: none; padding: 0; }
            .data-list li { padding: 5px 0; border-bottom: 1px solid #eee; }
            .data-list li:last-child { border-bottom: none; }
            .link-list a { display: block; padding: 5px; text-decoration: none; color: #4b79a1; border: 1px solid #4b79a1; border-radius: 4px; margin-bottom: 5px; transition: background 0.3s, color 0.3s; }
            .link-list a:hover { background: #4b79a1; color: white; }
            .overall-stats { display: flex; flex-wrap: wrap; }
            .stat-item { flex: 1 0 200px; margin: 10px; background: white; padding: 15px; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            table, th, td { border: 1px solid #ddd; }
            th, td { padding: 8px; text-align: left; }
            th { background-color: #4b79a1; color: white; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Network Traffic Analysis Report</h1>
        </div>
        <div class="container">
            {% if data.get("Overall Packet Statistics") %}
            <div class="section">
                <h2>Overall Packet Statistics</h2>
                <div class="overall-stats">
                    {% for stat, value in data["Overall Packet Statistics"].items() %}
                    <div class="stat-item">
                        <h3>{{ stat }}</h3>
                        <p>{{ value }}</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}
            {% for ip in sorted_ips %}
                {% set report = data[ip] %}
                <div class="ip-card">
                    <h3>IP: {{ ip }}</h3>
                    <ul class="data-list">
                        <li><strong>ASN:</strong> {{ report['ASN'] }}</li>
                        <li><strong>DNS Associations:</strong> {{ report['DNS Associations'] | join(', ') if report['DNS Associations'] else 'None' }}</li>
                    </ul>
                    {% if report['DNS Queries by Server'] and report['DNS Queries by Server']|length > 0 %}
                    <div class="section">
                        <h2>DNS Queries by Server</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>DNS Server</th>
                                    <th>Queries</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for server_ip, queries in report['DNS Queries by Server'].items() %}
                                <tr>
                                    <td>{{ server_ip }}</td>
                                    <td>{{ queries | join(', ') }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% elif report['DNS Responses'] and report['DNS Responses']|length > 0 %}
                    <div class="section">
                        <h2>DNS Responses</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>NAME</th>
                                    <th>TYPE</th>
                                    <th>RESOLUTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for entry in report['DNS Responses'] %}
                                <tr>
                                    <td>{{ entry.name }}</td>
                                    <td>{{ entry.type }}</td>
                                    <td>{{ entry.resolution }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% endif %}
                    {% if report.get("DNS Resolution Chains") %}
                    <div class="section">
                        <h2>DNS Resolution Chains</h2>
                        <ul class="data-list">
                            {% for chain in report["DNS Resolution Chains"] %}
                            <li>{{ chain }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    <ul class="data-list">
                        <li><strong>HTTP Domains:</strong> {{ report["HTTP Domains"] | join(', ') if report["HTTP Domains"] else "None" }}</li>
                        <li><strong>SNI Records:</strong> {{ report["SNI Records"] | join(', ') if report["SNI Records"] else "None" }}</li>
                    </ul>
                    <div class="section">
                        <h2>Traffic (Packets/Bytes)</h2>
                        <ul class="data-list">
                            {% for key, value in report["Traffic"].items() %}
                            <li><strong>{{ key.replace('_', ' ').title() }}:</strong> {{ value }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    <div class="section">
                        <h2>Protocols</h2>
                        <ul class="data-list">
                            {% for key, value in report["Protocols"].items() %}
                            <li><strong>{{ key.replace('_', ' ').title() }}:</strong> {{ value }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% if report["HTTP Requests"] and report["HTTP Requests"]|length > 0 %}
                    <div class="section">
                        <h2>HTTP Requests</h2>
                        <ul class="data-list">
                            {% for req in report["HTTP Requests"] %}
                            <li>
                                <strong>Method:</strong> {{ req.method }},
                                <strong>URI:</strong> {{ req.uri }},
                                <strong>Version:</strong> {{ req.version }}<br>
                                <strong>Host:</strong> {{ req.host }}{% if req.user_agent %}, <strong>User-Agent:</strong> {{ req.user_agent }}{% endif %}
                            </li>
                            {% endfor %}
                        </ul>
                    </div>
                    <div class="section">
                        <h2>HTTP URI Links</h2>
                        <div class="link-list">
                            {% for req in report["HTTP Requests"] %}
                                {% if req.host and req.uri %}
                                    {% set url = "http://" + req.host + req.uri %}
                                    <a href="{{ url }}" target="_blank">{{ url }}</a>
                                {% endif %}
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>
            {% endfor %}
        </div>
    </body>
    </html>
    """
    template = Template(html_template)
    html_content = template.render(data=data, sorted_ips=sorted_ips)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[*] HTML Report saved to '{output_path}'")
    return data

def print_report(report_data: Dict[str, Any]) -> None:
    """
    Выводит анализ трафика на экран в консоль с таблицами для DNS Queries или агрегированными DNS Responses.
    """
    def ip_sort_key_inner(ip: str) -> tuple:
        try:
            return tuple(int(part) for part in ip.split('.'))
        except Exception:
            return (9999,)
    print("\n" + "=" * 60)
    print(f"{'Network Traffic Analysis Report':^60}")
    print("=" * 60)
    overall_stats = report_data.get("Overall Packet Statistics")
    if overall_stats:
        print(f"\n{'Overall Packet Statistics':^60}")
        print("-" * 60)
        for stat, value in overall_stats.items():
            print(f"{stat:<20}: {value}")
        print("=" * 60)
    ip_keys = [ip for ip in report_data.keys() if ip != "Overall Packet Statistics"]
    sorted_ips = sorted(ip_keys, key=ip_sort_key_inner)
    for ip in sorted_ips:
        report = report_data[ip]
        print(f"\n{'IP Address:':<15}{ip}")
        print(f"{'ASN:':<15}{report.get('ASN', 'Not Available')}")
        dns_info = ', '.join(report.get('DNS Associations', [])) if report.get('DNS Associations') else 'None'
        print(f"{'DNS Associations:':<15}{dns_info}")
        if report.get('DNS Queries by Server'):
            print(f"{'DNS Queries by Server:':<15}")
            print("  +----------------+-----------------+")
            print("  | DNS Server     | Queries         |")
            print("  +----------------+-----------------+")
            for server_ip, queries in report['DNS Queries by Server'].items():
                queries_str = ', '.join(queries)
                print(f"  | {server_ip:<14} | {queries_str:<15} |")
            print("  +----------------+-----------------+")
        elif report.get('DNS Responses'):
            print(f"{'DNS Responses:':<15}")
            print("  +-----------------+-------+-----------------+")
            print("  | NAME            | TYPE  | RESOLUTION      |")
            print("  +-----------------+-------+-----------------+")
            for entry in report['DNS Responses']:
                print(f"  | {entry['name']:<15} | {entry['type']:<5} | {entry['resolution']:<15} |")
            print("  +-----------------+-------+-----------------+")
        if report.get("DNS Resolution Chains"):
            print(f"{'DNS Resolution Chains:':<15}")
            for chain in report["DNS Resolution Chains"]:
                print(f"  {chain}")
        print(f"{'HTTP Domains:':<15}{', '.join(report.get('HTTP Domains', [])) if report.get('HTTP Domains') else 'None'}")
        print(f"{'SNI Records:':<15}{', '.join(report.get('SNI Records', [])) if report.get('SNI Records') else 'None'}")
        print("\nTraffic (Packets/Bytes):")
        for key, value in report.get('Traffic', {}).items():
            print(f"  {key.replace('_', ' ').title():<20}{value}")
        print("\nProtocols:")
        for key, value in report.get('Protocols', {}).items():
            print(f"  {key.replace('_', ' ').title():<20}{value}")
        http_reqs = report.get('HTTP Requests', [])
        if http_reqs:
            print("\nHTTP Requests:")
            for req in http_reqs:
                req_line = f"{req.get('method', '')} {req.get('uri', '')} {req.get('version', '')} | Host: {req.get('host', '')}"
                if req.get('user_agent'):
                    req_line += f" | User-Agent: {req.get('user_agent', '')}"
                print(f"  {req_line}")
            print("\nHTTP URI Links:")
            for req in http_reqs:
                if req.get('host') and req.get('uri'):
                    url = "http://" + req.get('host') + req.get('uri')
                    print(f"  {url}")
        else:
            print("\nHTTP Requests: None")
        print("=" * 60)
        

def generate_txt_report(output_path: str, data: Dict[str, Any]) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        for ip, info in data.items():
            if ip == "Overall Packet Statistics":
                continue
            f.write(f"{ip}\n")
            dns_assocs = info.get("DNS Associations", [])
            sni_records = info.get("SNI Records", [])
            if dns_assocs:
                f.write("DNS Associations: ")
                for assoc in dns_assocs:
                    f.write(f"{assoc}\n")
            if sni_records:
                f.write("SNI Records: ")
                for record in sni_records:
                    f.write(f"{record}\n")
            f.write("\n")
    print(f"[*] TXT Report saved to '{output_path}'")
