import json
from jinja2 import Template

def compare_traffic(pcap_base_file, pcap_plugin_file, base_parser, plugin_parser):
    base_parser.analyze(pcap_base_file)
    base_traffic = base_parser.get_dict()

    plugin_parser.analyze(pcap_plugin_file)
    plugin_traffic = plugin_parser.get_dict()

    unique_traffic = {}
    for ip, plugin_data in plugin_traffic.items():
        base_data = base_traffic.get(ip)
        if not base_data:
            unique_traffic[ip] = plugin_data
        else:
            unique_dns = set(plugin_data["DNS Associations"]) - set(base_data["DNS Associations"])
            unique_sni = set(plugin_data["SNI Records"]) - set(base_data["SNI Records"])
            unique_asn = plugin_data["ASN"] if plugin_data["ASN"] != base_data["ASN"] else None

            unique_packets = {key: plugin_data["Packet Statistics"].get(key, 0) - base_data["Packet Statistics"].get(key, 0)
                              for key in plugin_data["Packet Statistics"]}

            if unique_dns or unique_sni or unique_asn or any(count != 0 for count in unique_packets.values()):
                unique_traffic[ip] = {
                    "ASN": unique_asn if unique_asn else base_data["ASN"],
                    "DNS Associations": sorted(unique_dns),
                    "SNI Records": sorted(unique_sni),
                    "Packet Statistics": {key: count for key, count in unique_packets.items() if count != 0}
                }

    return unique_traffic
    
def generate_report(output_path, data):
    output_data = data.copy()
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=4)
        
    print(f"[*] Report saved to '{output_path}'")
    return output_data

from jinja2 import Template

def generate_html_report(output_path, data):
    template = """
    <html>
    <head><title>Network Traffic Analysis Report</title></head>
    <body>
    <h1>Network Traffic Report</h1>
    <ul>
    {% for ip, report in data.items() if ip != 'Summary Statistics' %}
        <li>
            <h3>IP: {{ ip }}</h3>
            <ul>
                <li><strong>ASN:</strong> {{ report['ASN'] }}</li>
                <li><strong>DNS Associations:</strong> {{ report['DNS Associations'] }}</li>
                <li><strong>SNI Records:</strong> {{ report['SNI Records'] }}</li>
                <li><strong>Packet Statistics:</strong>
                    <ul>
                    {% for packet_type, count in report['Packet Statistics'].items() %}
                        <li>{{ packet_type }}: {{ count }}</li>
                    {% endfor %}
                    </ul>
                </li>
            </ul>
        </li>
    {% endfor %}
    </ul>
    </body>
    </html>
    """
    template = Template(template)
    html_content = template.render(data=data)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[*] HTML Report saved to '{output_path}'")
    return data
    
def print_report(report_data):
    """
    Функция для вывода анализа трафика на экран в читаемом и структурированном формате.
    :param report_data: Данные для анализа.
    """
    print("\n" + "="*60)
    print(f"{'Network Traffic Analysis Report':^60}")
    print("="*60)

    for ip, report in report_data.items():
        print(f"\n{'IP Address:':<15}{ip}")
        print(f"{'ASN:':<15}{report['ASN'] or 'Not Available'}")

        dns_info = ', '.join(report['DNS Associations']) if report['DNS Associations'] else 'None'
        print(f"{'DNS Associations:':<15}{dns_info}")

        sni_info = ', '.join(report['SNI Records']) if report['SNI Records'] else 'None'
        print(f"{'SNI Records:':<15}{sni_info}")
        
        if report['Packet Statistics']:
            print(f"\n{'Packet Statistics:':<15}")
            for packet_type, count in report['Packet Statistics'].items():
                print(f"  {'':<15}{packet_type:<20}{count}")
        else:
            print(f"{'Packet Statistics:':<15}No data available")

        print("="*60)
