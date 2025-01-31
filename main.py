import argparse
from utils import compare_traffic, generate_report, generate_html_report, print_report
from netparser import NetParser

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("pcap_file", help="Path to the pcap file to analyze")
    parser.add_argument("--filter", help="Packet filter expression (example: DNS, IP, HTTP, etc.)")
    parser.add_argument("--html", metavar="HTML_PATH", help="Generate HTML report at specified path")
    parser.add_argument("--json", metavar="JSON_PATH", help="Generate JSON report at specified path")
    parser.add_argument("--compare", metavar="COMPARE_FILE", help="Path to the second pcap file for comparison")
    args = parser.parse_args()

    # Если задан флаг сравнения
    if args.compare:
        base_parser = NetParser()
        plugin_parser = NetParser()
        unique_traffic = compare_traffic(args.pcap_file, args.compare, base_parser, plugin_parser)
        print("\nUnique Traffic (only in plugin traffic):")
        for ip, details in unique_traffic.items():
            print(f"\nIP: {ip}")
            print(f"  ASN: {details['ASN']}")
            print(f"  DNS Associations: {details['DNS Associations']}")
            print(f"  SNI Records: {details['SNI Records']}")
        
        if args.json:
            generate_report(args.json, unique_traffic)
        if args.html:
            generate_html_report(args.html, unique_traffic)
    
    else:
        filters = None
        if args.filter:
            filter_terms = args.filter.upper().split(",")  # поддержка нескольких фильтров через запятую
            filters = lambda pkt: any(term in str(pkt).upper() for term in filter_terms)

        net_parser = NetParser()
        data = net_parser.analyze(args.pcap_file, filters=filters)
        report_data = net_parser.get_dict()

        # Выводим отчет через отдельную функцию
        print_report(report_data)

        if args.json:
            generate_report(args.json, report_data)
        if args.html:
            generate_html_report(args.html, report_data)
            
if __name__ == "__main__":
    main()
