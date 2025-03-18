#!/usr/bin/env python3
import argparse
import sys
from utils import compare_traffic, generate_report, generate_html_report, print_report, generate_txt_report
from netparser import NetParser


def main() -> None:
    """
    Основная функция, осуществляющая разбор аргументов командной строки и запуск анализа/сравнения PCAP-файлов.
    """
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--filter", help="Packet filter expression (example: DNS, IP, HTTP, etc.)")
    parser.add_argument("--html", metavar="HTML_PATH", help="Generate HTML report at specified path")
    parser.add_argument("--json", metavar="JSON_PATH", help="Generate JSON report at specified path")
    parser.add_argument("--compare", metavar="COMPARE_FILE", help="Path to the second PCAP file for comparison")
    parser.add_argument("--txt", metavar="TXT_PATH", help="Generate TXT report at specified path")
    parser.add_argument("--check-blacklists", action="store_true", help="Check IP addresses against blacklists")
    parser.add_argument("--no-check-blacklists", action="store_false", dest="check_blacklists", help="Do not check IP addresses against blacklists")
    parser.set_defaults(check_blacklists=True)
    args = parser.parse_args()

    try:
        if args.compare:
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

            net_parser = NetParser(check_blacklists=args.check_blacklists)
            net_parser.analyze(args.pcap_file, filters=filters)
            report_data = net_parser.get_dict()
            print_report(report_data)

            if args.json:
                generate_report(args.json, report_data)
            if args.html:
                generate_html_report(args.html, report_data)
            if args.txt:
                generate_txt_report(args.txt, report_data)
    except Exception as e:
        sys.exit(f"An error occurred during processing: {str(e)}. Please check error.log for details.")


if __name__ == "__main__":
    main()
