#!/usr/bin/env python3
import logging
import sys
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Callable, Any, Dict, Set, Generator, List
import threading
import os
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, PcapReader, Packet, Raw
from tqdm import tqdm
import pyasn

DNS_TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

class Logger:
    """
    Класс для настройки логирования.
    Выводит сообщения в консоль и записывает предупреждения и ошибки в файл.
    """
    @staticmethod
    def setup_logger() -> logging.Logger:
        logger = logging.getLogger("NetParser")
        logger.setLevel(logging.DEBUG)
        info_console_handler = logging.StreamHandler(sys.stdout)
        info_console_handler.setLevel(logging.INFO)
        file_handler = logging.FileHandler('error.log', mode='w', encoding='utf-8')
        file_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        info_console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.addHandler(info_console_handler)
        logger.addHandler(file_handler)
        return logger

class ASNDatabase:
    """
    Класс для работы с базой ASN.
    Использует библиотеку pyasn для поиска информации по ASN.
    """
    def __init__(self, asndb_path: str, as_names_file: str) -> None:
        if not os.path.exists(asndb_path) or not os.path.exists(as_names_file):
            raise FileNotFoundError("ASN database files not found.")
        self.asndb = pyasn.pyasn(asndb_path, as_names_file=as_names_file)
        self.asn_cache: Dict[str, str] = {}
        self.lock = threading.Lock()

    def lookup_asn(self, ip: str) -> str:
        with self.lock:
            if ip in self.asn_cache:
                return self.asn_cache[ip]
        try:
            asn_info = self.asndb.lookup(ip)
            asn_name = self.asndb.get_as_name(asn_info[0]) if asn_info else '<NOT FOUND>'
        except Exception:
            asn_name = '<NOT FOUND>'
        with self.lock:
            self.asn_cache[ip] = asn_name
        return asn_name

class NetParser:
    """
    Класс для анализа трафика из PCAP файлов.
    Обрабатывает DNS, HTTP, TLS (SNI) пакеты, собирает статистику трафика и ассоциации.
    """
    def __init__(self,
                 asndb_path: str = "./asndb/ipasndb.dat",
                 as_names_file: str = "./asndb/asnname.json") -> None:
        self.logger = Logger.setup_logger()
        self.http_domains: Dict[str, Set[str]] = defaultdict(set)
        self.http_requests: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        self.dns_associations: Dict[str, Set[str]] = defaultdict(set)
        self.sni_by_ip: Dict[str, Set[str]] = defaultdict(set)
        self.output_data: Dict[str, Dict[str, int]] = {}
        self.ip_list_conn: Set[str] = set()
        self.asn_database = ASNDatabase(asndb_path, as_names_file)
        self.packet_statistics: Dict[str, int] = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "http_count": 0,
            "https_count": 0,
            "dns_count": 0,
            "total_bytes": 0
        }
        self.data_lock = threading.Lock()
        # Для клиентов – сохраняем DNS запросы с указанием DNS сервера
        self.dns_queries_by_server: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        # Для DNS серверов – сохраняем все ответы (без агрегации на этапе захвата)
        self.dns_response_table: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    @staticmethod
    def _normalize_ipv4(ip: str) -> str:
        """Нормализует IPv4 адрес, если он записан в формате ::ffff:x.x.x.x"""
        if ip and re.match(r"^::ffff:\d+\.\d+\.\d+\.\d+$", ip):
            return ip.split(":")[-1]
        return ip

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Проверяет, является ли строка корректным IPv4 адресом."""
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

    @staticmethod
    def _ip_sort_key(ip: str) -> tuple:
        """Ключ для сортировки IP адресов по числовому значению."""
        try:
            return tuple(int(part) for part in ip.split('.'))
        except Exception:
            return (9999,)

    def parse_http_request(self, payload: str) -> Optional[Dict[str, str]]:
        """Парсит HTTP запрос из полезной нагрузки."""
        lines = payload.splitlines()
        if not lines:
            return None
        request_line_pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+(HTTP/\d\.\d)")
        match = request_line_pattern.match(lines[0])
        if not match:
            return None
        http_data = {
            "method": match.group(1),
            "uri": match.group(2),
            "version": match.group(3),
            "host": "",
            "user_agent": ""
        }
        for line in lines[1:]:
            if ':' not in line:
                continue
            header, value = line.split(":", 1)
            header = header.strip().lower()
            value = value.strip()
            if header == "host":
                http_data["host"] = value
            elif header == "user-agent":
                http_data["user_agent"] = value
        return http_data

    def handle_dns_pkt(self, pkt: Packet) -> None:
        """Обрабатывает DNS пакет, аккумулируя запросы и ответы."""
        try:
            if UDP in pkt and (pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353):
                return

            dns_layer = pkt.getlayer(DNS)
            if not dns_layer:
                return

            # Обработка DNS запросов
            if dns_layer.qdcount and dns_layer.qd:
                queries = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
                ip_src = self._normalize_ipv4(pkt[IP].src) if IP in pkt else '<UNKNOWN>'
                ip_dst = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
                with self.data_lock:
                    for query in queries:
                        if hasattr(query, 'qname') and query.qname:
                            qname = query.qname.decode() if isinstance(query.qname, bytes) else query.qname
                            qname = qname.rstrip('.')  # удаляем завершающую точку
                            self.dns_queries_by_server[ip_src][ip_dst].add(qname)

            # Обработка DNS ответов
            if dns_layer.qr == 1 and dns_layer.ancount and dns_layer.an:
                ip_src = pkt[IP].src if IP in pkt else '<UNKNOWN>'
                dns_server_ip = self._normalize_ipv4(ip_src)
                answers = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                with self.data_lock:
                    for answer in answers:
                        try:
                            rrname = (answer.rrname.decode() if isinstance(answer.rrname, bytes)
                                      else answer.rrname) if answer.rrname else '<UNKNOWN>'
                        except Exception:
                            rrname = '<UNKNOWN>'
                        rrname = rrname.rstrip('.')
                        try:
                            rdata = answer.rdata
                        except AttributeError:
                            rdata = None
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors='ignore')
                        if rdata and self._is_valid_ipv4(rdata):
                            self.dns_associations[rdata].add(rrname)
                        try:
                            ans_type = getattr(answer, 'type', 'UNKNOWN')
                        except Exception:
                            ans_type = 'UNKNOWN'
                        type_str = DNS_TYPE_MAP.get(ans_type, str(ans_type))
                        ans_value = rdata if rdata else "<NO_DATA>"
                        if type_str != "A" and isinstance(ans_value, str):
                            ans_value = ans_value.rstrip('.')
                        self.dns_response_table[dns_server_ip].append({
                            "name": rrname,
                            "type": type_str,
                            "resolution": ans_value
                        })
        except Exception:
            self.logger.exception("Error handling DNS packet:")

    def extract_sni_scapy(self, pcap_file: str) -> None:
        """Извлекает SNI из TLS-пакетов."""
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    if TCP in pkt and pkt[TCP].dport == 443 and pkt.haslayer(Raw):
                        raw_payload = pkt[Raw].load
                        sni = self.extract_sni_from_tls(raw_payload)
                        if sni:
                            ip = self._normalize_ipv4(pkt[IP].dst) if IP in pkt else '<UNKNOWN>'
                            with self.data_lock:
                                self.sni_by_ip[ip].add(sni)
        except Exception:
            self.logger.exception("Error extracting SNI using Scapy.")

    def extract_sni_from_tls(self, data: bytes) -> Optional[str]:
        pos = 0
        while pos + 5 <= len(data):
            content_type = data[pos]
            rec_length = int.from_bytes(data[pos+3:pos+5], 'big')
            record_end = pos + 5 + rec_length
            if record_end > len(data):
                break
            if content_type != 22:
                pos = record_end
                continue
            handshake_pos = pos + 5
            while handshake_pos + 4 <= record_end:
                handshake_type = data[handshake_pos]
                handshake_length = int.from_bytes(data[handshake_pos+1:handshake_pos+4], 'big')
                handshake_end = handshake_pos + 4 + handshake_length
                if handshake_end > record_end:
                    break
                if handshake_type == 1:
                    client_hello = data[handshake_pos+4:handshake_end]
                    sni = self._parse_client_hello(client_hello)
                    if sni:
                        return sni
                handshake_pos = handshake_end
            pos = record_end
        return None

    def _parse_client_hello(self, client_hello: bytes) -> Optional[str]:
        pos = 0
        if len(client_hello) < 34:
            return None
        pos += 34
        if pos + 1 > len(client_hello):
            return None
        session_id_length = client_hello[pos]
        pos += 1 + session_id_length
        if pos + 2 > len(client_hello):
            return None
        cipher_suites_length = int.from_bytes(client_hello[pos:pos+2], 'big')
        pos += 2 + cipher_suites_length
        if pos + 1 > len(client_hello):
            return None
        comp_methods_length = client_hello[pos]
        pos += 1 + comp_methods_length
        if pos + 2 > len(client_hello):
            return None
        extensions_length = int.from_bytes(client_hello[pos:pos+2], 'big')
        pos += 2
        if pos + extensions_length > len(client_hello):
            return None
        end_ext = pos + extensions_length
        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(client_hello[pos:pos+2], 'big')
            ext_length = int.from_bytes(client_hello[pos+2:pos+4], 'big')
            pos += 4
            if pos + ext_length > end_ext:
                break
            if ext_type == 0:
                inner_pos = pos + 2
                inner_end = pos + ext_length
                while inner_pos + 3 <= inner_end:
                    name_type = client_hello[inner_pos]
                    name_length = int.from_bytes(client_hello[inner_pos+1:inner_pos+3], 'big')
                    inner_pos += 3
                    if inner_pos + name_length <= inner_end and name_type == 0:
                        try:
                            return client_hello[inner_pos:inner_pos+name_length].decode('utf-8')
                        except UnicodeDecodeError:
                            return None
                    inner_pos += name_length
            pos += ext_length
        return None

    def process_packets(self, packets: List[Packet],
                        filters: Optional[Callable[[Packet], bool]] = None) -> None:
        for pkt in packets:
            with self.data_lock:
                self.packet_statistics["total_packets"] += 1
                self.packet_statistics["total_bytes"] += len(pkt)
            if filters and not filters(pkt):
                continue
            if IP in pkt:
                ip_src = self._normalize_ipv4(pkt[IP].src)
                ip_dst = self._normalize_ipv4(pkt[IP].dst)
                with self.data_lock:
                    self.ip_list_conn.update([ip_src, ip_dst])
                    self.output_data.setdefault(ip_src, defaultdict(int))
                    self.output_data.setdefault(ip_dst, defaultdict(int))
                    self.output_data[ip_src]["packets_out"] += 1
                    self.output_data[ip_src]["bytes_out"] += len(pkt)
                    self.output_data[ip_dst]["packets_in"] += 1
                    self.output_data[ip_dst]["bytes_in"] += len(pkt)
                if TCP in pkt:
                    with self.data_lock:
                        self.packet_statistics["tcp_count"] += 1
                        self.output_data[ip_src]["tcp_count"] += 1
                        self.output_data[ip_dst]["tcp_count"] += 1
                    if pkt[TCP].dport == 80 and pkt.haslayer(Raw):
                        with self.data_lock:
                            self.packet_statistics["http_count"] += 1
                        try:
                            raw_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            host_match = re.search(r"Host:\s*([^\r\n]+)", raw_payload, re.IGNORECASE)
                            if host_match:
                                with self.data_lock:
                                    self.http_domains[ip_dst].add(host_match.group(1).strip())
                            http_data = self.parse_http_request(raw_payload)
                            if http_data:
                                with self.data_lock:
                                    self.http_requests[ip_dst].append(http_data)
                        except Exception:
                            self.logger.exception("Error extracting HTTP request details:")
                    elif pkt[TCP].dport == 443:
                        with self.data_lock:
                            self.packet_statistics["https_count"] += 1
                elif UDP in pkt:
                    with self.data_lock:
                        self.packet_statistics["udp_count"] += 1
                        self.output_data[ip_src]["udp_count"] += 1
                        self.output_data[ip_dst]["udp_count"] += 1
                elif ICMP in pkt:
                    with self.data_lock:
                        self.packet_statistics["icmp_count"] += 1
                        self.output_data[ip_src]["icmp_count"] += 1
                        self.output_data[ip_dst]["icmp_count"] += 1
                if DNS in pkt:
                    with self.data_lock:
                        self.packet_statistics["dns_count"] += 1
                        self.output_data[ip_src]["dns_count"] += 1
                        self.output_data[ip_dst]["dns_count"] += 1
                    self.handle_dns_pkt(pkt)

    def process_in_parallel(self, pcap_file: str,
                            num_threads: int = 4,
                            filters: Optional[Callable[[Packet], bool]] = None) -> None:
        def packet_iterator() -> Generator[Packet, None, None]:
            try:
                with PcapReader(pcap_file) as reader:
                    for pkt in reader:
                        yield pkt
            except FileNotFoundError as e:
                self.logger.error(f"PCAP file not found: {pcap_file}")
                raise e
            except Exception:
                self.logger.exception("Error while reading PCAP file:")
                raise

        chunk_size = 1000
        futures = []
        chunk: List[Packet] = []
        executor = ThreadPoolExecutor(max_workers=num_threads)
        for packet in tqdm(packet_iterator(), desc="Reading packets", unit="pkt"):
            chunk.append(packet)
            if len(chunk) >= chunk_size:
                futures.append(executor.submit(self.process_packets, chunk, filters))
                chunk = []
        if chunk:
            futures.append(executor.submit(self.process_packets, chunk, filters))
        for future in futures:
            future.result()
        executor.shutdown()

    def analyze(self, pcap_file: str,
                filters: Optional[Callable[[Packet], bool]] = None) -> Dict[str, Any]:
        self.logger.info("[*] Starting PCAP analysis...")
        self.process_in_parallel(pcap_file, filters=filters)
        self.extract_sni_scapy(pcap_file)
        return self.output_data

    def get_dict(self) -> Dict[str, Any]:
        """
        Формирует итоговый словарь с данными по IP.
        Для клиента выводится только таблица "DNS Queries by Server".
        Для DNS сервера – таблица "DNS Responses" (без дубликатов, с объединением записей по домену).
        """
        ip_dns_sni_map: Dict[str, Any] = {}
        with self.data_lock:
            ips = sorted(list(self.ip_list_conn), key=self._ip_sort_key)
        for ip in ips:
            ip_norm = self._normalize_ipv4(ip)
            with self.data_lock:
                dns_assocs = sorted([d.rstrip('.') for d in self.dns_associations.get(ip_norm, [])])
                sni_records = sorted(list(self.sni_by_ip.get(ip_norm, [])))
                http_hosts = sorted(list(self.http_domains.get(ip_norm, [])))
                raw_stats = dict(self.output_data.get(ip_norm, {}))
                dns_queries = self.dns_queries_by_server.get(ip_norm, {})
                dns_resps = self.dns_response_table.get(ip_norm, [])
            if dns_resps and len(dns_resps) > 0:
                aggregated = {}
                for resp in dns_resps:
                    name = resp.get("name", "").rstrip('.')
                    type_str = resp.get("type", "")
                    resolution = resp.get("resolution", "")
                    if type_str != "A" and isinstance(resolution, str):
                        resolution = resolution.rstrip('.')
                    key = (name, type_str)
                    if key in aggregated:
                        current = aggregated[key]
                        new_vals = [x.strip() for x in resolution.split(",") if x.strip()]
                        current.update(new_vals)
                    else:
                        new_vals = set(x.strip() for x in resolution.split(",") if x.strip())
                        aggregated[key] = new_vals
                aggregated_list = []
                for (name, type_str), res_set in aggregated.items():
                    resolution_str = ", ".join(sorted(res_set))
                    aggregated_list.append({
                        "name": name,
                        "type": type_str,
                        "resolution": resolution_str
                    })
                dns_info = {"DNS Responses": aggregated_list}
            elif dns_queries:
                dns_info = {"DNS Queries by Server": {
                    server_ip.rstrip('.'): sorted([q.rstrip('.') for q in queries])
                    for server_ip, queries in dns_queries.items()
                }}
            else:
                dns_info = {}
            traffic_stats = {k: raw_stats[k] for k in ["packets_in", "bytes_in", "packets_out", "bytes_out"] if k in raw_stats}
            protocol_stats = {k: v for k, v in raw_stats.items() if k not in ["packets_in", "bytes_in", "packets_out", "bytes_out"]}
            with self.data_lock:
                http_reqs = self.http_requests.get(ip_norm, [])
            unique_reqs = {}
            for req in http_reqs:
                key = tuple(sorted(req.items()))
                unique_reqs.setdefault(key, req)
            unique_http_reqs = list(unique_reqs.values())
            asn = self.asn_database.lookup_asn(ip_norm)
            ip_data = {
                "ASN": asn,
                "DNS Associations": dns_assocs,
                "SNI Records": sni_records,
                "HTTP Domains": http_hosts,
                "HTTP Requests": unique_http_reqs,
                "Traffic": traffic_stats,
                "Protocols": protocol_stats
            }
            ip_data.update(dns_info)
            ip_dns_sni_map[ip_norm] = ip_data
        with self.data_lock:
            ip_dns_sni_map["Overall Packet Statistics"] = dict(self.packet_statistics)
        return ip_dns_sni_map
